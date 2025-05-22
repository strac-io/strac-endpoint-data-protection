import asyncio
import logging
import mimetypes
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, List

import aiofiles
import filetype
from peewee import DoesNotExist

from config import SYSTEM, VIRTENV_CHECK_INTERVAL
from storage.database import BrowserDownloadRecord, VirtEnvScanHistory


class VirtEnv:
    def __init__(self, num_consumers: int = 5, queue_size: int = 150):
        self.name = "manager-virtenv"
        self.logger = logging.getLogger(self.name)
        self.producer_tasks: Dict[str, asyncio.Task] = {}
        self.consumer_tasks: List[asyncio.Task] = []
        self.is_running = False
        self.num_consumers = num_consumers
        self.queue = asyncio.Queue(maxsize=queue_size)
        self.executor = ThreadPoolExecutor()
        self.vm_info = {}

    async def _async_call(self, func, *args, **kwargs):
        event_loop = asyncio.get_event_loop()
        result = await event_loop.run_in_executor(self.executor, func, *args, **kwargs)
        return result

    async def detect_vms(self):
        """detect virtual machines running on the host"""
        try:
            # detect vmware vms
            vmware_vms = await self._detect_vmware_vms()

            # detect virtualbox vms
            vbox_vms = await self._detect_virtualbox_vms()

            # detect parallels vms
            parallels_vms = await self._detect_parallels_vms()

            # combine all detected vms
            all_vms = {**vmware_vms, **vbox_vms, **parallels_vms}

            self.vm_info = all_vms
            return all_vms
        except Exception as e:
            self.logger.error(f"error detecting virtual machines: {str(e)}")
            return {}

    async def _detect_vmware_vms(self):
        """detect vmware virtual machines"""
        vms = {}
        try:
            # check for vmware installation
            vmware_path = "/Applications/VMware Fusion.app"
            if not await self._async_call(os.path.exists, vmware_path):
                return vms

            # find vmware vms directory
            vm_dir = self._expand_user_path("Virtual Machines.localized")
            if not await self._async_call(os.path.exists, vm_dir):
                vm_dir = self._expand_user_path("Virtual Machines")

            if not await self._async_call(os.path.exists, vm_dir):
                return vms

            # scan for .vmx files which define vmware vms
            for root, dirs, files in await self._async_call(os.walk, vm_dir):
                for file in files:
                    if file.endswith(".vmx"):
                        vm_path = os.path.join(root, file)
                        vm_name = file[:-4]  # remove .vmx extension

                        # read vmx file to get vm details
                        async with aiofiles.open(vm_path, "r") as vmx_file:
                            content = await vmx_file.read()
                            # simple parsing of vmx file
                            ip_address = None
                            for line in content.splitlines():
                                if "displayName" in line:
                                    parts = line.split("=", 1)
                                    if len(parts) == 2:
                                        vm_name = parts[1].strip().strip('"')

                        vms[vm_name] = {
                            "path": vm_path,
                            "type": "vmware",
                            "ip_address": ip_address,
                        }
            return vms
        except Exception as e:
            self.logger.error(f"error detecting vmware vms: {str(e)}")
            return vms

    async def _detect_virtualbox_vms(self):
        """detect virtualbox virtual machines"""
        vms = {}
        try:
            # check for virtualbox installation
            vbox_path = "/Applications/VirtualBox.app"
            if not await self._async_call(os.path.exists, vbox_path):
                return vms

            # use vboxmanage to list vms
            try:
                result = await self._async_call(
                    subprocess.run,
                    ["vboxmanage", "list", "vms"],
                    capture_output=True,
                    text=True,
                )

                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if not line.strip():
                            continue

                        # parse output in format: "VM Name" {uuid}
                        parts = line.split('" {')
                        if len(parts) == 2:
                            vm_name = parts[0].strip('"')
                            vm_uuid = parts[1].strip("}")

                            # get additional info about this vm
                            vm_info_result = await self._async_call(
                                subprocess.run,
                                [
                                    "vboxmanage",
                                    "showvminfo",
                                    vm_uuid,
                                    "--machinereadable",
                                ],
                                capture_output=True,
                                text=True,
                            )

                            vm_path = None
                            for info_line in vm_info_result.stdout.splitlines():
                                if info_line.startswith("CfgFile="):
                                    vm_path = info_line.split("=", 1)[1].strip('"')
                                    break

                            vms[vm_name] = {
                                "path": vm_path,
                                "type": "virtualbox",
                                "uuid": vm_uuid,
                                "ip_address": None,
                            }
                return vms
            except Exception as e:
                self.logger.error(f"error running vboxmanage: {str(e)}")
                return vms
        except Exception as e:
            self.logger.error(f"error detecting virtualbox vms: {str(e)}")
            return vms

    async def _detect_parallels_vms(self):
        """detect parallels virtual machines"""
        vms = {}
        try:
            # check for parallels installation
            parallels_path = "/Applications/Parallels Desktop.app"
            if not await self._async_call(os.path.exists, parallels_path):
                return vms

            # find parallels vms directory
            vm_dir = self._expand_user_path("Parallels")
            if not await self._async_call(os.path.exists, vm_dir):
                return vms

            # scan for .pvm directories which contain parallels vms
            for item in await self._async_call(os.listdir, vm_dir):
                if item.endswith(".pvm"):
                    vm_path = os.path.join(vm_dir, item)
                    if await self._async_call(os.path.isdir, vm_path):
                        vm_name = item[:-4]  # remove .pvm extension

                        # look for config.pvs which contains vm info
                        config_path = os.path.join(vm_path, "config.pvs")
                        if await self._async_call(os.path.exists, config_path):
                            vms[vm_name] = {
                                "path": vm_path,
                                "type": "parallels",
                                "ip_address": None,
                            }
            return vms
        except Exception as e:
            self.logger.error(f"error detecting parallels vms: {str(e)}")
            return vms

    def _expand_user_path(self, additional_path=None):
        username = SYSTEM.current_user
        home_path = os.path.expanduser(f"~{username}")
        if not username:
            self.logger.error("failed to get username")
            return None
        if additional_path:
            return os.path.join(home_path, additional_path)
        return home_path

    async def find_vm_downloads(self, vm_name):
        """find browser downloads in a specific virtual machine"""
        try:
            if vm_name not in self.vm_info:
                self.logger.error(f"virtual machine not found: {vm_name}")
                return []

            vm_details = self.vm_info[vm_name]
            vm_type = vm_details.get("type")

            # check when this vm was last scanned
            last_scan = await self.get_last_scan_time(vm_name, vm_type)

            if vm_type == "vmware":
                return await self._find_vmware_downloads(vm_name, vm_details)
            elif vm_type == "virtualbox":
                return await self._find_virtualbox_downloads(vm_name, vm_details)
            elif vm_type == "parallels":
                return await self._find_parallels_downloads(vm_name, vm_details)
            else:
                self.logger.error(f"unsupported vm type: {vm_type}")
                return []
        except Exception as e:
            self.logger.error(f"error finding downloads in vm {vm_name}: {str(e)}")
            return []

    async def get_last_scan_time(self, vm_name, vm_type):
        """get the last scan time for a virtual machine"""
        try:
            scan = VirtEnvScanHistory.get(VirtEnvScanHistory.vm_name == vm_name)
            return (
                datetime.fromisoformat(scan.last_scan)
                if isinstance(scan.last_scan, str)
                else scan.last_scan
            )
        except DoesNotExist:
            return None
        except Exception as e:
            self.logger.error(
                f"error getting last scan time for vm {vm_name}: {str(e)}"
            )
            return None

    async def update_scan_time(self, vm_name, vm_type):
        """update the last scan time for a virtual machine"""
        try:
            VirtEnvScanHistory.replace(
                vm_name=vm_name, vm_type=vm_type, last_scan=datetime.now(timezone.utc)
            ).execute()
            self.logger.debug(f"updated scan time for vm {vm_name}")
        except Exception as e:
            self.logger.error(f"error updating scan time for vm {vm_name}: {str(e)}")

    async def _find_vmware_downloads(self, vm_name, vm_details):
        """find downloads in vmware virtual machine"""
        try:
            # this requires vm tools to be installed and shared folders to be enabled
            # typically vmware vms mount the host user folder
            vm_path = vm_details.get("path")

            # path to vm's disk files
            vm_dir = os.path.dirname(vm_path)

            # look for shared folders config in the vmx file
            shared_paths = []
            async with aiofiles.open(vm_path, "r") as vmx_file:
                content = await vmx_file.read()
                for line in content.splitlines():
                    if "sharedFolder" in line and "hostPath" in line:
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            host_path = parts[1].strip().strip('"')
                            shared_paths.append(host_path)

            downloads = []
            for shared_path in shared_paths:
                # look for downloads folder in shared paths
                if "downloads" in shared_path.lower():
                    # scan files in the downloads folder
                    for file in await self._async_call(os.listdir, shared_path):
                        file_path = os.path.join(shared_path, file)
                        if await self._async_call(os.path.isfile, file_path):
                            file_size, exists, mime_type = await self.get_file_info(
                                file_path
                            )

                            # get file stats for timestamp
                            stats = await self._async_call(os.stat, file_path)
                            created_time = datetime.fromtimestamp(stats.st_ctime)

                            downloads.append(
                                {
                                    "filename": file,
                                    "local_path": file_path,
                                    "source_url": "unknown",  # can't determine source from shared folder
                                    "download_time": created_time,
                                    "file_size": file_size,
                                    "browser": "unknown",  # can't determine browser from shared folder
                                    "file_exists": exists,
                                    "mime_type": mime_type,
                                    "vm_name": vm_name,
                                    "vm_type": "vmware",
                                }
                            )

            return downloads
        except Exception as e:
            self.logger.error(f"error finding vmware downloads for {vm_name}: {str(e)}")
            return []

    async def _find_virtualbox_downloads(self, vm_name, vm_details):
        """find downloads in virtualbox virtual machine"""
        try:
            # similar approach to vmware, look for shared folders
            vm_uuid = vm_details.get("uuid")

            # get shared folders info
            result = await self._async_call(
                subprocess.run,
                ["vboxmanage", "showvminfo", vm_uuid, "--machinereadable"],
                capture_output=True,
                text=True,
            )

            shared_paths = []
            for line in result.stdout.splitlines():
                if "SharedFolderPath" in line:
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        host_path = parts[1].strip('"')
                        shared_paths.append(host_path)

            downloads = []
            for shared_path in shared_paths:
                # look for downloads folder in shared paths
                if "downloads" in shared_path.lower():
                    # scan files in the downloads folder
                    for file in await self._async_call(os.listdir, shared_path):
                        file_path = os.path.join(shared_path, file)
                        if await self._async_call(os.path.isfile, file_path):
                            file_size, exists, mime_type = await self.get_file_info(
                                file_path
                            )

                            # get file stats for timestamp
                            stats = await self._async_call(os.stat, file_path)
                            created_time = datetime.fromtimestamp(stats.st_ctime)

                            downloads.append(
                                {
                                    "filename": file,
                                    "local_path": file_path,
                                    "source_url": "unknown",
                                    "download_time": created_time,
                                    "file_size": file_size,
                                    "browser": "unknown",
                                    "file_exists": exists,
                                    "mime_type": mime_type,
                                    "vm_name": vm_name,
                                    "vm_type": "virtualbox",
                                }
                            )

            return downloads
        except Exception as e:
            self.logger.error(
                f"error finding virtualbox downloads for {vm_name}: {str(e)}"
            )
            return []

    async def _find_parallels_downloads(self, vm_name, vm_details):
        """find downloads in parallels virtual machine"""
        try:
            # parallels typically has better integration with the host system
            vm_path = vm_details.get("path")

            # shared folders are usually defined in config
            config_path = os.path.join(vm_path, "config.pvs")

            shared_paths = []
            # parallels config can be complex xml, look for shared folders section
            # for now, check default user folder sharing
            user_home = self._expand_user_path()
            if user_home:
                downloads_path = os.path.join(user_home, "Downloads")
                if await self._async_call(os.path.exists, downloads_path):
                    shared_paths.append(downloads_path)

            downloads = []
            for shared_path in shared_paths:
                # scan files in the downloads folder
                for file in await self._async_call(os.listdir, shared_path):
                    file_path = os.path.join(shared_path, file)
                    if await self._async_call(os.path.isfile, file_path):
                        file_size, exists, mime_type = await self.get_file_info(
                            file_path
                        )

                        # get file stats for timestamp
                        stats = await self._async_call(os.stat, file_path)
                        created_time = datetime.fromtimestamp(stats.st_ctime)

                        downloads.append(
                            {
                                "filename": file,
                                "local_path": file_path,
                                "source_url": "unknown",
                                "download_time": created_time,
                                "file_size": file_size,
                                "browser": "unknown",
                                "file_exists": exists,
                                "mime_type": mime_type,
                                "vm_name": vm_name,
                                "vm_type": "parallels",
                            }
                        )

            return downloads
        except Exception as e:
            self.logger.error(
                f"error finding parallels downloads for {vm_name}: {str(e)}"
            )
            return []

    async def get_file_info(self, file_path):
        try:
            if not await self._async_call(os.path.exists, file_path):
                return 0, False, None

            file_size = await self._async_call(os.path.getsize, file_path)
            mime_type = await self._async_call(filetype.guess, file_path)
            if mime_type is None:
                mime_type, _ = await self._async_call(mimetypes.guess_type, file_path)
            else:
                mime_type = mime_type.mime

            return file_size, True, mime_type
        except Exception as e:
            self.logger.error(f"error getting file info for {file_path}: {str(e)}")
            return 0, False, None

    async def produce_events(self):
        """scan all vms and produce download events"""
        try:
            # detect available vms
            vms = await self.detect_vms()

            if not vms:
                self.logger.debug("no virtual machines detected")
                return

            for vm_name, vm_details in vms.items():
                self.logger.debug(f"scanning virtual machine: {vm_name}")
                downloads = await self.find_vm_downloads(vm_name)

                for download in downloads:
                    await self.queue.put(download)
                    self.logger.debug(
                        f"added vm download to queue: {download['filename']}"
                    )

                # update scan time for this vm
                await self.update_scan_time(vm_name, vm_details.get("type"))

        except Exception as e:
            self.logger.error(f"error producing vm download events: {str(e)}")

    async def consume_events(self, consumer_id: int):
        """consume download events from the queue"""
        self.logger.debug(f"consumer {consumer_id} started")
        while self.is_running:
            try:
                event = await self.queue.get()
                await self.process_event(event, consumer_id)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"consumer {consumer_id} error: {str(e)}")
        self.logger.debug(f"consumer {consumer_id} stopped")

    async def process_event(self, event, consumer_id: int):
        """process a download event"""
        try:
            self.logger.debug(
                f"consumer {consumer_id} processing event: {event['filename']}"
            )

            # store in database
            BrowserDownloadRecord.create(
                filename=event["filename"],
                local_path=event["local_path"],
                source_url=event["source_url"],
                download_time=event["download_time"],
                file_size=event["file_size"],
                browser=f"vm-{event['vm_type']}",
                file_exists=event["file_exists"],
                mime_type=event["mime_type"],
            )

            self.logger.debug(
                f"consumer {consumer_id} processed event: {event['filename']}"
            )
        except Exception as e:
            self.logger.error(f"error processing event {event['filename']}: {str(e)}")

    async def start(self):
        """start the virtual environment manager"""
        self.logger.debug("starting virtual environment manager")
        self.is_running = True

        # start producer task
        producer_task = asyncio.create_task(self.produce_events())
        producer_task.add_done_callback(self.handle_task_exception)

        # start consumer tasks
        for i in range(self.num_consumers):
            consumer_task = asyncio.create_task(self.consume_events(i))
            consumer_task.add_done_callback(self.handle_task_exception)
            self.consumer_tasks.append(consumer_task)

        # schedule periodic scans
        self.producer_tasks["periodic"] = asyncio.create_task(self.periodic_scan())
        self.producer_tasks["periodic"].add_done_callback(self.handle_task_exception)

        self.logger.debug("virtual environment manager started")

    async def periodic_scan(self):
        """run periodic scans of virtual machines"""
        self.logger.debug(
            f"starting periodic vm scans every {VIRTENV_CHECK_INTERVAL} seconds"
        )
        while self.is_running:
            try:
                await asyncio.sleep(VIRTENV_CHECK_INTERVAL)
                self.logger.debug("running periodic vm scan")
                await self.produce_events()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"error in periodic scan: {str(e)}")

    def handle_task_exception(self, task):
        """handle exceptions in background tasks"""
        try:
            exc = task.exception()
            if exc:
                self.logger.error(f"task exception: {str(exc)}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"error handling task exception: {str(e)}")

    async def stop(self):
        """stop the virtual environment manager"""
        self.logger.debug("stopping virtual environment manager")
        self.is_running = False

        # cancel all consumer tasks
        for task in self.consumer_tasks:
            task.cancel()

        # cancel all producer tasks
        for task_name, task in self.producer_tasks.items():
            task.cancel()

        # wait for all tasks to complete
        all_tasks = list(self.consumer_tasks) + list(self.producer_tasks.values())
        if all_tasks:
            await asyncio.gather(*all_tasks, return_exceptions=True)

        self.consumer_tasks = []
        self.producer_tasks = {}

        # close executor
        self.executor.shutdown(wait=False)

        self.logger.debug("virtual environment manager stopped")
