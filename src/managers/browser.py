import asyncio
import configparser
import json
import logging
import mimetypes
import os
import plistlib
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Dict, List

import aiofiles
import aiosqlite
import filetype
from peewee import DoesNotExist

from config import (
    BROWSER_CHROME_LINUX_HISTORY_PATH,
    BROWSER_CHROME_MACOS_HISTORY_PATH,
    BROWSER_CHROME_WINDOWS_HISTORY_PATH,
    BROWSER_FIREFOX_LINUX_HISTORY_PATH,
    BROWSER_FIREFOX_MACOS_HISTORY_PATH,
    BROWSER_FIREFOX_WINDOWS_HISTORY_PATH,
    BROWSER_SAFARI_MACOS_HISTORY_PATH,
    BROWSER_SERVICE_BROWSERS_ENABLED,
    SYSTEM,
)
from storage.database import BrowserScanHistory
from storage.httpapi import StracApi


class Browser:
    def __init__(self, num_consumers: int = 5, queue_size: int = 150):
        self.name = "manager-browser"
        self.logger = logging.getLogger(self.name)
        self.producer_tasks: Dict[str, asyncio.Task] = {}
        self.consumer_tasks: List[asyncio.Task] = []
        self.is_running = False
        self.num_consumers = num_consumers
        self.queue = asyncio.Queue(maxsize=queue_size)
        self.executor = ThreadPoolExecutor()

    def _expand_user_path(self, additional_path=None):
        username = SYSTEM.current_user
        home_path = os.path.expanduser(f"~{username}")
        if not username:
            self.logger.error("EXPAND_USER_PATH", "failed to get username")
            return None
        return os.path.join(home_path, additional_path)

    async def _async_call(self, func, *args, **kwargs):
        # self.logger.debug(f"calling {func.__name__} with {args} {kwargs}")
        event_loop = asyncio.get_event_loop()
        result = await event_loop.run_in_executor(self.executor, func, *args, **kwargs)
        # self.logger.debug(f"result: {result}")
        return result

    async def get_chrome_history_path(self):
        if SYSTEM.OS_IS_MACOS:  # macOS
            history_path = self._expand_user_path(BROWSER_CHROME_MACOS_HISTORY_PATH)
        elif SYSTEM.OS_IS_WINDOWS:
            history_path = os.path.join(
                os.getenv("LOCALAPPDATA"), BROWSER_CHROME_WINDOWS_HISTORY_PATH
            )
        elif SYSTEM.OS_IS_LINUX:
            history_path = self._expand_user_path(BROWSER_CHROME_LINUX_HISTORY_PATH)
        else:
            raise Exception(f"unsupported operating system: {SYSTEM.get_os_name()}")
        # self.logger.debug(f"chrome history_path: {history_path}")
        return history_path

    async def get_firefox_history_path(self):
        if SYSTEM.OS_IS_MACOS:  # macOS
            firefox_path = self._expand_user_path(BROWSER_FIREFOX_MACOS_HISTORY_PATH)
        elif SYSTEM.OS_IS_WINDOWS:
            firefox_path = os.path.join(
                os.getenv("APPDATA"), BROWSER_FIREFOX_WINDOWS_HISTORY_PATH
            )
        elif SYSTEM.OS_IS_LINUX:
            firefox_path = self._expand_user_path(BROWSER_FIREFOX_LINUX_HISTORY_PATH)
        else:
            raise Exception(f"unsupported operating system: {SYSTEM.get_os_name()}")
        try:
            profile_ini = os.path.join(firefox_path, "..", "profiles.ini")
            try:
                async with aiofiles.open(profile_ini, "r") as f:
                    content = await f.read()
                    config_parser = configparser.ConfigParser()
                    config_parser.read_string(content)
                    sections = config_parser.sections()
                    install_section = [
                        section for section in sections if section.startswith("Install")
                    ][0]
                    default_profile = config_parser.get(install_section, "Default")
                    history_path = os.path.join(
                        firefox_path, "..", default_profile, "places.sqlite"
                    )
                    # self.logger.debug(f"firefox history_path: {history_path}")
                    return history_path
            except Exception as e:
                raise Exception("no default firefox profile found")
        except Exception as e:
            self.logger.error(f"error finding firefox profile: {str(e)}")
            raise

    async def get_safari_history_path(self):
        if SYSTEM.OS_IS_MACOS:
            history_path = self._expand_user_path(BROWSER_SAFARI_MACOS_HISTORY_PATH)
        else:
            raise Exception("safari history is only available on macOS")
        # self.logger.debug(f"safari history_path: {history_path}")
        return history_path

    async def get_last_scan_time(self, browser):
        try:
            scan = BrowserScanHistory.get(BrowserScanHistory.browser == browser)
            return (
                datetime.fromisoformat(scan.last_scan)
                if isinstance(scan.last_scan, str)
                else scan.last_scan
            )
        except DoesNotExist:
            return None
        except Exception as e:
            self.logger.error(f"error getting last scan time for {browser}: {str(e)}")
            return None

    async def update_scan_time(self, browser):
        try:
            BrowserScanHistory.replace(
                browser=browser, last_scan=datetime.now(timezone.utc)
            ).execute()
            self.logger.debug(f"updated scan time for {browser}")
        except Exception as e:
            self.logger.error(f"failed to update scan time for {browser}: {str(e)}")

    async def get_file_info(self, file_path):
        try:
            if not await self._async_call(os.path.exists, file_path):
                return 0, False, None

            file_size = await self._async_call(os.path.getsize, file_path)
            mime_type = filetype.guess(file_path)
            if mime_type is None:
                mime_type, _ = mimetypes.guess_type(file_path)
            else:
                mime_type = mime_type.mime

            return file_size, True, mime_type
        except Exception as e:
            self.logger.error(f"error getting file info for {file_path}: {str(e)}")
            return 0, False, None

    async def parse_downloads(self, browser: str):
        if browser == "chrome":
            return await self.parse_chrome_downloads()
        elif browser == "firefox":
            pass
            # return await self.parse_firefox_downloads()
        elif browser == "safari":
            return await self.parse_safari_downloads()

    async def parse_chrome_downloads(self):
        try:
            history_path = await self.get_chrome_history_path()
            if not await self._async_call(os.path.exists, history_path):
                self.logger.warning("chrome history file not found")
                return []

            # creates a temporary copy of the history file since the originial might be locked
            temp_history = f"{SYSTEM.log_path}/chrome_history_temp"
            await self._async_call(shutil.copy2, history_path, temp_history)
            await self._async_call(os.chmod, temp_history, 0o777)

            last_scan = await self.get_last_scan_time("chrome")

            results = []

            async with aiosqlite.connect(temp_history) as db:
                query = """
                    SELECT target_path, tab_url, start_time, received_bytes
                    FROM downloads
                    WHERE start_time > ?
                """

                # NOTE: chrome uses microseconds since 1601-01-01, UTC
                epoch_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
                params = [
                    (
                        (last_scan - epoch_1601).total_seconds() * 1_000_000
                        if last_scan
                        else 0
                    )
                ]

                async with db.execute(query, params) as cursor:
                    async for row in cursor:
                        local_path = row[0]
                        if SYSTEM.OS_IS_WINDOWS:
                            local_path = local_path.replace("/", "\\")

                        file_size, exists, mime_type = await self.get_file_info(
                            local_path
                        )

                        download_time = datetime(1601, 1, 1) + timedelta(
                            microseconds=row[2]
                        )

                        results.append(
                            {
                                "filename": os.path.basename(local_path),
                                "local_path": local_path,
                                "source_url": row[1],
                                "download_time": download_time,
                                "file_size": row[3] or file_size,
                                "browser": "chrome",
                                "file_exists": exists,
                                "mime_type": mime_type,
                            }
                        )

                await self._async_call(os.remove, temp_history)
                await self.update_scan_time("chrome")
                # self.logger.debug("chrome history parsed successfully")
                return results

        except Exception as e:
            self.logger.error(f"error parsing chrome history: {str(e)}")

    async def parse_firefox_downloads(self):
        try:
            history_path = await self.get_firefox_history_path()
            if not await self._async_call(os.path.exists, history_path):
                self.logger.warning("firefox history file not found")
                return []

            temp_history = f"{SYSTEM.log_path}/firefox_history_temp"
            await self._async_call(shutil.copy2, history_path, temp_history)
            await self._async_call(os.chmod, temp_history, 0o777)

            last_scan = await self.get_last_scan_time("firefox")

            async with aiosqlite.connect(temp_history) as db:
                query = """
                    SELECT moz_annos.content, moz_places.url, moz_annos.dateAdded
                    FROM moz_annos
                    JOIN moz_places ON moz_annos.place_id = moz_places.id
                    WHERE moz_annos.dateAdded > ?
                """

                # NOTE: firefox uses microseconds since 1970-01-01
                params = [(last_scan.timestamp() * 1000000) if last_scan else 0]
                # params = [
                #     (datetime.datetime.now() - datetime.timedelta(days=1)).timestamp()
                #     * 1000000
                # ]

                results = []

                async with db.execute(query, params) as cursor:
                    async for row in cursor:
                        try:
                            download_path = "FIXME"
                            # if not download_path:
                            #     continue

                            if SYSTEM.OS_IS_WINDOWS:
                                download_path = download_path.replace("/", "\\")

                            file_size, exists, mime_type = await self.get_file_info(
                                download_path
                            )
                            download_time = datetime.fromtimestamp(row[2] / 1000000)
                            results.append(
                                {
                                    "filename": os.path.basename(download_path),
                                    "local_path": download_path,
                                    "source_url": row[1],
                                    "download_time": download_time,
                                    "file_size": file_size,
                                    "browser": "firefox",
                                    "file_exists": exists,
                                    "mime_type": mime_type,
                                }
                            )

                        except json.JSONDecodeError:
                            continue

                await self._async_call(os.remove, temp_history)
                await self.update_scan_time("firefox")
                # self.logger.debug("firefox history parsed successfully")
                return results

        except Exception as e:
            self.logger.error(f"error parsing firefox history: {str(e)}")
            return []

    async def parse_safari_downloads(self):
        try:
            history_path = await self.get_safari_history_path()
            if not await self._async_call(os.path.exists, history_path):
                self.logger.warning("safari history file not found")
                return []

            temp_history = f"{SYSTEM.log_path}/safari_history_temp"
            await self._async_call(shutil.copy2, history_path, temp_history)
            await self._async_call(os.chmod, temp_history, 0o777)

            # safari uses a binary plist file, so we need to use plistlib
            last_scan = await self.get_last_scan_time("safari")

            async with aiofiles.open(temp_history, "rb") as f:
                value = await f.read()
                downloads = plistlib.loads(value)

                results = []

                for download in downloads.get("DownloadHistory", []):
                    # skip if we've already processed this download
                    download_time = download.get("DownloadEntryDateAddedKey")
                    # this is UTC but we get a naive datetime
                    download_time = download_time.replace(tzinfo=timezone.utc)

                    if last_scan and download_time <= last_scan:
                        continue

                    local_path = download.get("DownloadEntryPath")
                    if not local_path:
                        continue

                    file_size, exists, mime_type = await self.get_file_info(local_path)

                    results.append(
                        {
                            "filename": os.path.basename(local_path),
                            "local_path": local_path,
                            "source_url": download.get("DownloadEntryURL", ""),
                            "download_time": download_time,
                            "file_size": download.get(
                                "DownloadEntryProgressTotalToLoad", file_size
                            ),
                            "browser": "safari",
                            "file_exists": exists,
                            "mime_type": mime_type,
                        }
                    )

                await self._async_call(os.remove, temp_history)
                await self.update_scan_time("safari")
                # self.logger.debug("safari history parsed successfully")
                return results

        except Exception as e:
            self.logger.error(f"error parsing safari history: {e}")

    async def produce_events(self, browser: str):
        while self.is_running:
            try:
                events = await self.parse_downloads(browser)
                for event in events:
                    await self.queue.put(event)
            except Exception as e:
                self.logger.error(f"error creating event: {str(e)}")
            await asyncio.sleep(30)

    async def consume_events(self, consumer_id: int):
        """Consumer: processes lines from the queue"""
        self.logger.debug(f"Browser consumer {consumer_id} starting")
        while self.is_running:
            try:
                # Get event from queue with timeout
                event = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                self.logger.debug(f"Browser consumer {consumer_id} got event: {event}")
                try:
                    await self.process_event(event, consumer_id)
                finally:
                    self.queue.task_done()
            except asyncio.TimeoutError:
                # No line available, check if we should keep running
                continue
            except Exception as e:
                self.logger.error(f"Browser consumer {consumer_id} error: {e}")
                continue
        self.logger.debug(f"Browser consumer {consumer_id} stopping")

    async def process_event(self, event, consumer_id: int):
        self.logger.debug(f"Browser consumer {consumer_id} processing: {event}")
        timestamp, filepath, app_name, file_exists, url = (
            event["download_time"],
            event["local_path"],
            event["browser"],
            event["file_exists"],
            event["source_url"],
        )
        file_access = (timestamp, filepath, app_name, url)
        if file_exists:
            client = StracApi()
            self.logger.info(f"browser.process_event: {filepath}")
            await client.process_document(file_access)

    async def start(self):
        """Start producer and all consumers"""
        if self.is_running:
            self.logger.warning("Browser monitor is already running")
            return

        self.is_running = True

        def handle_task_exception(task):
            try:
                task.result()
            except asyncio.CancelledError:
                pass
            except Exception as e:
                self.logger.error(f"Task {task} raised an exception: {e}")

        # Start consumers
        self.consumer_tasks = []
        for i in range(self.num_consumers):
            task = asyncio.create_task(self.consume_events(i))
            task.add_done_callback(handle_task_exception)
            self.consumer_tasks.append(task)

        # Start producers
        for browser in BROWSER_SERVICE_BROWSERS_ENABLED:
            if not SYSTEM.OS_IS_MACOS and browser == "safari":
                continue
            self.producer_tasks[browser] = asyncio.create_task(
                self.produce_events(browser)
            )
            self.producer_tasks[browser].add_done_callback(handle_task_exception)
            self.logger.debug(f"Browser producer for {browser} started")

        self.logger.debug(
            f"Browser monitor started with {self.num_consumers} consumers"
        )

        while self.is_running:
            await asyncio.sleep(3)

        # # TODO
        # # - add a better file info/mimetype method
        # # - add additional browser support (edge, brave, etc.)

    async def stop(self):
        """
        Stop the browser monitoring.

        Sets the stop event to terminate the monitoring loop gracefully.
        """

        if not self.is_running:
            self.logger.warning("Browser monitor is not running")
            return

        self.logger.debug("Stopping browser monitor...")
        self.is_running = False

        # Wait for producers to complete
        for task in self.producer_tasks.values():
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Wait for queue to be empty
        if not self.queue.empty():
            try:
                await asyncio.wait_for(self.queue.join(), timeout=1.0)
            except asyncio.TimeoutError:
                pass

        # Wait for all consumers to complete
        if self.consumer_tasks:
            for task in self.consumer_tasks:
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            self.consumer_tasks = []

        self.logger.debug("Browser monitor stopped")
