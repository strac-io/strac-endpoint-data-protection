import asyncio
import collections
import datetime
import logging
import re
import time
from typing import List, Optional

import psutil

from config import (
    ACCESS_IGNORE_APPS,
    ACCESS_IGNORE_DIRECTORIES,
    ACCESS_IGNORE_FILENAME_EXACT,
    ACCESS_IGNORE_FILENAMES,
    SYSTEM,
)
from storage.database import AccessFSUsageLog
from storage.httpapi import StracApi

# TODO:
# - + add usb as an application to filter by

# uncomment to log to a file

# logging.basicConfig(
#     level=logging.DEBUG,
#     format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
#     # stream=os.sys.stdout,
#     handlers=[
#         logging.FileHandler(f"access.log"),
#     ],
# )


class FSUsage:
    """
    File System Usage monitoring class that tracks file access patterns
    of specific applications via `fs_usage`.

    Note:
        This currently only works for macOS.

    This class provides methods to start and stop monitoring file system
    access events, parse log entries, and report relevant events to StracAPI.
    """

    # length of syscall field in log is always 17 with 2 spaces before it
    # taken from https://github.com/apple-oss-distributions/system_cmds/blob/56f28fa802f4c21f687637fac27793932eedfbb3/fs_usage/fs_usage.c#L1750
    OPEN_SYSCALL_PATTERN = "  open             "

    def __init__(self, num_consumers: int = 12, queue_size: int = 1200):
        self.name = "manager-access"
        self.logger = logging.getLogger(self.name)
        self.process: Optional[asyncio.subprocess.Process] = None
        self.producer_task = None
        self.consumer_tasks: List[asyncio.Task] = []
        self.is_running = False
        self.num_consumers = num_consumers
        self.queue = asyncio.Queue(maxsize=queue_size)

    async def kill_processes(self, process_names):
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"] in process_names:
                    self.logger.debug(
                        f"killing prior running process='{proc.info['name']}' pid='{proc.info['pid']}')"
                    )
                    psutil.Process(proc.info["pid"]).kill()
                    time.sleep(0.5)  # give the system time to clean up
                    self.process = None
            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ) as e:
                self.logger.error(f"error killing prior running process: {str(e)}")
                self.process = None

    async def produce_lines(self):
        """
        Start monitoring file system access events.

        This method:
        1. Launches fs_usage in non-blocking mode
        2. Filters events for specific applications
        3. Sends unique file access events to consumer
        4. Logs events to AccessFSUsageLog

        The method runs until stop() is called or interrupted.

        Note:
            Requires sudo access to run fs_usage.

        Raises:
            Exception: If there's an error sending events to StracAPI
        """

        self.logger.debug("Producer starting")

        brave_pattern = r"[bB]rave"
        chrome_pattern = r"[cC]hrome"
        cyberduck_pattern = r"[cC]yberduck"
        curl_pattern = r"[cC]url"
        discord_pattern = r"[dD]iscord"
        edge_pattern = r"[eE]dge"
        evernote_pattern = r"[eE]vernote"
        filezilla_pattern = r"[fF]ilezilla"
        firefox_pattern = r"[fF]irefox"
        ftp_pattern = r"[fF]TP"
        lftp_pattern = r"[lL]ftp"
        mail_pattern = r"[mM]ail"
        messages_pattern = r"[mM]essages"
        notes_pattern = r"[nN]otes"
        notion_pattern = r"[nN]otion"
        obsidian_pattern = r"[oO]bsidian"
        opera_pattern = r"[oO]pera"
        outlook_pattern = r"[mM]icrosoft\s[oO]utlook"
        rsync_pattern = r"[rR]sync"
        safari_pattern = r"[sS]afari"
        safari_webkit_pattern = r"com\.apple\.WebKit\.Networking"
        scp_pattern = r"[sS]cp"
        sftp_pattern = r"[sS]ftp"
        skype_pattern = r"[sS]kype"
        signal_pattern = r"[sS]ignal"
        slack_pattern = r"[sS]lack"
        teams_pattern = r"[tT]eams"
        telegram_pattern = r"[tT]elegram"
        telnet_pattern = r"[tT]elnet"
        terminal_pattern = r"[tT]erminal"
        wechat_pattern = r"[wW]echat"
        wget_pattern = r"[wW]get"
        whatsapp_pattern = r"[wW]hats[aA]pp"
        zalo_pattern = r"[zZ]alo"
        zoom_pattern = r"[zZ]oom"

        app_name_patterns = [
            brave_pattern,
            chrome_pattern,
            curl_pattern,
            cyberduck_pattern,
            discord_pattern,
            edge_pattern,
            evernote_pattern,
            filezilla_pattern,
            firefox_pattern,
            ftp_pattern,
            lftp_pattern,
            mail_pattern,
            messages_pattern,
            notes_pattern,
            notion_pattern,
            obsidian_pattern,
            opera_pattern,
            outlook_pattern,
            rsync_pattern,
            safari_pattern,
            safari_webkit_pattern,
            scp_pattern,
            sftp_pattern,
            signal_pattern,
            skype_pattern,
            slack_pattern,
            teams_pattern,
            telegram_pattern,
            telnet_pattern,
            terminal_pattern,
            wechat_pattern,
            wget_pattern,
            whatsapp_pattern,
            zalo_pattern,
            zoom_pattern,
        ]

        scanning_cache_size = 50
        recent_accesses_list = collections.deque(maxlen=scanning_cache_size)
        recent_accesses_set = set()

        try:
            # kill any existing fs_usage processes
            await self.kill_processes(["fs_usage"])

            # add a small delay after killing processes
            await asyncio.sleep(3)

            # start fs_usage
            self.process = await asyncio.create_subprocess_shell(
                "sudo fs_usage -w -f pathname",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # check if we started fs_usage
            if not self.process:
                self.logger.error("Failed to start fs_usage subprocess")
                raise RuntimeError("Failed to start fs_usage subprocess")

            while self.is_running:
                try:
                    line = await self.process.stdout.readline()
                    if not line:
                        continue

                    if isinstance(line, bytes):
                        line = line.decode().strip()
                    else:
                        line = line.strip()

                    if (
                        line
                        and self.OPEN_SYSCALL_PATTERN in line
                        and any(
                            re.search(pattern, line) for pattern in app_name_patterns
                        )
                    ):
                        should_process = True
                        file_name = None
                        ts, filepath, app_name = await self._parse_log_line(line)

                        if not any(
                            re.search(pattern, app_name)
                            for pattern in app_name_patterns
                        ):
                            should_process = False

                        if should_process:
                            if not filepath or not app_name:
                                should_process = False

                        if should_process and not SYSTEM.is_file(filepath):
                            should_process = False

                        if should_process:
                            # get filename once and reuse it - done here to avoid bunk names
                            file_name = SYSTEM.get_file_name(filepath)
                            should_process = file_name is not None

                        access_key = f"{filepath}:{app_name}"

                        if should_process and file_name.startswith("."):
                            should_process = False

                        if should_process:
                            if any(
                                ignore_dir in str(filepath)
                                for ignore_dir in ACCESS_IGNORE_DIRECTORIES
                            ):
                                should_process = False

                        if should_process:
                            file_name_lower = file_name.lower()
                            if any(
                                ignore_file.lower() in file_name_lower
                                for ignore_file in ACCESS_IGNORE_FILENAMES
                            ):
                                should_process = False

                        if should_process:
                            if file_name.lower() in (
                                f.lower() for f in ACCESS_IGNORE_FILENAME_EXACT
                            ):
                                should_process = False

                        if should_process:
                            # check exact match first since it's faster
                            if app_name in ACCESS_IGNORE_APPS:
                                should_process = False
                            # only do the more expensive substring check if should_process is still true
                            elif should_process:
                                line_lower = str(line).lower()
                                if any(
                                    app.lower() in line_lower
                                    for app in ACCESS_IGNORE_APPS
                                ):
                                    should_process = False

                        if should_process:
                            if any(
                                access_key.startswith(prefix)
                                for prefix in recent_accesses_set
                            ):
                                self.logger.debug(
                                    f"skipping {access_key} as it is recent"
                                )
                                should_process = False

                        if should_process:
                            if len(recent_accesses_list) >= recent_accesses_list.maxlen:
                                recent_accesses_set.remove(recent_accesses_list[0])
                            recent_accesses_list.append(access_key)
                            recent_accesses_set.add(access_key)

                            try:
                                await self.queue.put(
                                    (ts, filepath, app_name.lower().replace(" ", "-"))
                                )
                            except Exception as e:
                                self.logger.error(
                                    f"produce_lines queue.put error: {str(e)}"
                                )
                                continue
                            AccessFSUsageLog.create(
                                timestamp=ts,
                                filepath=filepath,
                                app_name=app_name,
                            )
                            self.logger.debug(
                                f"start time='{app_name}' path='{filepath}' app='{app_name}'"
                            )
                        else:
                            continue
                except Exception as e:
                    self.logger.error(f"reading line: {str(e)}")
                    break
        except Exception as e:
            self.logger.error(f"produce_lines: {str(e)}")
        finally:
            self.logger.debug("producer stopping")

    async def consume_lines(self, consumer_id: int):
        """Consumer: processes lines from the queue"""
        while self.is_running:
            try:
                # Get line from queue with timeout
                file_access = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                try:
                    await self.process_line(file_access, consumer_id)
                finally:
                    self.queue.task_done()
            except asyncio.TimeoutError:
                # had log message here but it was too noisy
                continue
            except Exception as e:
                self.logger.error(f"consume_lines error: {str(e)}")
                continue

    async def _parse_log_line(self, line):
        """
        Parse a log line from fs_usage output into components.

        Args:
            line (bytes): Raw log line from fs_usage

        Returns:
            tuple: (timestamp, filepath, app_name)
                - timestamp (str): Formatted timestamp (YYYY-MM-DD HH:MM:SS)
                - filepath (str): Path to the accessed file
                - app_name (str): Name of the accessing application

        Example:
            >>> monitor = FSUsage()
            >>> timestamp, path, app = monitor.parse_log_line(b"14:30:15  fsgetpath ... Chrome")
        """
        timestamp, rest = line.split(self.OPEN_SYSCALL_PATTERN)

        ts_prefix = datetime.datetime.now().strftime("%Y-%m-%d")
        timestamp = f"{ts_prefix} {timestamp.strip()}"

        # parse out app name, working from the back of the line
        # time taken field is always a.bbbbbb with 1 space before it, 1 space after, and optionally a W
        # taken from https://github.com/apple-oss-distributions/system_cmds/blob/56f28fa802f4c21f687637fac27793932eedfbb3/fs_usage/fs_usage.c#L2925
        time_taken_pattern = r" [ 0-9]{2}\d\.\d{6} [ W] "
        parts = re.split(time_taken_pattern, rest)
        app_name = parts[-1].strip() if len(parts) > 1 else ""
        # Find last dot with a number after it and the end in app name to extract base app name
        dot_idx = app_name.rfind(".")
        if dot_idx != -1 and all(
            # ascii values for 0-9
            ord(c) >= 48 and ord(c) <= 57
            for c in app_name[dot_idx + 1 :].rstrip()
        ):
            app_name = app_name[:dot_idx]

        # parse out filepath, by looking for the read flags pattern (only reads for now because those are uploads)
        read_flags_pattern = r" \(R___________\) |" + r" \(R_________V_\) "
        filepath_and_flags = parts[-2].strip() if len(parts) > 1 else ""
        filepath_and_flags_parts = re.split(read_flags_pattern, filepath_and_flags)
        filepath = (
            filepath_and_flags_parts[-1] if len(filepath_and_flags_parts) > 1 else ""
        )
        return timestamp.strip(), filepath.strip(), app_name

    async def process_line(self, file_access, consumer_id: int):
        """Process a single line - customize this method"""
        timestamp, filepath, app_name = file_access
        if SYSTEM.is_file(filepath):
            client = StracApi()
            self.logger.info(f"access.process_line: {filepath}")
            await client.process_document((timestamp, filepath, app_name, None))

    async def start(self):
        """Start producer and all consumers"""
        if self.is_running:
            self.logger.warning("access manager is already running")
            return

        self.is_running = True

        def handle_task_exception(task):
            try:
                task.result()
            except asyncio.CancelledError:
                pass
            except Exception as e:
                self.logger.error(
                    f"start.handle_task_exception task: {str(task)} exception: {str(e)}"
                )

        # Start consumers
        self.consumer_tasks = []
        for i in range(self.num_consumers):
            task = asyncio.create_task(self.consume_lines(i))
            task.add_done_callback(handle_task_exception)
            self.consumer_tasks.append(task)

        # Start producer
        self.producer_task = asyncio.create_task(self.produce_lines())
        self.producer_task.add_done_callback(handle_task_exception)

        self.logger.debug(
            f"access manager started with {str(self.num_consumers)} consumers"
        )

        while self.is_running:
            await asyncio.sleep(1)

    async def stop(self):
        """
        Stop the file system monitoring.

        Sets the stop event to terminate the monitoring loop gracefully.

        Example:
            >>> monitor = FSUsage()
            >>> monitor.start()  # Start in another thread
            >>> # ... some time later ...
            >>> monitor.stop()  # Stops monitoring
        """

        if not self.is_running:
            self.logger.warning("access manager is not running")
            return

        self.logger.debug("Stopping access manager...")
        self.is_running = False

        # Stop the process
        if self.process:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except Exception as e:
                self.process.kill()
            self.process = None

        # Wait for producer to complete
        if self.producer_task and not self.producer_task.done():
            self.producer_task.cancel()
            try:
                await self.producer_task
            except asyncio.CancelledError:
                pass

        # Wait for queue to be empty
        if not self.queue.empty():
            try:
                await asyncio.wait_for(self.queue.join(), timeout=1.5)
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

        self.logger.debug("access manager stopped")


class AuditD:
    """
    linux audit monitoring class that tracks file access patterns
    via `/var/log/audit/audit.log`.

    note:
        this only works for linux systems with audit daemon enabled.

    this class provides methods to start and stop monitoring file system
    access events, parse audit log entries, and report relevant events to stracapi.
    """

    # pattern to match file open syscalls in audit log
    SYSCALL_PATTERN = "type=SYSCALL"
    PATH_PATTERN = "type=PATH"
    EXECVE_PATTERN = "type=EXECVE"

    def __init__(self, num_consumers: int = 12, queue_size: int = 1200):
        self.name = "manager-auditd"
        self.logger = logging.getLogger(self.name)
        self.process: Optional[asyncio.subprocess.Process] = None
        self.producer_task = None
        self.consumer_tasks: List[asyncio.Task] = []
        self.is_running = False
        self.num_consumers = num_consumers
        self.queue = asyncio.Queue(maxsize=queue_size)
        self.event_buffer = {}  # store related audit events by audit_id

    async def kill_processes(self, process_names):
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"] in process_names:
                    self.logger.debug(
                        f"killing prior running process='{proc.info['name']}' pid='{proc.info['pid']}')"
                    )
                    psutil.Process(proc.info["pid"]).kill()
                    time.sleep(0.5)  # give the system time to clean up
                    self.process = None
            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ) as e:
                self.logger.error(f"error killing prior running process: {str(e)}")
                self.process = None

    async def produce_lines(self):
        """
        start monitoring file system access events via linux audit logs.

        this method:
        1. launches 'ausearch' or directly tails the audit log
        2. filters events for file access operations
        3. sends unique file access events to consumer
        4. logs events to accessfsusagelog

        the method runs until stop() is called or interrupted.

        note:
            requires proper permissions to read audit logs.

        raises:
            exception: if there's an error processing audit logs
        """

        self.logger.debug("Producer starting")

        brave_pattern = r"[bB]rave"
        chrome_pattern = r"[cC]hrome"
        cyberduck_pattern = r"[cC]yberduck"
        discord_pattern = r"[dD]iscord"
        edge_pattern = r"[eE]dge"
        evernote_pattern = r"[eE]vernote"
        filezilla_pattern = r"[fF]ilezilla"
        firefox_pattern = r"[fF]irefox"
        thunderbird_pattern = r"[tT]hunderbird"
        evolution_pattern = r"[eE]volution"
        notes_pattern = r"[nN]otes"
        notion_pattern = r"[nN]otion"
        obsidian_pattern = r"[oO]bsidian"
        opera_pattern = r"[oO]pera"
        outlook_pattern = r"[oO]utlook"
        skype_pattern = r"[sS]kype"
        signal_pattern = r"[sS]ignal"
        slack_pattern = r"[sS]lack"
        teams_pattern = r"[tT]eams"
        telegram_pattern = r"[tT]elegram"
        whatsapp_pattern = r"[wW]hats[aA]pp"
        zalo_pattern = r"[zZ]alo"
        zoom_pattern = r"[zZ]oom"

        app_name_patterns = [
            brave_pattern,
            chrome_pattern,
            cyberduck_pattern,
            discord_pattern,
            edge_pattern,
            evernote_pattern,
            filezilla_pattern,
            firefox_pattern,
            thunderbird_pattern,
            evolution_pattern,
            notes_pattern,
            notion_pattern,
            obsidian_pattern,
            opera_pattern,
            outlook_pattern,
            signal_pattern,
            skype_pattern,
            slack_pattern,
            teams_pattern,
            telegram_pattern,
            whatsapp_pattern,
            zalo_pattern,
            zoom_pattern,
        ]

        scanning_cache_size = 50
        recent_accesses_list = collections.deque(maxlen=scanning_cache_size)
        recent_accesses_set = set()

        try:
            # start monitoring the audit log using ausearch for real-time events
            # -ts recent looks at events since boot, -i for interpretable format
            self.process = await asyncio.create_subprocess_shell(
                "sudo ausearch -f -ts recent -i --format raw | grep -E 'type=PATH|type=SYSCALL|type=EXECVE'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=True,
            )

            # check if we started the audit monitoring
            if not self.process:
                self.logger.error("Failed to start audit log monitoring subprocess")
                raise RuntimeError("Failed to start audit log monitoring subprocess")

            current_audit_id = None
            current_event = {}

            while self.is_running:
                try:
                    line = await self.process.stdout.readline()
                    if not line:
                        continue

                    if isinstance(line, bytes):
                        line = line.decode().strip()
                    else:
                        line = line.strip()

                    if not line:
                        continue

                    # check for a new audit event boundary
                    if "audit(" in line:
                        # extract audit_id
                        audit_id_match = re.search(r"audit\(([^:]+)", line)
                        if audit_id_match:
                            new_audit_id = audit_id_match.group(1)

                            # if we were processing an event and found a new one, process the completed event
                            if (
                                current_audit_id
                                and current_audit_id != new_audit_id
                                and current_event
                            ):
                                await self._process_audit_event(
                                    current_event,
                                    app_name_patterns,
                                    recent_accesses_list,
                                    recent_accesses_set,
                                )
                                current_event = {}

                            current_audit_id = new_audit_id

                    # store data based on the event type
                    if self.SYSCALL_PATTERN in line:
                        syscall_match = re.search(r"syscall=(\d+)", line)
                        if syscall_match:
                            syscall = syscall_match.group(1)
                            # syscalls 2, 3, 4, 5, 257 are open, read, write, close, openat
                            if syscall in ["2", "3", "4", "5", "257"]:
                                current_event["syscall"] = syscall

                                # extract process id and executable
                                pid_match = re.search(r"pid=(\d+)", line)
                                if pid_match:
                                    current_event["pid"] = pid_match.group(1)

                                # extract timestamp
                                timestamp_match = re.search(r"audit\(([^:]+)", line)
                                if timestamp_match:
                                    ts_raw = timestamp_match.group(1)
                                    try:
                                        ts_float = float(ts_raw.split(".")[0])
                                        ts_dt = datetime.datetime.fromtimestamp(
                                            ts_float
                                        )
                                        current_event["timestamp"] = ts_dt.strftime(
                                            "%Y-%m-%d %H:%M:%S"
                                        )
                                    except (ValueError, IndexError):
                                        current_event["timestamp"] = (
                                            datetime.datetime.now().strftime(
                                                "%Y-%m-%d %H:%M:%S"
                                            )
                                        )

                    elif self.PATH_PATTERN in line:
                        # extract file path information
                        path_match = re.search(r"name=\"([^\"]+)\"", line)
                        if path_match and "syscall" in current_event:
                            file_path = path_match.group(1)
                            current_event["filepath"] = file_path

                    elif self.EXECVE_PATTERN in line:
                        # extract command/app name
                        if "pid" in current_event:
                            app_name_match = re.search(r"a0=\"([^\"]+)\"", line)
                            if app_name_match:
                                app_path = app_name_match.group(1)
                                app_name = (
                                    app_path.split("/")[-1]
                                    if "/" in app_path
                                    else app_path
                                )
                                current_event["app_name"] = app_name

                except Exception as e:
                    self.logger.error(f"reading line: {str(e)}")
                    continue

        except Exception as e:
            self.logger.error(f"produce_lines: {str(e)}")
        finally:
            self.logger.debug("producer stopping")

    async def _process_audit_event(
        self, event, app_name_patterns, recent_accesses_list, recent_accesses_set
    ):
        # process a completed audit event
        if not ("filepath" in event and "syscall" in event):
            return

        filepath = event.get("filepath")
        app_name = event.get("app_name", "unknown")
        timestamp = event.get(
            "timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        # skip if no filepath or not supported syscall
        if not filepath or event["syscall"] not in ["2", "3", "4", "5", "257"]:
            return

        should_process = True

        # validate app name against patterns
        if app_name != "unknown" and app_name_patterns:
            found_match = False
            for pattern in app_name_patterns:
                if re.search(pattern, app_name):
                    found_match = True
                    break
            if not found_match:
                should_process = False

        # skip hidden files
        if should_process and filepath.split("/")[-1].startswith("."):
            should_process = False

        # skip ignored directories
        if should_process and any(
            ignore_dir in filepath for ignore_dir in ACCESS_IGNORE_DIRECTORIES
        ):
            should_process = False

        # skip ignored filenames
        if should_process:
            file_name = filepath.split("/")[-1]
            file_name_lower = file_name.lower()
            if any(
                ignore_file.lower() in file_name_lower
                for ignore_file in ACCESS_IGNORE_FILENAMES
            ):
                should_process = False

        # skip exact filename matches
        if should_process:
            file_name = filepath.split("/")[-1]
            if file_name.lower() in (f.lower() for f in ACCESS_IGNORE_FILENAME_EXACT):
                should_process = False

        # skip ignored apps
        if should_process and app_name in ACCESS_IGNORE_APPS:
            should_process = False

        # use cache to avoid duplication
        access_key = f"{filepath}:{app_name}"
        if should_process and any(
            access_key.startswith(prefix) for prefix in recent_accesses_set
        ):
            self.logger.debug(f"skipping {access_key} as it is recent")
            should_process = False

        if should_process:
            # update cache
            if len(recent_accesses_list) >= recent_accesses_list.maxlen:
                recent_accesses_set.remove(recent_accesses_list[0])
            recent_accesses_list.append(access_key)
            recent_accesses_set.add(access_key)

            try:
                await self.queue.put(
                    (timestamp, filepath, app_name.lower().replace(" ", "-"))
                )
            except Exception as e:
                self.logger.error(f"_process_audit_event queue.put error: {str(e)}")
                return

            AccessFSUsageLog.create(
                timestamp=timestamp,
                filepath=filepath,
                app_name=app_name,
            )
            self.logger.debug(
                f"start time='{timestamp}' path='{filepath}' app='{app_name}'"
            )

    async def check_ausearch_installed(self):
        """check if ausearch is installed on the system"""
        try:
            process = await asyncio.create_subprocess_shell(
                "which ausearch",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0 and stdout:
                self.logger.debug("ausearch is installed")
                return True
            else:
                self.logger.warning("ausearch is not installed")
                return False
        except Exception as e:
            self.logger.error(f"Error checking if ausearch is installed: {str(e)}")
            return False

    async def install_ausearch(self):
        """install ausearch package on the system"""
        self.logger.info("Attempting to install ausearch...")

        # detect linux distribution
        try:
            process = await asyncio.create_subprocess_shell(
                "cat /etc/os-release",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            os_info = stdout.decode()

            install_cmd = ""
            if "debian" in os_info.lower() or "ubuntu" in os_info.lower():
                install_cmd = "sudo apt-get update && sudo apt-get install -y auditd audispd-plugins"
            elif (
                "fedora" in os_info.lower()
                or "rhel" in os_info.lower()
                or "centos" in os_info.lower()
            ):
                install_cmd = "sudo dnf install -y audit"
            elif "arch" in os_info.lower():
                install_cmd = "sudo pacman -S --noconfirm audit"
            elif "suse" in os_info.lower():
                install_cmd = "sudo zypper install -y audit"
            else:
                self.logger.error(
                    "Unsupported Linux distribution, cannot install ausearch automatically"
                )
                return False

            if install_cmd:
                self.logger.info(f"Installing ausearch with command: {install_cmd}")
                process = await asyncio.create_subprocess_shell(
                    install_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    self.logger.info("Successfully installed ausearch")
                    return True
                else:
                    self.logger.error(f"Failed to install ausearch: {stderr.decode()}")
                    return False

        except Exception as e:
            self.logger.error(f"Error installing ausearch: {str(e)}")
            return False

    async def check_audit_permissions(self):
        """check if we have sufficient permissions to read audit logs"""
        try:
            # try to read from audit log file directly
            process = await asyncio.create_subprocess_shell(
                "sudo test -r /var/log/audit/audit.log && echo 'Access OK'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0 and b"Access OK" in stdout:
                self.logger.debug("Have permissions to read audit log file")
                return True

            # try to use ausearch to make sure we have permissions
            process = await asyncio.create_subprocess_shell(
                "sudo ausearch -ts recent -i -n 1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            # check if ausearch command ran successfully
            if process.returncode == 0:
                self.logger.debug("Have permissions to use ausearch")
                return True
            else:
                error = stderr.decode()
                if "Permission denied" in error:
                    self.logger.error("Insufficient permissions to access audit logs")
                else:
                    self.logger.error(f"Error accessing audit logs: {error}")
                return False

        except Exception as e:
            self.logger.error(f"Error checking audit log permissions: {str(e)}")
            return False

    async def consume_lines(self, consumer_id: int):
        # consumer: processes lines from the queue
        while self.is_running:
            try:
                # get line from queue with timeout
                file_access = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                try:
                    await self.process_line(file_access, consumer_id)
                finally:
                    self.queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"consume_lines error: {str(e)}")
                continue

    async def process_line(self, file_access, consumer_id: int):
        # process a single line from the audit log
        timestamp, filepath, app_name = file_access
        if SYSTEM.is_file(filepath):
            client = StracApi()
            self.logger.info(f"access.process_line: {filepath}")
            await client.process_document((timestamp, filepath, app_name, None))

    async def start(self):
        # start producer and all consumers
        if self.is_running:
            self.logger.warning("audit log manager is already running")
            return

        # check if ausearch is installed and we have permissions
        ausearch_installed = await self.check_ausearch_installed()
        if not ausearch_installed:
            self.logger.warning("ausearch not found, attempting to install...")
            install_success = await self.install_ausearch()
            if not install_success:
                self.logger.error(
                    "Failed to install ausearch. Audit monitoring cannot start."
                )
                return

        # check permissions to access audit logs
        permissions_ok = await self.check_audit_permissions()
        if not permissions_ok:
            self.logger.error(
                "Insufficient permissions to access audit logs. Audit monitoring cannot start."
            )
            return

        self.is_running = True

        def handle_task_exception(task):
            try:
                task.result()
            except asyncio.CancelledError:
                pass
            except Exception as e:
                self.logger.error(
                    f"start.handle_task_exception task: {str(task)} exception: {str(e)}"
                )

        # start consumers
        self.consumer_tasks = []
        for i in range(self.num_consumers):
            task = asyncio.create_task(self.consume_lines(i))
            task.add_done_callback(handle_task_exception)
            self.consumer_tasks.append(task)

        # start producer
        self.producer_task = asyncio.create_task(self.produce_lines())
        self.producer_task.add_done_callback(handle_task_exception)

        self.logger.debug(
            f"audit log manager started with {str(self.num_consumers)} consumers"
        )

        while self.is_running:
            await asyncio.sleep(1)

    async def stop(self):
        """
        stop the audit log monitoring.

        sets the stop event to terminate the monitoring loop gracefully.
        """

        if not self.is_running:
            self.logger.warning("audit log manager is not running")
            return

        self.logger.debug("Stopping audit log manager...")
        self.is_running = False

        # stop the process
        if self.process:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except Exception as e:
                self.process.kill()
            self.process = None

        # wait for producer to complete
        if self.producer_task and not self.producer_task.done():
            self.producer_task.cancel()
            try:
                await self.producer_task
            except asyncio.CancelledError:
                pass

        # wait for queue to be empty
        if not self.queue.empty():
            try:
                await asyncio.wait_for(self.queue.join(), timeout=1.5)
            except asyncio.TimeoutError:
                pass

        # wait for all consumers to complete
        if self.consumer_tasks:
            for task in self.consumer_tasks:
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            self.consumer_tasks = []

        self.logger.debug("audit log manager stopped")
