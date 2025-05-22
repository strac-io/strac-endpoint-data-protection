import datetime
import hashlib
import logging
import os
import time
from collections import OrderedDict
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from config import SYSTEM, USB_DRIVE_WHITELIST, USB_IGNORE_FILES, USB_IGNORE_FOLDERS
from storage.database import UsbDrive, UsbFileTransfer


class UsbManager:
    def __init__(self, whitelist=USB_DRIVE_WHITELIST):
        self.name = "manager-usb"
        self.logger = logging.getLogger(self.name)
        self.observers = {}
        self.known_mounts = set()
        self.running = False
        self.whitelist = set(whitelist) if whitelist else set()
        self.logger.info(
            f"started with whitelisted drives: {', '.join(self.whitelist) if self.whitelist else 'none'}"
        )

    def get_connected_drives(self):
        """get all connected usb drives based on the current operating system"""
        try:
            if SYSTEM.OS_IS_MACOS:
                return self._get_connected_drives_macos()
            elif SYSTEM.OS_IS_WINDOWS:
                return self._get_connected_drives_windows()
            elif SYSTEM.OS_IS_LINUX:
                return self._get_connected_drives_linux()
            else:
                self.logger.error("unsupported operating system")
                return []
        except Exception as e:
            self.logger.error(f"error getting usb drives: {e}")
            return []

    def _get_connected_drives_macos(self):
        """get all connected usb drives on macos"""
        # on macos, external drives are typically mounted at /volumes/
        volumes_path = Path("/Volumes")
        mount_points = []

        if volumes_path.exists():
            for volume in volumes_path.iterdir():
                if volume.is_mount() and volume.is_dir():
                    mount_points.append(volume)

        return mount_points

    def _get_connected_drives_windows(self):
        """get all connected usb drives on windows"""
        try:
            import win32file

            mount_points = []
            drives = win32file.GetLogicalDriveStrings().split("\000")[:-1]

            for drive in drives:
                if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    mount_points.append(Path(drive))

            return mount_points
        except ImportError:
            self.logger.error("win32file module not found. please install pywin32.")
            return []

    def _get_connected_drives_linux(self):
        """get all connected usb drives on linux"""
        mount_points = []

        # read mount points from /proc/mounts or /etc/mtab
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) > 1:
                        device, mount_point = parts[0], parts[1]
                        # check if this is likely a usb device
                        if device.startswith("/dev/sd") or "usb" in device:
                            path = Path(mount_point)
                            if path.exists() and path.is_dir():
                                mount_points.append(path)
        except FileNotFoundError:
            try:
                # alternative approach using /etc/mtab if /proc/mounts is not available
                with open("/etc/mtab", "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) > 1:
                            device, mount_point = parts[0], parts[1]
                            if device.startswith("/dev/sd") or "usb" in device:
                                path = Path(mount_point)
                                if path.exists() and path.is_dir():
                                    mount_points.append(path)
            except FileNotFoundError:
                self.logger.error("could not access mount information on linux")

        return mount_points

    def start(self):
        """start monitoring all connected usb drives"""
        self.logger.info("starting usb drive monitoring")
        self.running = True

        while self.running:
            try:
                # get current drives
                current_drives = self.get_connected_drives()
                current_mount_points = {str(drive) for drive in current_drives}

                # check for new drives
                for drive in current_drives:
                    mount_point = str(drive)
                    drive_name = os.path.basename(mount_point.rstrip(os.path.sep))

                    # windows drive paths end with \, handle this special case
                    if SYSTEM.OS_IS_WINDOWS and drive_name == "":
                        # for windows, use the drive letter as the name
                        drive_name = mount_point.rstrip("\\")

                    # skip drives in the whitelist
                    if drive_name in self.whitelist:
                        self.logger.debug(
                            f"skipping whitelisted drive: {drive_name} at {mount_point}"
                        )
                        continue

                    if mount_point not in self.known_mounts:
                        self.logger.info(
                            f"found new usb drive: {drive_name} at {mount_point}"
                        )

                        # add drive to database
                        try:
                            usb_drive, created = UsbDrive.get_or_create(
                                name=drive_name, mount_point=mount_point
                            )

                            if not created:
                                usb_drive.last_connected = datetime.datetime.now()
                                usb_drive.save()

                            # start watching this drive
                            event_handler = FileEventHandler(
                                self.logger, mount_point, drive_name
                            )
                            observer = Observer()
                            observer.schedule(
                                event_handler, mount_point, recursive=True
                            )
                            observer.daemon = True
                            observer.start()

                            # log detailed info about the observer
                            self.logger.info(
                                f"watching {drive_name} at {mount_point} recursively"
                            )

                            self.observers[mount_point] = observer
                            self.known_mounts.add(mount_point)

                            self.logger.info(f"now monitoring {drive_name}")

                        except Exception as e:
                            self.logger.error(
                                f"couldn't set up monitoring for {drive_name}: {e}"
                            )

                # check for disconnected drives or whitelisted drives
                disconnected = self.known_mounts - current_mount_points

                # check for whitelisted drives that are currently being monitored
                whitelisted_mounts = set()
                for mount_point in self.known_mounts:
                    drive_name = os.path.basename(mount_point.rstrip(os.path.sep))

                    # windows drive paths end with \, handle this special case
                    if SYSTEM.OS_IS_WINDOWS and drive_name == "":
                        # for windows, use the drive letter as the name
                        drive_name = mount_point.rstrip("\\")

                    if drive_name in self.whitelist:
                        whitelisted_mounts.add(mount_point)
                        self.logger.info(
                            f"drive is now whitelisted, stopping monitoring: {drive_name} at {mount_point}"
                        )

                # add whitelisted mounts to disconnected set
                disconnected.update(whitelisted_mounts)

                for mount_point in disconnected:
                    drive_name = os.path.basename(mount_point.rstrip(os.path.sep))

                    # windows drive paths end with \, handle this special case
                    if SYSTEM.OS_IS_WINDOWS and drive_name == "":
                        # for windows, use the drive letter as the name
                        drive_name = mount_point.rstrip("\\")

                    self.logger.info(
                        f"usb drive unplugged: {drive_name} at {mount_point}"
                    )

                    # stop watching this drive
                    if mount_point in self.observers:
                        try:
                            self.observers[mount_point].stop()
                            self.observers[mount_point].join()
                            del self.observers[mount_point]
                            self.known_mounts.remove(mount_point)
                            self.logger.info(f"stopped watching {drive_name}")
                        except Exception as e:
                            self.logger.error(
                                f"couldn't stop monitoring {drive_name}: {e}"
                            )

                # wait before checking again
                time.sleep(2)

            except Exception as e:
                self.logger.error(f"monitoring loop error: {e}")
                time.sleep(5)  # wait longer if there's an error

    def stop(self):
        """safely shutdown the monitoring process"""
        self.logger.info("shutting down usb monitoring")
        self.running = False
        self.cleanup()
        return True

    def cleanup(self):
        """stop all observers and close database"""
        self.logger.info("cleaning up")
        for mount_point, observer in self.observers.items():
            try:
                observer.stop()
                observer.join()
            except Exception as e:
                self.logger.error(f"couldn't stop observer for {mount_point}: {e}")

        # clear the observers and known mounts
        self.observers = {}
        self.known_mounts = set()

    def update_whitelist(self, whitelist):
        self.whitelist = set(whitelist) if whitelist else set()
        self.logger.info(
            f"updated whitelist: {', '.join(self.whitelist) if self.whitelist else 'none'}"
        )

    def add_to_whitelist(self, drive_name):
        self.whitelist.add(drive_name)
        self.logger.info(f"added {drive_name} to whitelist")

    def remove_from_whitelist(self, drive_name):
        if drive_name in self.whitelist:
            self.whitelist.remove(drive_name)
            self.logger.info(f"removed {drive_name} from whitelist")
        else:
            self.logger.warning(f"{drive_name} isn't in the whitelist")


class FileEventHandler(FileSystemEventHandler):
    # lru cache of processed file hashes, max size of 10000
    MAX_PROCESSED_HASHES = 10000
    processed_hashes = OrderedDict()
    # track when we last cleaned up
    last_cleanup_time = time.time()
    # clean up every hour
    CLEANUP_INTERVAL = 3600

    def __init__(self, logger, mount_point, drive_name):
        self.logger = logger
        self.mount_point = mount_point
        self.drive_name = drive_name
        self.temp_files = {}  # track files being copied
        self.processed_files = set()  # files we've already handled
        self.max_processed_files = 5000  # max files to track per usb drive
        self.processed_file_count = 0  # how many files we've processed

        # ignore files starting with these
        self.IGNORE_FILES = USB_IGNORE_FILES
        # ignore folders starting with these
        self.IGNORE_FOLDERS = USB_IGNORE_FOLDERS

    def on_created(self, event):
        """handle file creation events"""
        if event.is_directory:
            return

        # record the file's creation time and size
        try:
            file_path = event.src_path

            # check if we've already processed this file
            if file_path in self.processed_files:
                self.logger.debug(
                    f"already processed this file in on_created, skipping: {file_path}"
                )
                return

            self.logger.debug(f"trying to access new file: {file_path}")

            # wait a moment to make sure the file is completely written
            time.sleep(0.5)

            # check if file exists and is accessible
            if not os.path.exists(file_path):
                self.logger.debug(f"new file disappeared: {file_path}")
                return

            file_size = os.path.getsize(file_path)
            self.temp_files[file_path] = {
                "size": file_size,
                "created_time": time.time(),
            }
            self.logger.info(f"new file: {file_path}, size: {file_size}")

            # for small files (less than 1MB), process them immediately
            if file_size > 0 and file_size < 1024 * 1024:
                self.logger.debug(f"small file found, processing now: {file_path}")
                # wait a moment to ensure the file is fully written
                time.sleep(0.5)
                # check if size hasn't changed after waiting
                current_size = os.path.getsize(file_path)
                if current_size == file_size:
                    self._process_completed_file(file_path)
                    del self.temp_files[file_path]
        except (FileNotFoundError, OSError) as e:
            self.logger.error(f"can't access new file {event.src_path}: {e}")
            self.logger.error(
                f"permission check: {os.access(os.path.dirname(event.src_path), os.R_OK)}"
            )

    def on_modified(self, event):
        """handle file modification events (which occur during copy operations)"""
        if event.is_directory:
            return

        file_path = event.src_path
        self.logger.debug(f"file changed: {file_path}")

        # check if we've already processed this file
        if file_path in self.processed_files:
            self.logger.debug(
                f"already processed this file in on_modified, skipping: {file_path}"
            )
            return

        try:
            # check if file exists
            if not os.path.exists(file_path):
                self.logger.debug(f"modified file disappeared: {file_path}")
                if file_path in self.temp_files:
                    del self.temp_files[file_path]
                return

            # check if we've seen this file before
            if file_path in self.temp_files:
                self.logger.debug(f"already tracking this file: {file_path}")
                current_size = os.path.getsize(file_path)
                original_size = self.temp_files[file_path]["size"]
                created_time = self.temp_files[file_path]["created_time"]
                elapsed_time = time.time() - created_time

                self.logger.debug(
                    f"file {file_path}: current_size={current_size}, original_size={original_size}, elapsed_time={elapsed_time:.2f}s"
                )

                # if file size hasn't changed in a bit, it might be fully copied
                if current_size > original_size:
                    self.temp_files[file_path]["size"] = current_size
                    self.temp_files[file_path]["last_modified"] = time.time()
                    self.logger.debug(
                        f"file is growing: {file_path}, new size: {current_size}"
                    )

                    # check again after a short delay to see if file has stopped growing
                    time.sleep(0.2)
                    new_size = os.path.getsize(file_path)
                    if new_size == current_size:
                        self.logger.debug(f"file size stable, processing: {file_path}")
                        self._process_completed_file(file_path)
                        del self.temp_files[file_path]

                # if size hasn't changed for a while, consider the copy complete
                elif current_size == original_size and elapsed_time > 0.5:
                    self.logger.debug(
                        f"looks like copy is done: {file_path}, processing..."
                    )
                    self._process_completed_file(file_path)
                    del self.temp_files[file_path]
            else:
                # possibly started monitoring mid-copy
                self.logger.debug(f"found new file during modification: {file_path}")
                file_size = os.path.getsize(file_path)
                self.temp_files[file_path] = {
                    "size": file_size,
                    "created_time": time.time(),
                    "last_modified": time.time(),
                }

                # for small files that are modified once, consider them complete
                if file_size < 1024 * 1024:  # less than 1MB
                    time.sleep(0.2)
                    new_size = os.path.getsize(file_path)
                    if new_size == file_size:
                        self.logger.debug(
                            f"small file is stable, processing: {file_path}"
                        )
                        self._process_completed_file(file_path)
                        del self.temp_files[file_path]

        except (FileNotFoundError, OSError) as e:
            self.logger.error(f"can't access modified file {file_path}: {e}")

    def on_moved(self, event):
        """handle file move events (which can occur during copy operations)"""
        if event.is_directory:
            return

        src_path = event.src_path
        dest_path = event.dest_path

        # if source was in our tracking dict, update the key
        if src_path in self.temp_files:
            self.temp_files[dest_path] = self.temp_files[src_path]
            del self.temp_files[src_path]

        self.logger.debug(f"file moved from {src_path} to {dest_path}")

    def _process_completed_file(self, file_path):
        """handle a finished file copy and add it to the database"""
        try:
            self.logger.debug(f"processing file: {file_path}")

            # periodically check if we need to do a more thorough cleanup
            current_time = time.time()
            if (
                current_time - FileEventHandler.last_cleanup_time
                > FileEventHandler.CLEANUP_INTERVAL
            ):
                self._perform_periodic_cleanup()
                FileEventHandler.last_cleanup_time = current_time

            # check if we've already processed this file
            if file_path in self.processed_files:
                self.logger.debug(f"already processed this file, skipping: {file_path}")
                return

            # verify file exists and is accessible
            if not os.path.exists(file_path):
                self.logger.error(f"file disappeared while processing: {file_path}")
                return

            # get the filename and check if it should be ignored
            filename = os.path.basename(file_path)
            for ignore_prefix in self.IGNORE_FILES:
                if filename.startswith(ignore_prefix):
                    self.logger.debug(f"ignoring file with prefix: {filename}")
                    return

            # check if file is in an ignored folder
            path_parts = file_path.split(os.path.sep)
            for part in path_parts:
                for ignore_prefix in self.IGNORE_FOLDERS:
                    if part.startswith(ignore_prefix):
                        self.logger.debug(
                            f"ignoring file in ignored folder: {part} in {file_path}"
                        )
                        return

            file_stat = os.stat(file_path)
            file_size = file_stat.st_size

            # try to determine file type
            _, extension = os.path.splitext(filename)
            file_type = extension[1:] if extension else "unknown"

            self.logger.debug(f"file type: {file_type}, size: {file_size} bytes")

            # calculate file hash only for files smaller than 100MB to avoid performance issues
            file_hash = None
            if file_size < 100 * 1024 * 1024:  # 100MB
                self.logger.debug(f"calculating hash for: {filename}")
                file_hash = self._calculate_file_hash(file_path)
                self.logger.debug(
                    f"hash result: {file_hash if file_hash else 'failed'}"
                )

                # check if we've already processed a file with this hash
                if file_hash and file_hash in FileEventHandler.processed_hashes:
                    self.logger.info(f"found duplicate file, skipping: {filename}")
                    self.processed_files.add(file_path)
                    self.processed_file_count += 1

                    # update the lru status by moving this hash to the end (most recently used)
                    FileEventHandler.processed_hashes.pop(file_hash)
                    FileEventHandler.processed_hashes[file_hash] = None
                    return
            else:
                self.logger.info(
                    f"file too big to hash: {filename} ({file_size} bytes)"
                )

            self.logger.info(
                f"copied {filename} to {self.drive_name}, size: {file_size} bytes"
            )

            # record the transfer in the database
            try:
                self.logger.debug(
                    f"saving to database: {filename}, type: {file_type}, hash: {file_hash}"
                )

                # to work around issues with null hash values, we need different logic
                # when file_hash is None/NULL
                if file_hash is None:
                    # for null hash values, use a different method
                    try:
                        # first check if there's already a matching record
                        existing = (
                            UsbFileTransfer.select()
                            .where(
                                (UsbFileTransfer.filename == filename)
                                & (UsbFileTransfer.usb_drive == self.drive_name)
                                & (UsbFileTransfer.file_hash.is_null())
                            )
                            .first()
                        )

                        if existing:
                            transfer = existing
                            created = False
                        else:
                            # create a new record
                            transfer = UsbFileTransfer.create(
                                filename=filename,
                                destination_path=file_path,
                                file_size=file_size,
                                file_type=file_type,
                                usb_drive=self.drive_name,
                                file_hash=None,  # explicitly set to None
                            )
                            created = True
                    except Exception as e:
                        self.logger.error(f"error creating UsbFileTransfer record: {e}")
                        raise
                else:
                    # use get_or_create for non-null hash values
                    transfer, created = UsbFileTransfer.get_or_create(
                        file_hash=file_hash,
                        filename=filename,
                        usb_drive=self.drive_name,
                        defaults={
                            "destination_path": file_path,
                            "file_size": file_size,
                            "file_type": file_type,
                        },
                    )

                if created:
                    self.logger.info(f"saved transfer to database, id: {transfer.id}")
                else:
                    self.logger.info(f"file already in database, id: {transfer.id}")

                self.processed_files.add(file_path)
                self.processed_file_count += 1

                # if we've exceeded the maximum size for processed_files, trim it
                if self.processed_file_count > self.max_processed_files:
                    # remove about 20% of the oldest entries
                    entries_to_remove = int(self.max_processed_files * 0.2)
                    self.processed_files = set(
                        list(self.processed_files)[entries_to_remove:]
                    )
                    self.processed_file_count = len(self.processed_files)
                    self.logger.debug(
                        f"trimmed processed files for {self.drive_name} to {self.processed_file_count}"
                    )

                if file_hash:
                    # add to the lru cache of processed hashes
                    if file_hash in FileEventHandler.processed_hashes:
                        # move to end (most recently used)
                        FileEventHandler.processed_hashes.pop(file_hash)

                    FileEventHandler.processed_hashes[file_hash] = (
                        None  # value doesn't matter, we only care about keys
                    )

                    # if we've exceeded the maximum size, remove the oldest entries (first ones in the OrderedDict)
                    if (
                        len(FileEventHandler.processed_hashes)
                        > FileEventHandler.MAX_PROCESSED_HASHES
                    ):
                        # remove the oldest 20% entries
                        entries_to_remove = int(
                            FileEventHandler.MAX_PROCESSED_HASHES * 0.2
                        )
                        for _ in range(entries_to_remove):
                            if FileEventHandler.processed_hashes:
                                FileEventHandler.processed_hashes.popitem(
                                    last=False
                                )  # remove oldest item (FIFO)

                        self.logger.info(
                            f"trimmed hash cache to {len(FileEventHandler.processed_hashes)} entries"
                        )
            except Exception as e:
                self.logger.error(f"database error for {file_path}: {e}")
                self.logger.exception("database error:")
        except (OSError, IOError) as e:
            self.logger.error(f"error processing file {file_path}: {e}")
        except Exception as e:
            self.logger.error(f"unexpected error with {file_path}: {e}")
            self.logger.exception("error processing file:")

    def _calculate_file_hash(self, file_path):
        """get the sha-256 hash of the file"""
        try:
            self.logger.debug(f"starting hash calculation for: {file_path}")

            hash_obj = hashlib.sha256()

            # log file details before hashing
            file_size = os.path.getsize(file_path)
            self.logger.debug(f"file size before hashing: {file_size} bytes")

            with open(file_path, "rb") as f:
                # read in chunks to handle large files
                chunks_read = 0
                bytes_read = 0
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
                    chunks_read += 1
                    bytes_read += len(chunk)

                # log progress for debugging
                if chunks_read % 1000 == 0:
                    self.logger.debug(f"hash progress: {bytes_read / file_size:.2%}")

            self.logger.debug(f"hash done: {chunks_read} chunks, {bytes_read} bytes")

            result = hash_obj.hexdigest()
            return result

        except (OSError, IOError) as e:
            self.logger.error(f"couldn't calculate hash for {file_path}: {e}")
            self.logger.exception("error calculating hash:")
            return None

    def _perform_periodic_cleanup(self):
        """clean up memory usage every now and then"""
        try:
            # log current memory usage stats
            hash_count = len(FileEventHandler.processed_hashes)
            files_count = self.processed_file_count

            self.logger.info(
                f"cleaning up memory - hashes: {hash_count}, files: {files_count}"
            )

            # a slightly more aggressive cleanup of the lru cache if it's large
            if hash_count > FileEventHandler.MAX_PROCESSED_HASHES / 2:
                # keep only the most recent 25%
                entries_to_keep = int(FileEventHandler.MAX_PROCESSED_HASHES * 0.25)
                if hash_count > entries_to_keep:
                    # create a new lru cache with only the most recent entries
                    recent_entries = list(FileEventHandler.processed_hashes.keys())[
                        -entries_to_keep:
                    ]
                    FileEventHandler.processed_hashes = OrderedDict.fromkeys(
                        recent_entries
                    )
                    self.logger.info(
                        f"cleaned up hash cache - reduced from {hash_count} to {len(FileEventHandler.processed_hashes)}"
                    )

            # a slightly more aggressive cleanup of instance processed_files if it's large
            if files_count > self.max_processed_files / 2:
                # keeps only the most recent 25%
                entries_to_keep = int(self.max_processed_files * 0.25)
                if files_count > entries_to_keep:
                    recent_files = list(self.processed_files)[-entries_to_keep:]
                    self.processed_files = set(recent_files)
                    self.processed_file_count = len(self.processed_files)
                    self.logger.info(
                        f"cleaned up files for {self.drive_name} - reduced from {files_count} to {self.processed_file_count}"
                    )

            # force garbage collection
            import gc

            gc.collect()

        except Exception as e:
            self.logger.error(f"error during cleanup: {e}")
            self.logger.exception("error during cleanup:")
