import asyncio
import datetime
import hashlib
import logging
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver

from config import (
    SCANNER_DETECTORS_PATH,
    SCANNER_HOME_ROOT_PATH,
    SCANNER_IGNORE_DIRECTORIES,
    SCANNER_IGNORE_EXTENSIONS,
    SCANNER_IGNORE_FILENAMES,
    SCANNER_MAX_FILE_SIZE_MB,
    SCANNER_PROCESSORS_PATH,
    SCANNER_SKIP_PLUGIN_REQUIREMENTS,
    SYSTEM,
)
from detectors.au_passport_detector import au_passport_detector
from detectors.confidential_detector import confidential_detector
from detectors.dob_detector import dob_detector
from detectors.email_detector import email_detector
from detectors.financial_account_detector import financial_account_detector
from detectors.iban_detector import iban_detector
from detectors.ip_detector import ip_detector
from detectors.pci_detector import pci_detector
from detectors.phone_number_detector import phone_number_detector
from detectors.us_drivers_license_detector import us_drivers_license_detector
from detectors.us_passport_detector import us_passport_detector
from detectors.us_ssn_detector import us_ssn_detector
from detectors.us_taxpayer_id_detector import us_taxpayer_id_detector
from processors.archive_processor import archive_processor
from processors.email_processor import email_processor
from processors.excel_processor import excel_processor
from processors.gds_processor import gds_processor
from processors.image_processor import image_processor
from processors.iwork_processor import iwork_processor
from processors.pdf_processor import pdf_processor
from processors.powerpoint_processor import powerpoint_processor
from processors.text_processor import text_processor
from processors.word_processor import word_processor
from storage.database import ScannerFile, ScannerFinding, ScannerHistory
from storage.httpapi import StracApi


class Scanner:
    def __init__(self):
        self.name = "manager-scanner"
        self.logger = logging.getLogger(self.name)
        self.processor_registry = {}
        self.detector_registry = []
        self.loop = asyncio.get_event_loop()
        self.executor = ThreadPoolExecutor()
        self.process_executor = ProcessPoolExecutor()
        self.current_scanner_history = None
        self.observers = []  # track running watchdog observers
        self.is_running = False

    def _install_plugin_requirements(self, processor_path):
        if SCANNER_SKIP_PLUGIN_REQUIREMENTS:
            self.logger.debug(
                f"skipping installation of requirements for processor at {processor_path}"
            )
            return
        requirements_file = os.path.join(processor_path, "requirements.txt")
        if os.path.exists(requirements_file):
            self.logger.debug(
                f"installing requirements for processor at {processor_path}"
            )
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-r", requirements_file]
            )

    def _register_processor(self, processor_class):
        self.logger.warning(f"registering processor: {processor_class.__name__}")
        try:
            for ext in processor_class.supported_extensions:
                ext = ext.lower()
                self.processor_registry[ext] = processor_class
                self.logger.debug(
                    f"registered processor extension: {ext} for {processor_class.__name__}"
                )
        except Exception as e:
            self.logger.error(f"failed to register processor: {e}")

    def _register_detector(self, detector_class):
        self.logger.warning(f"registering detector: {detector_class.__name__}")
        try:
            self.detector_registry.append(detector_class())
            self.logger.debug(f"registered detector: {detector_class.__name__}")
        except Exception as e:
            self.logger.error(f"failed to register detector: {e}")

    def _load_processors(self):
        processors_dir = os.path.abspath(SCANNER_PROCESSORS_PATH)
        self.logger.debug(f"processors_dir: {processors_dir}")

        try:
            archive_class = archive_processor.Processor
            self._register_processor(archive_class)
            self.logger.debug("loaded processor: processors.archive_processor")
            email_class = email_processor.Processor
            self._register_processor(email_class)
            self.logger.debug("loaded processor: processors.email_processor")
            excel_class = excel_processor.Processor
            self._register_processor(excel_class)
            self.logger.debug("loaded processor: processors.excel_processor")
            gds_class = gds_processor.Processor
            self._register_processor(gds_class)
            self.logger.debug("loaded processor: processors.gds_processor")
            image_class = image_processor.Processor
            self._register_processor(image_class)
            self.logger.debug("loaded processor: processors.image_processor")
            iwork_class = iwork_processor.Processor
            self._register_processor(iwork_class)
            self.logger.debug("loaded processor: processors.iwork_processor")
            pdf_class = pdf_processor.Processor
            self._register_processor(pdf_class)
            self.logger.debug("loaded processor: processors.pdf_processor")
            powerpoint_class = powerpoint_processor.Processor
            self._register_processor(powerpoint_class)
            self.logger.debug("loaded processor: processors.powerpoint_processor")
            text_class = text_processor.Processor
            self._register_processor(text_class)
            self.logger.debug("loaded processor: processors.text_processor")
            word_class = word_processor.Processor
            self._register_processor(word_class)
            self.logger.debug("loaded processor: processors.word_processor")
        except Exception as e:
            self.logger.error(f"failed to load processor: {e}")

        # sys.path.insert(0, processors_dir)
        # self.logger.debug(f"sys.path: {sys.path}")
        # SCANNER_ENABLED_PROCESSORS_lower = [
        #     p.lower() for p in SCANNER_ENABLED_PROCESSORS
        # ]
        # for item in os.listdir(processors_dir):
        #     if item.lower() not in SCANNER_ENABLED_PROCESSORS_lower:
        #         self.logger.debug(f"skipping processor not in enabled list: {item}")
        #         continue
        #     processor_path = os.path.join(processors_dir, item)
        #     self.logger.debug(f"processor_path: {processor_path}")
        #     if os.path.isdir(processor_path) and "__init__.py" in os.listdir(
        #         processor_path
        #     ):
        #         try:
        #             self._install_plugin_requirements(processor_path)
        #             module_name = f"{item}.{item}"
        #             self.logger.debug(f"module_name: {module_name}")
        #             module = importlib.import_module(module_name)
        #             self.logger.debug(f"module: {module}")
        #             if hasattr(module, "Processor"):
        #                 processor_class = module.Processor
        #                 self._register_processor(processor_class)
        #                 self.logger.debug(f"loaded processor: {module_name}")
        #             else:
        #                 self.logger.warning(
        #                     f"no Processor class found in {module_name}"
        #                 )
        #         except Exception as e:
        #             self.logger.error(f"failed to load processor {item}: {e}")

    def _load_detectors(self):
        detector_dir = os.path.abspath(SCANNER_DETECTORS_PATH)
        self.logger.debug(f"detector_dir: {detector_dir}")

        try:
            au_passport_class = au_passport_detector.Detector
            self._register_detector(au_passport_class)
            self.logger.debug("loaded detector: detectors.au_passport_detector")
            confidential_class = confidential_detector.Detector
            self._register_detector(confidential_class)
            self.logger.debug("loaded detector: detectors.confidential_detector")
            dob_class = dob_detector.Detector
            self._register_detector(dob_class)
            self.logger.debug("loaded detector: detectors.dob_detector")
            email_class = email_detector.Detector
            self._register_detector(email_class)
            self.logger.debug("loaded detector: detectors.email_detector")
            financial_account_class = financial_account_detector.Detector
            self._register_detector(financial_account_class)
            self.logger.debug("loaded detector: detectors.financial_account_detector")
            iban_class = iban_detector.Detector
            self._register_detector(iban_class)
            self.logger.debug("loaded detector: detectors.iban_detector")
            ip_class = ip_detector.Detector
            self._register_detector(ip_class)
            self.logger.debug("loaded detector: detectors.ip_detector")
            pci_class = pci_detector.Detector
            self._register_detector(pci_class)
            self.logger.debug("loaded detector: detectors.pci_detector")
            phone_number_class = phone_number_detector.Detector
            self._register_detector(phone_number_class)
            self.logger.debug("loaded detector: detectors.phone_number_detector")
            us_drivers_license_class = us_drivers_license_detector.Detector
            self._register_detector(us_drivers_license_class)
            self.logger.debug("loaded detector: detectors.us_drivers_license_detector")
            us_passport_class = us_passport_detector.Detector
            self._register_detector(us_passport_class)
            self.logger.debug("loaded detector: detectors.us_passport_detector")
            us_ssn_class = us_ssn_detector.Detector
            self._register_detector(us_ssn_class)
            self.logger.debug("loaded detector: detectors.us_ssn_detector")
            us_taxpayer_id_class = us_taxpayer_id_detector.Detector
            self._register_detector(us_taxpayer_id_class)
            self.logger.debug("loaded detector: detectors.us_taxpayer_id_detector")
        except Exception as e:
            self.logger.error(f"failed to load detector: {e}")

        # sys.path.insert(0, detector_dir)
        # self.logger.debug(f"sys.path: {sys.path}")
        # SCANNER_ENABLED_DETECTORS_lower = [d.lower() for d in SCANNER_ENABLED_DETECTORS]
        # for item in os.listdir(detector_dir):
        #     if item.lower() not in SCANNER_ENABLED_DETECTORS_lower:
        #         self.logger.debug(f"skipping detector not in enabled list: {item}")
        #         continue
        #     detector_path = os.path.join(detector_dir, item)
        #     self.logger.debug(f"detector_path: {detector_path}")
        #     if os.path.isdir(detector_path) and "__init__.py" in os.listdir(
        #         detector_path
        #     ):
        #         try:
        #             self._install_plugin_requirements(detector_path)
        #             module_name = f"{item}.{item}"
        #             self.logger.debug(f"module_name: {module_name}")
        #             module = importlib.import_module(module_name)
        #             self.logger.debug(f"module: {module}")
        #             if hasattr(module, "Detector"):
        #                 detector_class = module.Detector
        #                 self._register_detector(detector_class)
        #                 self.logger.debug(f"loaded detector plugin: {module_name}")
        #             else:
        #                 self.logger.warning(f"no Plugin class found in {module_name}")
        #         except Exception as e:
        #             self.logger.error(f"failed to load detector plugin {item}: {e}")

    def _get_processor(self, file_extension):
        return self.processor_registry.get(file_extension.lower())

    def _run_in_executor(self, func, *args):
        return self.loop.run_in_executor(self.executor, func, *args)

    def _run_in_process(self, func, *args):
        return self.loop.run_in_executor(self.process_executor, func, *args)

    async def _record_results(self, scanner_file, findings):
        try:
            for finding in findings:
                ScannerFinding.create(
                    scanner_file=scanner_file,
                    finding_type=finding["type"],
                    content=finding["content"],
                    context=finding["context"],
                )
                try:
                    if SYSTEM.is_file(scanner_file.file_path):
                        client = StracApi()
                        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")
                        self.logger.debug(
                            f"scanner.record_results: {scanner_file.file_path}"
                        )
                        await client.process_document(
                            (timestamp, scanner_file.file_path, "Finder", None)
                        )
                except Exception as e:
                    self.logger.error(
                        f"failed to record at strac results for: {scanner_file}: {e}"
                    )
        except Exception as e:
            self.logger.error(f"failed to record results for: {scanner_file}: {e}")

    async def _process_file(self, file_path, scanner_history):
        file_extension = file_path.suffix.lower()
        processor_class = self._get_processor(file_extension)
        if processor_class:
            try:
                file_size_mb = file_path.stat().st_size / (1024 * 1024)
                if file_size_mb > SCANNER_MAX_FILE_SIZE_MB:
                    self.logger.warning(
                        f"skipping {file_path} (size {file_size_mb:.2f} MB exceeds limit)"
                    )
                    scanner_history.files_skipped += 1
                    scanner_history.save()
                    return

                # fix the executor call issue
                try:
                    file_signature = self.compute_file_signature(file_path)
                    if not file_signature:
                        scanner_history.files_skipped += 1
                        scanner_history.save()
                        return
                except Exception as e:
                    self.logger.error(f"Error computing file signature: {e}")
                    scanner_history.files_skipped += 1
                    scanner_history.save()
                    return

                # checks if the file has already been scanned
                existing_file = ScannerFile.get_or_none(file_signature=file_signature)
                if existing_file:
                    self.logger.debug(f"skipping already scanned file: {file_path}")
                    scanner_history.files_skipped += 1
                    scanner_history.save()
                    return

                absolute_file_path = str(file_path.resolve())
                scanner_file = ScannerFile.create(
                    scanner_history=scanner_history,
                    file_path=absolute_file_path,
                    file_name=file_path.name,
                    file_extension=file_extension,
                    file_signature=file_signature,
                )

                scanner_history.files_scanned += 1
                scanner_history.save()

                processor_instance = processor_class()
                text_content = await processor_instance.process_file_async(
                    file_path, self
                )
                if text_content:
                    for detector in self.detector_registry:
                        findings = await detector.process_text(text_content)
                        if findings:
                            await self._record_results(scanner_file, findings)
            except Exception as e:
                self.logger.error(f"error processing file {file_path}: {e}")
                scanner_history.files_skipped += 1
                scanner_history.save()
        else:
            self.logger.warning(
                f"no processor found for file extension: {file_extension}"
            )
            scanner_history.files_skipped += 1
            scanner_history.save()

    async def compute_file_signature_async(self, file_path):
        # async wrapper for compute_file_signature
        return await self.loop.run_in_executor(
            self.executor, self.compute_file_signature, file_path
        )

    def _get_user_home_directories(self, ignore_directories):
        users_dir = Path(SCANNER_HOME_ROOT_PATH)
        user_dirs = []
        for user_dir in users_dir.iterdir():
            if user_dir.is_dir() and not any(
                user_dir.name.lower().startswith(ign.lower())
                for ign in ignore_directories
            ):
                user_dirs.append(user_dir)
            else:
                self.logger.debug(f"skipping user directory: {user_dir}")
        return user_dirs

    async def start(self, ignore_directories=None):
        """
        Scans the current user's home directory and then monitors it for changes.

        Args:
            ignore_directories: List of directory names to ignore. Defaults to SCANNER_IGNORE_DIRECTORIES.
        """
        if self.is_running:
            self.logger.warning("Scanner monitor is already running")
            return

        self.is_running = True

        self._load_processors()
        self._load_detectors()

        if ignore_directories is None:
            ignore_directories = SCANNER_IGNORE_DIRECTORIES

        # get the current user's home directory
        user_home_dir = f"{SCANNER_HOME_ROOT_PATH}/{SYSTEM.current_user}"
        self.logger.debug(f"user_home_dir: {str(user_home_dir)}")
        user_home_path = Path(user_home_dir)

        if not user_home_path.exists() or not user_home_path.is_dir():
            self.logger.error(
                f"Current user home directory not found: {str(user_home_path)}"
            )
            return

        # first scan the entire home directory
        self.logger.info(f"Scanning current user home directory: {str(user_home_path)}")
        await self.scan_folder(user_home_dir, ignore_directories)

        # set up watchdog monitoring with appropriate observer
        self.logger.info(f"starting file monitoring for: {str(user_home_path)}")
        event_handler = ScannerEventHandler(
            self,
            user_home_dir,
            SCANNER_IGNORE_DIRECTORIES,
            SCANNER_IGNORE_FILENAMES,
            SCANNER_IGNORE_EXTENSIONS,
        )

        # use PollingObserver instead of default Observer on Mac to avoid fsevents issues
        observer = PollingObserver()
        observer.schedule(event_handler, user_home_dir, recursive=True)
        observer.daemon = True
        observer.start()
        self.logger.info(f"started observer for: {str(user_home_path)}")
        self.observers.append(observer)  # track this observer

        # keep the monitoring running
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            self.logger.info("stopping file monitoring")
            observer.stop()
            observer.join()
            self.observers.remove(observer)  # remove from tracking
            raise

    async def stop(self):
        # cleanup any running observers
        if not self.is_running:
            self.logger.warning("Scanner monitor is not running")
            return

        for observer in self.observers:
            try:
                self.logger.info("stopping file monitoring observer")
                observer.stop()
                observer.join()
            except Exception as e:
                self.logger.error(f"error stopping observer: {e}")
        self.observers.clear()

        # cleanup executors
        self.executor.shutdown(wait=False)
        self.process_executor.shutdown(wait=False)
        await asyncio.sleep(0.1)

    async def scan_folder(self, folder_path, ignore_directories=None):
        if ignore_directories is None:
            ignore_directories = SCANNER_IGNORE_DIRECTORIES
        folder_path = Path(folder_path)
        if not folder_path.is_dir():
            self.logger.error(f"{folder_path} is not a directory")
            return
        absolute_folder_path = str(folder_path.resolve())
        scanner_history = ScannerHistory.create(
            path=absolute_folder_path, start_time=datetime.datetime.now()
        )
        self.current_scanner_history = scanner_history
        tasks = []
        for root, dirs, files in os.walk(folder_path):
            dirs_to_scan = []
            for d in dirs:
                if any(d.lower().startswith(ign.lower()) for ign in ignore_directories):
                    scanner_history.directories_skipped += 1
                    self.logger.debug(f"skipping directory: {os.path.join(root, d)}")
                else:
                    dirs_to_scan.append(d)
                    scanner_history.directories_scanned += 1
            dirs[:] = dirs_to_scan
            for file_name in files:
                if any(
                    file_name.lower() == ign.lower() for ign in SCANNER_IGNORE_FILENAMES
                ):
                    scanner_history.files_skipped += 1
                    self.logger.debug(
                        f"skipping file by name: {os.path.join(root, file_name)}"
                    )
                    continue
                file_path = Path(root) / file_name
                if file_path.suffix.lower() in [
                    ext.lower() for ext in SCANNER_IGNORE_EXTENSIONS
                ]:
                    scanner_history.files_skipped += 1
                    self.logger.debug(f"skipping file by extension: {file_path}")
                    continue
                tasks.append(self._process_file(file_path, scanner_history))
        await asyncio.gather(*tasks)
        scanner_history.end_time = datetime.datetime.now()
        scanner_history.save()

    async def scan_home_folders(self, ignore_directories=None):
        if ignore_directories is None:
            ignore_directories = SCANNER_IGNORE_DIRECTORIES
        user_dirs = self._get_user_home_directories(ignore_directories)
        tasks = [
            self.scan_folder(user_dir, ignore_directories) for user_dir in user_dirs
        ]
        await asyncio.gather(*tasks)

    async def scan_file(self, file_path):
        file_path = Path(file_path)
        if not file_path.is_file():
            self.logger.error(f"{file_path} is not a file")
            return
        absolute_file_path = str(file_path.resolve())
        scanner_history = ScannerHistory.create(
            path=absolute_file_path, start_time=datetime.datetime.now()
        )
        self.current_scanner_history = scanner_history
        await self._process_file(file_path, scanner_history)
        scanner_history.end_time = datetime.datetime.now()
        scanner_history.save()

    def is_available(self, name, type_):
        name_lower = name.lower()
        if type_ == "processor":
            return name_lower in [
                p.lower() for p in os.listdir(SCANNER_PROCESSORS_PATH)
            ]
        elif type_ == "detector":
            return name_lower in [d.lower() for d in os.listdir(SCANNER_DETECTORS_PATH)]
        else:
            self.logger.error(f"invalid type specified: {type_}")
            return False

    def compute_file_signature(self, file_path):
        try:
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to compute signature for {file_path}: {e}")
            return None


class ScannerEventHandler(FileSystemEventHandler):
    def __init__(
        self, scanner, base_path, ignore_dirs, ignore_files, ignore_extensions
    ):
        # store scanner instance and filtering rules
        self.scanner = scanner
        self.base_path = base_path
        self.ignore_dirs = ignore_dirs
        self.ignore_files = ignore_files
        self.ignore_extensions = ignore_extensions
        self.logger = logging.getLogger("scanner-event-handler")

    def _should_process_file(self, file_path):
        # check if we should process this file based on our rules
        try:
            path = Path(file_path)

            # check filename ignores
            if any(path.name.startswith(ignore) for ignore in self.ignore_files):
                self.logger.debug(f"ignoring file by name: {path.name}")
                return False

            # check extension ignores
            if path.suffix.lower() in self.ignore_extensions:
                self.logger.debug(f"ignoring file by extension: {path.suffix}")
                return False

            # check directory ignores
            path_parts = path.parts
            for part in path_parts:
                if any(part.startswith(ignore) for ignore in self.ignore_dirs):
                    self.logger.debug(f"ignoring file in ignored directory: {part}")
                    return False

            return True
        except Exception as e:
            self.logger.error(f"error checking file rules: {e}")
            return False

    def on_created(self, event):
        # handle new file creation
        if event.is_directory:
            return

        file_path = event.src_path
        if self._should_process_file(file_path):
            self.logger.debug(f"new file detected: {file_path}")
            asyncio.create_task(self.scanner.scan_file(file_path))

    def on_modified(self, event):
        # handle file modifications
        if event.is_directory:
            return

        file_path = event.src_path
        if self._should_process_file(file_path):
            self.logger.debug(f"modified file detected: {file_path}")
            asyncio.create_task(self.scanner.scan_file(file_path))
