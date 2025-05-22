"""Archive file processor module for extracting and scanning archived content.

This module provides functionality to process various archive formats including
ZIP, RAR, TAR, TGZ, and 7Z files. It extracts the contents and processes each
file within the archive.

Example:
    >>> processor = Processor()
    >>> scanner = Scanner()  # Your scanner instance
    >>> await processor.process_file_async(Path('example.zip'), scanner)
"""

import logging
import os
import shutil
import tempfile
from pathlib import Path


class Processor:
    """Archive file processor for extracting and scanning archived content.

    This class handles the extraction and processing of various archive formats.
    It works in conjunction with a scanner to process the extracted contents.

    Attributes:
        name (str): Display name of the processor.
        version (str): Version string of the processor.
        supported_extensions (list): List of supported archive file extensions.

    Example:
        >>> processor = Processor()
        >>> # Process a ZIP file
        >>> processor.process_file(Path('documents.zip'), scanner)
        >>>
        >>> # Process a RAR file asynchronously
        >>> await processor.process_file_async(Path('files.rar'), scanner)
    """

    name = "Archive Processor"
    version = "1.1"
    supported_extensions = [".zip", ".rar", ".tar", ".tgz", ".7z"]

    def __init__(self):
        """Initialize the Archive Processor with a dedicated logger."""
        self.logger = logging.getLogger("processor-archive")

    def __repr__(self):
        """Return a string representation of the processor for debugging.

        Returns:
            str: A string in the format "<ClassName ProcessorName vVersion>"
        """
        return f"<{self.__class__.__name__} {self.name} v{self.version}>"

    def __str__(self):
        """Return a human-readable string representation of the processor.

        Returns:
            str: A string in the format "ProcessorName vVersion"
        """
        return f"{self.name} v{self.version}"

    async def process_file_async(self, file_path, scanner):
        """Process an archive file asynchronously.

        Args:
            file_path (Path): Path to the archive file to process.
            scanner (Scanner): Scanner instance to use for processing extracted files.

        Example:
            >>> async with Scanner() as scanner:
            ...     await processor.process_file_async(Path('archive.zip'), scanner)
        """
        loop = scanner.loop
        await loop.run_in_executor(
            scanner.executor, self.process_file, file_path, scanner
        )

    def process_file(self, file_path, scanner):
        """Process an archive file by extracting and scanning its contents.

        Extracts the contents of the archive to a temporary directory and processes
        each extracted file using the provided scanner.

        Args:
            file_path (Path): Path to the archive file to process.
            scanner (Scanner): Scanner instance to use for processing extracted files.

        Note:
            Supports ZIP, RAR, TAR, TGZ, and 7Z formats. Different extraction methods
            are used based on the file extension. RAR files require the patoolib package,
            and 7Z files require the py7zr package.

        Example:
            >>> with Scanner() as scanner:
            ...     processor.process_file(Path('archive.zip'), scanner)
        """
        temp_dir = tempfile.mkdtemp()
        try:
            if file_path.suffix.lower() == ".7z":
                import py7zr

                with py7zr.SevenZipFile(file_path, mode="r") as z:
                    z.extractall(path=temp_dir)
            elif file_path.suffix.lower() == ".rar":
                import patoolib

                patoolib.extract_archive(str(file_path), outdir=temp_dir)
            else:
                shutil.unpack_archive(file_path, temp_dir)
            for root, dirs, files in os.walk(temp_dir):
                for file_name in files:
                    extracted_file_path = Path(root) / file_name
                    scanner.loop.create_task(
                        scanner.process_file(
                            extracted_file_path, scanner.current_scan_history
                        )
                    )
        except Exception as e:
            pass
        finally:
            shutil.rmtree(temp_dir)
