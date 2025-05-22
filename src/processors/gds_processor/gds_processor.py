"""GDS/GDSII/OASIS file processor for text extraction.

This module provides functionality to process GDS, GDSII, and OASIS layout files
and extract text content from their label elements using the gdstk library.

Example:
    >>> processor = Processor()
    >>> text_content = processor.process_file("path/to/layout.gds")
    >>> print(text_content)
    Label1
    Label2

    # Async usage with scanner
    >>> text_content = await processor.process_file_async("path/to/layout.gds", scanner)
"""

import logging

import gdstk


class Processor:
    """Processes GDS/GDSII/OASIS files to extract text from labels.

    This class handles the reading and processing of layout files to extract
    text content from label elements within each cell of the design.

    Attributes:
        name (str): Name identifier for the processor.
        version (str): Version number of the processor.
        supported_extensions (list): List of supported file extensions.
    """

    name = "GDS Processor"
    version = "1.3"
    supported_extensions = [".gds", ".gdsii", ".oas"]

    def __init__(self):
        """Initializes the GDS Processor with a configured logger."""
        self.logger = logging.getLogger("processor-gds")

    def __repr__(self):
        """Returns a string representation of the Processor object.

        Returns:
            str: A string in the format "<ClassName ProcessorName vVersion>"
        """
        return f"<{self.__class__.__name__} {self.name} v{self.version}>"

    def __str__(self):
        """Returns a human-readable string representation of the Processor.

        Returns:
            str: A string in the format "ProcessorName vVersion"
        """
        return f"{self.name} v{self.version}"

    async def process_file_async(self, file_path, scanner):
        """Asynchronously processes a layout file to extract text content.

        Args:
            file_path (str or Path): Path to the layout file to process.
            scanner: Scanner object providing executor and event loop.

        Returns:
            str: Extracted text content from the file's labels, or empty string on error.

        Example:
            >>> async with Scanner() as scanner:
            ...     processor = Processor()
            ...     text = await processor.process_file_async("test.gds", scanner)
        """
        loop = scanner.loop
        try:
            text_content = await loop.run_in_executor(
                scanner.executor, self.process_file, file_path
            )
            return text_content
        except Exception as e:
            self.logger.error(f"error processing: {file_path}: {e}")
            return ""

    def process_file(self, file_path):
        """Processes a layout file to extract text content.

        Reads a GDS, GDSII, or OASIS file and extracts text from all labels
        found in all cells of the design.

        Args:
            file_path (str or Path): Path to the layout file to process.

        Returns:
            str: Extracted text content from the file's labels, with each label
                on a new line. Returns empty string on error.

        Example:
            >>> processor = Processor()
            >>> text = processor.process_file("path/to/design.gds")
            >>> print(text)
            Label1
            Label2
        """
        text_content = ""
        try:
            self.logger.debug(f"reading: {file_path}")
            file_path = str(file_path)
            if file_path.lower().endswith(".oas"):
                lib = gdstk.read_oas(file_path)
            else:
                lib = gdstk.read_gds(file_path)
            for cell in lib.cells:
                self.logger.debug(f"processing cell: {cell.name}")
                for label in cell.labels:
                    text_content += label.text + "\n"
                    self.logger.debug(f"extracted label text: {label.text}")
            return text_content
        except Exception as e:
            self.logger.error(f"error processing: {file_path}: {e}")
            return ""
