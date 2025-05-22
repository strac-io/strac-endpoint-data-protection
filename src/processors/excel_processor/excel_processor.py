"""Excel document processor module for extracting text content from Excel files.

This module provides functionality to process Excel (.xls, .xlsx) files and extract
their text content. It supports asynchronous processing and handles both data and
formula cells by using the openpyxl library.

Example:
    Basic usage of the Excel Processor:

    ```python
    processor = Processor()

    # Synchronous processing
    text_content = processor.process_file("path/to/file.xlsx")

    # Asynchronous processing (requires a scanner object)
    text_content = await processor.process_file_async("path/to/file.xlsx", scanner)
    ```
"""

import logging

import openpyxl


class Processor:
    """Excel file processor for text content extraction.

    This class handles the processing of Excel files (.xls, .xlsx) and extracts
    their text content. It provides both synchronous and asynchronous processing
    methods and includes built-in logging.

    Attributes:
        name (str): The display name of the processor.
        version (str): The version number of the processor.
        supported_extensions (list): List of supported file extensions.
    """

    name = "Excel Processor"
    version = "1.2"
    supported_extensions = [".xls", ".xlsx"]

    def __init__(self):
        """Initialize the Excel processor with a configured logger."""
        self.logger = logging.getLogger("processor-excel")

    def __repr__(self):
        """Return a developer-friendly string representation of the processor.

        Returns:
            str: A string containing the class name, processor name, and version.
        """
        return f"<{self.__class__.__name__} {self.name} v{self.version}>"

    def __str__(self):
        """Return a user-friendly string representation of the processor.

        Returns:
            str: A string containing the processor name and version.
        """
        return f"{self.name} v{self.version}"

    async def process_file_async(self, file_path, scanner):
        """Process an Excel file asynchronously.

        This method runs the Excel processing in a separate executor to avoid
        blocking the event loop.

        Args:
            file_path (str): Path to the Excel file to process.
            scanner (Scanner): Scanner object providing the event loop and executor.

        Returns:
            str: Extracted text content from the Excel file, or empty string on error.

        Example:
            ```python
            processor = Processor()
            scanner = Scanner()  # Your scanner implementation
            content = await processor.process_file_async("document.xlsx", scanner)
            print(content)
            ```
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
        """Process an Excel file synchronously.

        Opens the Excel file and extracts text content from all sheets,
        concatenating cell values into a single string with newlines between rows.

        Args:
            file_path (str): Path to the Excel file to process.

        Returns:
            str: Extracted text content from the Excel file, or empty string on error.

        Example:
            ```python
            processor = Processor()
            content = processor.process_file("document.xlsx")
            print(content)
            ```
        """
        text_content = ""
        try:
            self.logger.debug(f"loading workbook: {file_path}")
            wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
            for sheet in wb.worksheets:
                self.logger.debug(f"processing sheet: {sheet.title}")
                for row in sheet.iter_rows(values_only=True):
                    row_values = [str(cell) if cell is not None else "" for cell in row]
                    text_content += " ".join(row_values) + "\n"
            return text_content
        except Exception as e:
            self.logger.error(f"error processing: {file_path}: {e}")
            return ""
