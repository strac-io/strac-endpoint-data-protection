"""Text processing module for various file formats.

This module provides a Processor class that handles text extraction from different
file formats including CSV, JSON, YAML, HTML, RTF, XML, and plain text files.

Example:
    >>> processor = Processor()
    >>> text = processor.process_file(Path("document.txt"))
    >>> print(text)
    'Content of the text file...'

    # Async processing with a scanner
    >>> text = await processor.process_file_async(
    ...     Path("document.json"), scanner)
    >>> print(text)
    '{"key": "value"}'
"""

import csv
import json
import logging

import yaml
from lxml import etree
from striprtf.striprtf import rtf_to_text


class Processor:
    """A processor for extracting text from various file formats.

    This class provides methods to process and extract text content from multiple
    file formats including plain text, JSON, YAML, CSV, HTML, RTF, and XML files.
    It supports both synchronous and asynchronous processing.

    Attributes:
        name (str): The processor's display name.
        version (str): The processor's version number.
        supported_extensions (list[str]): File extensions this processor can handle.
        logger (logging.Logger): Logger instance for the processor.

    Example:
        >>> processor = Processor()
        >>> # Process a JSON file
        >>> content = processor.process_file(Path("config.json"))
        >>> print(content)
        '{
          "setting": "value",
          "enabled": true
        }'
    """

    name = "Text Processor"
    version = "1.5"
    supported_extensions = [
        ".csv",
        ".env",
        ".htm",
        ".html",
        ".json",
        ".rtf",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
        ".md",
    ]

    def __init__(self):
        """Initialize the Text Processor with a configured logger."""
        self.logger = logging.getLogger("processor-text")

    def __repr__(self):
        """
        Returns the official string representation of the processor.

        Returns:
            str: The official representation.
        """
        return f"<{self.__class__.__name__} {self.name} v{self.version}>"

    def __str__(self):
        """
        Returns the informal string representation of the processor.

        Returns:
            str: The informal representation.
        """
        return f"{self.name} v{self.version}"

    async def process_file_async(self, file_path, scanner):
        """Asynchronously process a text-based file using the scanner's executor.

        Args:
            file_path (Path): Path to the file to be processed.
            scanner (Scanner): Scanner instance providing the event loop and executor.

        Returns:
            str: The extracted text content from the file.

        Example:
            >>> async def process():
            ...     scanner = Scanner()
            ...     processor = Processor()
            ...     content = await processor.process_file_async(
            ...         Path("data.json"), scanner)
            ...     print(content)
        """
        loop = scanner.loop
        try:
            text_content = await loop.run_in_executor(
                scanner.executor, self.process_file, file_path
            )
            return text_content
        except Exception as e:
            self.logger.error(f"Error processing {file_path}: {e}")
            return ""

    def process_file(self, file_path):
        """Process a text-based file and extract its content.

        This method determines the appropriate processing method based on the file
        extension and delegates to the specific processor.

        Args:
            file_path (Path): Path to the file to be processed.

        Returns:
            str: The extracted text content from the file.

        Example:
            >>> processor = Processor()
            >>> # Process a YAML file
            >>> content = processor.process_file(Path("config.yaml"))
            >>> print(content)
            'key: value\nsetting: enabled\n'
        """
        extension = file_path.suffix.lower()
        if extension in [".txt", ".env"]:
            return self.process_text_file(file_path)
        elif extension == ".json":
            return self.process_json_file(file_path)
        elif extension in [".yaml", ".yml"]:
            return self.process_yaml_file(file_path)
        elif extension == ".csv":
            return self.process_csv_file(file_path)
        elif extension in [".htm", ".html"]:
            return self.process_html_file(file_path)
        elif extension == ".rtf":
            return self.process_rtf_file(file_path)
        elif extension == ".xml":
            return self.process_xml_file(file_path)
        else:
            self.logger.warning(f"Extension {extension} not supported.")
            return ""

    def process_text_file(self, file_path):
        """Process a plain text file and return its content.

        Args:
            file_path (Path): Path to the text file.

        Returns:
            str: The raw content of the text file.

        Example:
            >>> processor = Processor()
            >>> content = processor.process_text_file(Path("readme.txt"))
            >>> print(content)
            'This is the content of the text file...'
        """
        try:
            self.logger.debug(f"Reading text file: {file_path}")
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                self.logger.debug(f"Read {len(content)} characters from {file_path}")
                return content
        except Exception as e:
            self.logger.error(f"Error reading {file_path}: {e}")
            return ""

    def process_json_file(self, file_path):
        """Process a JSON file and return its formatted content.

        Args:
            file_path (Path): Path to the JSON file.

        Returns:
            str: The JSON content formatted with indentation.

        Example:
            >>> processor = Processor()
            >>> content = processor.process_json_file(Path("data.json"))
            >>> print(content)
            '{
              "name": "example",
              "values": [1, 2, 3]
            }'
        """
        try:
            self.logger.debug(f"Reading JSON file: {file_path}")
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                content = json.dumps(data, indent=2)
                self.logger.debug(f"Extracted JSON content from {file_path}")
                return content
        except Exception as e:
            self.logger.error(f"Error reading JSON file {file_path}: {e}")
            return ""

    def process_yaml_file(self, file_path):
        """Process a YAML file and return its formatted content.

        Args:
            file_path (Path): Path to the YAML file.

        Returns:
            str: The YAML content as a formatted string.

        Example:
            >>> processor = Processor()
            >>> content = processor.process_yaml_file(Path("config.yaml"))
            >>> print(content)
            'name: example\nconfig:\n  enabled: true\n'
        """
        try:
            self.logger.debug(f"Reading YAML file: {file_path}")
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = yaml.safe_load(f)
                content = yaml.dump(data)
                self.logger.debug(f"Extracted YAML content from {file_path}")
                return content
        except Exception as e:
            self.logger.error(f"Error reading YAML file {file_path}: {e}")
            return ""

    def process_csv_file(self, file_path):
        """Process a CSV file and return its content as a formatted string.

        Args:
            file_path (Path): Path to the CSV file.

        Returns:
            str: The CSV content with rows joined by commas and newlines.

        Example:
            >>> processor = Processor()
            >>> content = processor.process_csv_file(Path("data.csv"))
            >>> print(content)
            'header1, header2, header3\nvalue1, value2, value3\n'
        """
        content = ""
        try:
            self.logger.debug(f"Reading CSV file: {file_path}")
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                for row in reader:
                    content += ", ".join(row) + "\n"
                self.logger.debug(f"Extracted CSV content from {file_path}")
            return content
        except Exception as e:
            self.logger.error(f"Error reading CSV file {file_path}: {e}")
            return ""

    def process_html_file(self, file_path):
        """Process an HTML file and extract its text content.

        Args:
            file_path (Path): Path to the HTML file.

        Returns:
            str: The extracted text content from the HTML, excluding markup.

        Example:
            >>> processor = Processor()
            >>> content = processor.process_html_file(Path("page.html"))
            >>> print(content)
            'Main Heading This is a paragraph of text...'
        """
        try:
            self.logger.debug(f"Reading HTML file: {file_path}")
            parser = etree.HTMLParser()
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                tree = etree.parse(f, parser)
                content = " ".join(tree.xpath("//text()"))
                self.logger.debug(f"Extracted HTML content from {file_path}")
                return content
        except Exception as e:
            self.logger.error(f"Error reading HTML file {file_path}: {e}")
            return ""

    def process_rtf_file(self, file_path):
        """Process an RTF file and extract its text content.

        Args:
            file_path (Path): Path to the RTF file.

        Returns:
            str: The extracted plain text content from the RTF file.

        Example:
            >>> processor = Processor()
            >>> content = processor.process_rtf_file(Path("document.rtf"))
            >>> print(content)
            'This is the plain text content extracted from RTF...'
        """
        try:
            self.logger.debug(f"Reading RTF file: {file_path}")
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = rtf_to_text(f.read())
                self.logger.debug(f"Extracted RTF content from {file_path}")
                return content
        except Exception as e:
            self.logger.error(f"Error reading RTF file {file_path}: {e}")
            return ""

    def process_xml_file(self, file_path):
        """Process an XML file and extract its text content.

        Args:
            file_path (Path): Path to the XML file.

        Returns:
            str: The extracted text content from the XML, excluding markup.

        Example:
            >>> processor = Processor()
            >>> content = processor.process_xml_file(Path("data.xml"))
            >>> print(content)
            'Root Element Child Element Text Content...'
        """
        try:
            self.logger.debug(f"Reading XML file: {file_path}")
            tree = etree.parse(file_path)
            content = " ".join(tree.xpath("//text()"))
            self.logger.debug(f"Extracted XML content from {file_path}")
            return content
        except Exception as e:
            self.logger.error(f"Error reading XML file {file_path}: {e}")
            return ""
