import logging
import os
import shutil
import tempfile
from pathlib import Path

from lxml import etree


class Processor:
    """Processes Apple iWork document files (Pages, Numbers, and Keynote) to extract text content.

    This processor handles the extraction of text content from Apple iWork documents by
    unpacking the document bundle and parsing the contained XML files.

    Attributes:
        name (str): The display name of the processor.
        version (str): The version number of the processor.
        supported_extensions (list[str]): List of file extensions this processor can handle.

    Example:
        ```python
        processor = Processor()

        # Process a single file
        text = processor.process_file("presentation.key")

        # Process asynchronously with a scanner
        async with Scanner() as scanner:
            text = await processor.process_file_async("document.pages", scanner)
        ```
    """

    name = "iWork Processor"
    version = "1.2"
    supported_extensions = [".key", ".numbers", ".pages"]

    def __init__(self):
        """Initializes the iWork processor with a configured logger."""
        self.logger = logging.getLogger("processor-iwork")

    def __repr__(self):
        """Returns a string representation of the processor for debugging.

        Returns:
            str: A string in the format "<ClassName ProcessorName vVersion>"
        """
        return f"<{self.__class__.__name__} {self.name} v{self.version}>"

    def __str__(self):
        """Returns a human-readable string representation of the processor.

        Returns:
            str: A string in the format "ProcessorName vVersion"
        """
        return f"{self.name} v{self.version}"

    async def process_file_async(self, file_path, scanner):
        """Asynchronously processes an iWork file to extract its text content.

        This method runs the synchronous processing in a separate thread using
        the scanner's executor to avoid blocking the event loop.

        Args:
            file_path (str): Path to the iWork file to process.
            scanner (Scanner): Scanner instance providing the event loop and executor.

        Returns:
            str: Extracted text content from the document, or empty string on error.

        Example:
            ```python
            async with Scanner() as scanner:
                text = await processor.process_file_async("presentation.key", scanner)
                print(f"Extracted text: {text}")
            ```
        """
        try:
            loop = scanner.loop
            text_content = await loop.run_in_executor(
                scanner.executor, self.process_file, file_path
            )
            return text_content
        except Exception as e:
            self.logger.error(f"error async processing: {file_path} exception: {e}")
            return ""

    def process_file(self, file_path):
        """Processes an iWork file to extract its text content.

        This method unpacks the iWork bundle (which is actually a directory structure),
        finds all XML files within it, and extracts text content from these files.

        Args:
            file_path (str): Path to the iWork file to process.

        Returns:
            str: Extracted text content from the document, or empty string on error.

        Example:
            ```python
            processor = Processor()
            text = processor.process_file("document.pages")
            print(f"Extracted text: {text}")
            ```
        """
        text_content = ""
        temp_dir = tempfile.mkdtemp()
        try:
            self.logger.debug(f"unpacking: {file_path} to {temp_dir}")
            shutil.unpack_archive(file_path, temp_dir)
            xml_files = []
            for root, dirs, files in os.walk(temp_dir):
                for file_name in files:
                    if file_name.endswith(".xml"):
                        xml_file_path = Path(root) / file_name
                        xml_files.append(xml_file_path)
                        self.logger.debug(f"found XML file: {xml_file_path}")
            for xml_file in xml_files:
                try:
                    self.logger.debug(f"parsing XML file: {xml_file}")
                    tree = etree.parse(str(xml_file))
                    extracted_text = " ".join(tree.xpath("//text()"))
                    text_content += extracted_text + "\n"
                    self.logger.debug(f"extracted text from XML file: {xml_file}")
                except Exception as e:
                    self.logger.error(
                        f"error parsing XML file: {xml_file} exception: {e}"
                    )
            return text_content
        except Exception as e:
            self.logger.error(f"error processing: {file_path} exception: {e}")
            return ""
        finally:
            self.logger.debug(f"cleaning up temp directory: {temp_dir}")
            shutil.rmtree(temp_dir)
