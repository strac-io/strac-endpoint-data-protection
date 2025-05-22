"""PDF text extraction processor module.

This module provides functionality for extracting text from PDF files using both
direct text extraction and OCR capabilities. It handles both searchable PDFs and
image-based PDFs that require OCR processing.

Example:
    Basic usage of the PDF processor:

    ```python
    processor = Processor()

    # Process a single PDF file
    text = processor.process_file("/path/to/document.pdf")

    # Async processing with a scanner
    async with Scanner() as scanner:
        text = await processor.process_file_async("/path/to/document.pdf", scanner)
    ```
"""

import logging
import platform
import shutil
import subprocess
import tempfile

import fitz

# Only import ocrmac on macOS
if platform.system() == "Darwin":
    import ocrmac


class Processor:
    """PDF text extraction processor.

    A processor class that handles text extraction from PDF files using both direct
    text extraction and OCR when needed. It supports both synchronous and asynchronous
    processing methods.

    Attributes:
        name (str): The processor identifier name.
        version (str): The current version of the processor.
        supported_extensions (list[str]): File extensions this processor can handle.
        logger (logging.Logger): Logger instance for this processor.

    Example:
        ```python
        processor = Processor()

        # Basic synchronous processing
        text = processor.process_file("document.pdf")

        # If text extraction fails, OCR is automatically attempted
        if not text:
            print("Document may be image-based, OCR was attempted")
        ```
    """

    name = "PDF Processor"
    version = "1.2"
    supported_extensions = [".pdf"]

    def __init__(self):
        """Initializes the PDF Processor with a configured logger."""
        self.logger = logging.getLogger("processor-pdf")
        self.system = platform.system()

        # Check for ocrad on Linux
        if self.system == "Linux":
            try:
                subprocess.run(
                    ["ocrad", "--version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.ocrad_available = True
            except (FileNotFoundError, subprocess.SubprocessError):
                self.ocrad_available = False
                self.logger.warning(
                    "ocrad not found on this Linux system. Please install it using 'apt-get install ocrad' or your system's package manager."
                )

    def __repr__(self):
        """Returns the official string representation of the processor.

        Returns:
            str: A string in the format "<ClassName ProcessorName vVersion>".
        """
        return f"<{self.__class__.__name__} {self.name} v{self.version}>"

    def __str__(self):
        """Returns the informal string representation of the processor.

        Returns:
            str: A string in the format "ProcessorName vVersion".
        """
        return f"{self.name} v{self.version}"

    async def process_file_async(self, file_path, scanner):
        """Asynchronously processes a PDF file using the provided scanner.

        This method offloads the CPU-intensive PDF processing to a process pool
        executor to avoid blocking the event loop.

        Args:
            file_path (Path): Path to the PDF file to process.
            scanner (Scanner): Scanner instance providing the process pool executor.

        Returns:
            str: Extracted text content from the PDF, or empty string on failure.

        Example:
            ```python
            async with Scanner() as scanner:
                text = await processor.process_file_async("doc.pdf", scanner)
                print(f"Extracted {len(text)} characters")
            ```
        """
        try:
            loop = scanner.loop
            text_content = await loop.run_in_executor(
                scanner.process_executor, self.process_file, file_path
            )
            return text_content
        except Exception as e:
            self.logger.error(f"Error processing {file_path}: {e}")
            return ""

    def process_file(self, file_path):
        """Processes a PDF file to extract its text content.

        Attempts direct text extraction first, and if no text is found,
        automatically falls back to OCR processing.

        Args:
            file_path (Path): Path to the PDF file to process.

        Returns:
            str: Extracted text content from the PDF, or empty string on failure.

        Example:
            ```python
            text = processor.process_file("document.pdf")
            if text:
                print("First 100 chars:", text[:100])
            ```
        """
        text_content = ""
        try:
            self.logger.debug(f"Opening PDF file: {file_path}")
            doc = fitz.open(file_path)
            for page_num, page in enumerate(doc, start=1):
                self.logger.debug(f"Extracting text from page {page_num}")
                text = page.get_text()
                if text:
                    text_content += text + "\n"
            if not text_content.strip():
                self.logger.debug(f"No text extracted, performing OCR on: {file_path}")
                text_content = self.ocr_pdf(file_path)
            return text_content
        except Exception as e:
            self.logger.error(f"Error extracting text from {file_path}: {e}")
            self.logger.debug(f"Attempting OCR on: {file_path}")
            return self.ocr_pdf(file_path)

    def ocr_pdf(self, pdf_path):
        """Performs OCR on a PDF file by converting pages to images.

        Creates temporary image files for each PDF page and processes them
        through OCR, then combines the results.

        Args:
            pdf_path (Path): Path to the PDF file to OCR.

        Returns:
            str: Combined OCR text content from all pages, or empty string on failure.

        Example:
            ```python
            # Usually called automatically by process_file, but can be used directly
            text = processor.ocr_pdf("scanned_document.pdf")
            ```
        """
        text_content = ""
        temp_dir = tempfile.mkdtemp()
        try:
            self.logger.debug("Converting PDF pages to images for OCR")
            doc = fitz.open(pdf_path)
            for page_num, page in enumerate(doc, start=1):
                image_path = f"{temp_dir}/page_{page_num}.png"
                pix = page.get_pixmap()
                pix.save(image_path)
                self.logger.debug(f"Saved page {page_num} as image for OCR")
                text_content += self.perform_ocr(image_path) + "\n"
            return text_content
        except Exception as e:
            self.logger.error(f"Error during OCR of {pdf_path}: {e}")
            return ""
        finally:
            shutil.rmtree(temp_dir)

    def perform_ocr(self, image_path):
        """Performs OCR on a single image file.

        Uses the ocrmac library on macOS or ocrad on Linux to perform text recognition
        on the provided image.

        Args:
            image_path (str): Path to the image file to process.

        Returns:
            str: Extracted text content from the image, or empty string on failure.

        Example:
            ```python
            # Usually called by ocr_pdf, but can be used independently
            text = processor.perform_ocr("page_image.png")
            ```
        """
        try:
            if self.system == "Darwin":
                # Use ocrmac on macOS
                annotations = ocrmac.OCR(
                    image_path, recognition_level="accurate"
                ).recognize()
                if not annotations:
                    self.logger.debug(f"OCR returned no results for {image_path}")
                    return ""
                else:
                    found_text = " ".join([bbox[0] for bbox in annotations])
                    self.logger.debug(f"OCR found text in {image_path}")
                    return found_text
            elif self.system == "Linux":
                # Use ocrad on Linux
                if not self.ocrad_available:
                    self.logger.error("ocrad is not available on this Linux system")
                    return ""

                try:
                    # Run ocrad command
                    process = subprocess.run(
                        ["ocrad", image_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True,
                        text=True,
                    )

                    found_text = process.stdout.strip()
                    if not found_text:
                        self.logger.debug(f"ocrad returned no results for {image_path}")
                        return ""

                    self.logger.debug(f"ocrad successfully processed: {image_path}")
                    return found_text
                except subprocess.SubprocessError as e:
                    self.logger.error(
                        f"ocrad failed to process: {image_path} exception: {str(e)}"
                    )
                    return ""
            else:
                self.logger.error(f"Unsupported operating system: {self.system}")
                return ""
        except Exception as e:
            self.logger.error(f"OCR failed for {image_path}: {e}")
            return ""
