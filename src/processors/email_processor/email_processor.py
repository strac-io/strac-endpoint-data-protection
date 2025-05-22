import email
import logging


class Processor:
    """Email processor for extracting text content from email files.

    This processor handles .eml and .msg file formats, extracting plain text content
    from email bodies and attachments. It supports both synchronous and asynchronous
    processing methods.

    Attributes:
        name (str): The display name of the processor.
        version (str): The version number of the processor.
        supported_extensions (list[str]): List of file extensions this processor can handle.

    Example:
        >>> processor = Processor()
        >>> # Synchronous processing
        >>> text = processor.process_file("path/to/email.eml")
        >>> print(text)
        'Email content...'

        >>> # Asynchronous processing with a scanner
        >>> text = await processor.process_file_async("path/to/email.eml", scanner)
        >>> print(text)
        'Email content...'
    """

    name = "Email Processor"
    version = "1.2"
    supported_extensions = [".eml", ".msg"]

    def __init__(self):
        """Initialize the Email Processor with a configured logger."""
        self.logger = logging.getLogger("processor-email")

    def __repr__(self):
        """Return a developer-friendly string representation of the processor.

        Returns:
            str: A string in the format "<ClassName ProcessorName vVersion>"
        """
        return f"<{self.__class__.__name__} {self.name} v{self.version}>"

    def __str__(self):
        """Return a user-friendly string representation of the processor.

        Returns:
            str: A string in the format "ProcessorName vVersion"
        """
        return f"{self.name} v{self.version}"

    async def process_file_async(self, file_path, scanner):
        """Process an email file asynchronously using the provided scanner.

        Args:
            file_path (str): Path to the email file to process.
            scanner: Scanner instance providing the event loop and executor.

        Returns:
            str: Extracted text content from the email file, or empty string on error.

        Example:
            >>> async with Scanner() as scanner:
            ...     processor = Processor()
            ...     text = await processor.process_file_async("email.eml", scanner)
        """
        loop = scanner.loop
        try:
            text_content = await loop.run_in_executor(
                scanner.executor, self.process_file, file_path
            )
            return text_content
        except Exception as e:
            self.logger.error(f"error processing file {file_path}: {e}")
            return ""

    def process_file(self, file_path):
        """Process an email file synchronously to extract its text content.

        This method opens the email file, parses it, and extracts text content
        from all text/plain parts of the email.

        Args:
            file_path (str): Path to the email file to process.

        Returns:
            str: Extracted text content from the email file, or empty string on error.

        Example:
            >>> processor = Processor()
            >>> text = processor.process_file("path/to/email.eml")
            >>> if text:
            ...     print("Successfully extracted text content")
        """
        text_content = ""
        try:
            with open(file_path, "rb") as f:
                self.logger.debug(f"processing: {file_path}")
                msg = email.message_from_bytes(f.read())
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            content = payload.decode("utf-8", errors="ignore")
                            text_content += content + "\n"
                            self.logger.debug("extracted text content from email part")
            return text_content
        except Exception as e:
            self.logger.error(f"error processing email file {file_path}: {e}")
            return ""
