import logging
import platform
import subprocess
import tempfile

# Only import ocrmac on macOS
if platform.system() == "Darwin":
    from ocrmac import ocrmac

from PIL import Image, ImageFile
from pillow_heif import register_avif_opener, register_heif_opener

register_heif_opener()  # pillow plugin registration
register_avif_opener()  # pillow plugin registration


class Processor:
    """Image processing class that performs OCR on various image formats.

    This processor handles a wide variety of image formats including HEIC, AVIF,
    JPEG, PNG and others. It converts images to a compatible format and performs
    OCR using the ocrmac library on macOS or ocrad on Linux.

    Note:
        This processor does not support all image formats. If an image format is
        not supported, it will be skipped and a warning will be logged.

    Attributes:
        name (str): Display name of the processor.
        version (str): Version string of the processor.
        supported_extensions (list[str]): List of file extensions this processor can handle.

    Example:
        >>> processor = Processor()
        >>> text = processor.process_file("path/to/image.jpg")
        >>> print(text)  # Prints extracted text from image
    """

    name = "Image Processor"
    version = "1.2"
    supported_extensions = [
        ".avif",
        ".bmp",
        ".dib",
        ".fpx",
        ".gif",
        ".heic",
        ".ico",
        ".j2k",
        ".jp2",
        ".jpeg",
        ".jpg",
        ".mcidas",
        ".pbm",
        ".pcd",
        ".pcx",
        ".pfm",
        ".pgm",
        ".pixar",
        ".png",
        ".pnm",
        ".ppm",
        ".psd",
        ".sgi",
        ".tga",
        ".tif",
        ".tiff",
        ".webp",
        ".wmf",
        ".xbm",
    ]

    def __init__(self):
        self.logger = logging.getLogger("processor-images")
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
        return f"<{self.__class__.__name__} {self.name} v{self.version}>"

    def __str__(self):
        return f"{self.name} v{self.version}"

    def perform_ocr(self, temp_file, image_path):
        """Performs OCR on the given image file.

        Args:
            temp_file (str): Path to temporary JPEG file to process.
            image_path (str): Original image path for logging purposes.

        Returns:
            str: Extracted text from the image. Empty string if no text found
                or if an error occurs.

        Example:
            >>> with tempfile.NamedTemporaryFile(suffix=".jpeg") as temp:
            ...     processor.perform_ocr(temp.name, "original.jpg")
        """
        try:
            if self.system == "Darwin":
                # Use ocrmac on macOS
                annotations = ocrmac.OCR(
                    temp_file, recognition_level="accurate"
                ).recognize()
                if len(annotations) == 0:
                    self.logger.debug(f"ocr returned no results: {image_path}")
                    return ""
                else:
                    found_text = ""
                    for bounding_box in annotations:
                        found_text = f"{found_text} {bounding_box[0]}"
                    self.logger.debug(
                        f"ocr found: {len(annotations)} bounding boxes: {image_path}"
                    )
                    return found_text
            elif self.system == "Linux":
                # Use ocrad on Linux
                if not self.ocrad_available:
                    self.logger.error("ocrad is not available on this Linux system")
                    return ""

                try:
                    # Run ocrad command
                    process = subprocess.run(
                        ["ocrad", temp_file],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True,
                        text=True,
                    )

                    found_text = process.stdout.strip()
                    if not found_text:
                        self.logger.debug(f"ocrad returned no results: {image_path}")
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
            self.logger.error(
                f"ocr failed to process: {image_path} exception: {str(e)}"
            )
            return ""

    async def process_file_async(self, file_path, scanner):
        """Asynchronously processes an image file using the scanner's executor.

        Args:
            file_path (str): Path to the image file to process.
            scanner (Scanner): Scanner instance providing the process executor
                and event loop.

        Returns:
            str: Extracted text from the image. Empty string if processing fails.

        Example:
            >>> async with Scanner() as scanner:
            ...     text = await processor.process_file_async("image.png", scanner)
        """
        try:
            loop = scanner.loop
            text_content = await loop.run_in_executor(
                scanner.process_executor, self.process_file, file_path
            )
            return text_content
        except Exception as e:
            self.logger.error(f"error processing: {file_path}: {e}")
            return ""

    def process_file(self, file_path):
        """Processes an image file and extracts text using OCR.

        This method handles image mode conversion and creates a temporary JPEG
        file for OCR processing.

        Args:
            file_path (str): Path to the image file to process.

        Returns:
            str: Extracted text from the image. Empty string if processing fails
                or if the image is not supported or if image has no text.

        Example:
            >>> processor = Processor()
            >>> text = processor.process_file("document.png")
            >>> if text:
            ...     print("Found text:", text)
        """
        try:
            self.logger.debug(f"opening image: {file_path}")
            ImageFile.LOAD_TRUNCATED_IMAGES = True
            image = Image.open(file_path)
            if image.mode == "L":
                image = image.convert("L")
            elif image.mode in ["RGB", "RGBA", "P", "CMYK"]:
                image = image.convert("RGB")
            else:
                self.logger.warning(
                    f"skipping: {file_path} due to unsupported image mode: {image.mode}"
                )
                return ""
            with tempfile.NamedTemporaryFile(suffix=".jpeg") as temp_image:
                image.save(temp_image.name)
                self.logger.debug(f"saved temp JPG: {temp_image.name}")
                text = self.perform_ocr(temp_image.name, file_path)
                return text
        except Exception as e:
            self.logger.error(f"error processing: {file_path} exception: {e}")
            return ""
