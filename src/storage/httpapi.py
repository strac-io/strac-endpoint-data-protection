import asyncio
import json
import logging
import mimetypes
import os
import uuid
from datetime import datetime, timezone

import aiofiles
import httpx

from config import (
    APP_VERSION,
    STRAC_API_DOCUMENT_SIZE_LIMIT,
    STRAC_API_DOCUMENT_TYPE_DEFAULT,
    STRAC_API_ENDPOINT_CONFIG,
    STRAC_API_ENDPOINT_CREATE_DOCUMENT,
    STRAC_API_ENDPOINT_CREATE_DOCUMENT_LARGE,
    STRAC_API_ENDPOINT_PROCESS_MESSAGE,
    STRAC_API_HEADERS,
    STRAC_API_KEY,
    STRAC_API_PUT_LOGS_RESOURCE_TYPE,
    STRAC_API_REMEDIATION_TYPE,
    STRAC_API_RESOURCE_TYPE,
    SYSTEM,
)
from storage.database import StracApiDocument

logger = logging.getLogger("storage-httpapi")


class StracApi:
    """
    Main driver class for Strac API interactions.

    This class handles all communications with the Strac Public API, including
    document uploads, sensitive content detection, and agent event logging. More
    information about the Strac API can be found at https://docs.strac.io.
    Attributes:
        logger: Logger instance for this class
        client: httpx Client instance for making HTTP requests
        TIMEOUT_SECONDS (httpx.Timeout): Timeout configuration for HTTP requests

    Examples:
        Basic usage:
            >>> client = StracApi()
            >>> client.send_documents(['/path/doc1.pdf'], 'safari')
            >>> client.close()

        Processing individual documents:
            >>> client = StracApi()
            >>> doc_id = client.create_document('/path/doc.pdf', 'safari')
            >>> client.detect_sensitive(doc_id)
            >>> client.store_event(doc_id, '/path/doc.pdf')
            >>> client.close()
    """

    def __init__(self):
        self.name = "storage-httpapi"
        self.logger = logger
        self.TIMEOUT_SECONDS = httpx.Timeout(connect=5, read=30, write=15, pool=5)
        self.current_user = SYSTEM.current_user

    def _alter_matches(self, detected_entities):
        """
        Transform detected entities into a Strac API compatible `matches` format.

        Args:
            detected_entities (list): List of detected sensitive content labels

        Returns:
            dict: Dictionary with 'matches' key containing formatted content labels

        Examples:
            >>> matches = self._alter_matches(['SSN', 'CREDIT_CARD'])
            >>> matches
            {'matches': ['content: SSN', 'content: CREDIT_CARD']}
        """
        m = set()
        for label in detected_entities:
            m.add(f"content: {label}")
        return {"matches": list(m)}

    def get_config(self):
        """
        Retrieve the configuration from the Strac API.

        Returns:
            dict | None: The configuration data if the request is successful, None otherwise.

        Examples:
            >>> client = StracApi()
            >>> config = client.get_config()
            >>> if config:
            ...     print("Strac Vault Config retrieved successfully")
            ... else:
            ...     print("Failed to retrieve Strac Vault Config")
        """
        headers = STRAC_API_HEADERS.copy()
        headers.update(
            {
                "x-device_id": SYSTEM.uuid,
                "x-logged_in_user": SYSTEM.current_user,
                "x-version": f"v{APP_VERSION}_{SYSTEM.os_architecture}",
                "x-operating-system": SYSTEM.os_name,
                "x-architecture": SYSTEM.os_architecture,
                "x-last-request-at": datetime.now(timezone.utc).isoformat(),
                "x-request-count": "0",
            }
        )
        try:
            with httpx.Client(timeout=self.TIMEOUT_SECONDS) as client:
                response = client.get(STRAC_API_ENDPOINT_CONFIG, headers=headers)

            if response.status_code == 200:
                try:
                    json_response = response.json()
                    return json_response
                except ValueError:
                    self.logger.debug("get_config response was not valid JSON")
                    return None
            elif response.status_code == 400:
                self.logger.debug(f"get_config error details: {response.text}")

            elif response.status_code == 401:
                self.logger.debug(f"get_config error details: {response.text}")

            elif response.status_code == 403:
                self.logger.debug(f"get_config error details: {response.text}")

            elif response.status_code == 404:
                self.logger.debug("get_config the requested endpoint was not found")

            elif response.status_code == 429:
                self.logger.debug("get_config too many requests: rate limit exceeded")

            elif response.status_code >= 500:
                self.logger.error(f"get_config error details: {response.text}")

            else:
                self.logger.debug(f"get_config unknown response: {response.text}")
        except Exception as e:
            self.logger.error(f"get_config unexpected error: {str(e)}")
        return None

    async def send_heartbeat(self):
        """
        Send a heartbeat to the Strac API.
        """
        try:
            ha_headers = STRAC_API_HEADERS.copy()
            ha_headers.update(
                {
                    "x-device_id": SYSTEM.uuid,
                    "x-logged_in_user": SYSTEM.current_user,
                    "x-version": f"v{APP_VERSION}_{SYSTEM.os_architecture}",
                    "x-operating-system": SYSTEM.os_name,
                    "x-architecture": SYSTEM.os_architecture,
                    "x-last-request-at": datetime.now(timezone.utc).isoformat(),
                    "x-request-count": "0",
                }
            )
            async with httpx.AsyncClient(verify=False) as async_client:
                response = await async_client.get(
                    STRAC_API_ENDPOINT_CONFIG, headers=ha_headers, timeout=None
                )
                if response.status_code > 300:
                    self.logger.debug(f"asynchronous heartbeat error: {response.text}")
        except Exception as e:
            self.logger.error(f"asynchronous heartbeat error: {str(e)}")

    async def create_document(self, file_path, app_name):
        """
        Upload a document to the Strac API.

        Args:
            file_path (str): Path to the file to upload
            app_name (str): Name of the application processing the document

        Returns:
            str: Document ID returned by the API

        Raises:
            Exception: If document creation fails

        Examples:
            >>> client = StracApi()
            >>> doc_id = client.create_document('/path/doc.pdf', 'chrome')
            >>> print(doc_id)
            'abc123-def456'
        """
        async with aiofiles.open(file_path, "rb") as file:
            mime_type, _ = mimetypes.guess_type(file_path)
            file_name = file_path.split("/")[-1]
            file_size = os.path.getsize(file_path)
            if app_name != "Finder":
                file_content = await file.read()
                is_large_file = file_size > STRAC_API_DOCUMENT_SIZE_LIMIT
            else:
                file_content = None
                is_large_file = False
            async with httpx.AsyncClient(verify=False) as async_client:
                if not is_large_file:
                    try:
                        response = await async_client.post(
                            STRAC_API_ENDPOINT_CREATE_DOCUMENT,
                            headers=STRAC_API_HEADERS,
                            files={"document": (file_name, file_content, mime_type)},
                            timeout=None,
                        )
                    except Exception as e:
                        self.logger.debug(e)
                        raise
                else:
                    payload = {"contentType": mime_type, "fileName": file_name}
                    response = await async_client.post(
                        STRAC_API_ENDPOINT_CREATE_DOCUMENT_LARGE,
                        headers=STRAC_API_HEADERS,
                        json=payload,
                        timeout=None,
                    )
                    response_document_url = response.json().get(
                        "response", response.json()
                    )
                    document_url = response_document_url.get("documentUrl")
                    document_id = response_document_url.get("documentId")

                    if document_id and document_url:
                        upload_headers = {"Content-Type": mime_type}

                        await async_client.put(
                            document_url,
                            headers=upload_headers,
                            data=file_content,
                            timeout=self.TIMEOUT_SECONDS,
                        )
                if response.status_code == 200:
                    if not is_large_file:
                        document_id = response.json().get("id")
                    else:
                        document_id = response.json().get("documentId")

                    # Check if document_id already exists
                    if (
                        not StracApiDocument.select()
                        .where(StracApiDocument.document_id == document_id)
                        .exists()
                    ):
                        StracApiDocument.create(
                            document_id=document_id,
                            content_type=response.json().get("content_type", mime_type),
                            document_type=STRAC_API_DOCUMENT_TYPE_DEFAULT,
                            app_name=app_name,
                            file_name=file_name,
                            creation_time=datetime.fromisoformat(
                                response.json().get(
                                    "creation_time", datetime.now().isoformat()
                                )
                            ),
                            size=response.json().get("size", file_size),
                        )
                    return document_id
                raise Exception(f"failed to create document for {file_path}")

    async def process_message(self, document_id, file_path, url):
        """
        Analyze a document for sensitive content.

        Args:
            document_id (str): ID of the document to analyze

        Returns:
            bool: True if detection was successful

        Raises:
            Exception: If sensitive content detection fails

        Examples:
            >>> client = StracApi()
            >>> client.detect_sensitive('abc123-def456')
            True
        """
        try:
            strac_doc = StracApiDocument.get(document_id=document_id)
            username = SYSTEM.current_user
            body = {
                "resource_type": STRAC_API_RESOURCE_TYPE,
                "remediation_type": STRAC_API_REMEDIATION_TYPE,
                "device_id": SYSTEM.uuid,
                "logged_in_user": username,
                "event_id": str(uuid.uuid4()),
                "file_path": file_path.split("/")[-1],
                "document_id": document_id,
                "document_type": strac_doc.document_type,
                "last_updated": datetime.now(timezone.utc).isoformat()[:-6] + "Z",
                "creation_date": datetime.now(timezone.utc).isoformat()[:-6] + "Z",
                "event_date": datetime.now(timezone.utc).isoformat()[:-6] + "Z",
                "app_name": strac_doc.app_name,
            }
            if url is not None:
                body["url"] = url

            async with httpx.AsyncClient(verify=False) as async_client:
                response = await async_client.post(
                    STRAC_API_ENDPOINT_PROCESS_MESSAGE,
                    headers=STRAC_API_HEADERS,
                    json=body,
                    timeout=self.TIMEOUT_SECONDS,
                )
                retry_count = 0
                while response.status_code == 504 and retry_count < 3:
                    self.logger.warning(
                        f"process_message error='504 timeout' retry_count='{retry_count}/3' document_id='{document_id}' file_path='{file_path}'"
                    )
                    await asyncio.sleep(5)
                    response = await async_client.post(
                        STRAC_API_ENDPOINT_PROCESS_MESSAGE,
                        headers=STRAC_API_HEADERS,
                        json=body,
                        timeout=self.TIMEOUT_SECONDS,
                    )
                    retry_count += 1
                if response.status_code == 504:
                    self.logger.error(
                        "process_message error='504 timeout' reason='server is busy'"
                    )
                    return False
                if response.status_code <= 299:
                    data = response.json()
                    self.logger.debug(
                        f"process_message response_status='{response.status_code}' document_id='{document_id}' file_path='{file_path}' response='{response.text}'"
                    )
                    if "detectedElementTypes" in data:
                        detected_elements = data["detectedElementTypes"]
                    else:
                        detected_elements = []

                    # Update StracDocument with detection results
                    query = StracApiDocument.update(
                        is_sensitive=bool(len(detected_elements) > 0),
                        detection_time=datetime.now(timezone.utc),
                        detected_entities=(
                            json.dumps(detected_elements) if detected_elements else None
                        ),
                    ).where(StracApiDocument.document_id == document_id)
                    query.execute()

                    return True
                else:
                    self.logger.error(
                        f"process_message response_status='{response.status_code}' document_id='{document_id}' file_path='{file_path}' response='{response.text}'"
                    )
        except Exception as e:
            self.logger.error(
                f"process_message document_id='{document_id}' file_path='{file_path}' exception='{str(e)}'"
            )
            return True

    async def store_event(self, document_id, file_path, url):
        """
        Record a document processing event.

        Args:
            document_id (str): ID of the processed document
            file_path (str): Original path of the processed file

        Returns:
            bool: True if event was stored successfully

        Examples:
            >>> client = StracApi()
            >>> client.store_event('abc123-def456', '/path/doc.pdf')
            True
        """
        try:
            strac_doc = StracApiDocument.get(document_id=document_id)
            detected_elements_types = (
                []
                if strac_doc.detected_entities is None
                else json.loads(strac_doc.detected_entities)
            )

            async with httpx.AsyncClient(verify=False) as async_client:
                username = SYSTEM.current_user
                payload = {
                    "resource_type": "ScanFile",
                    "remediation_type": "AUDIT",
                    "device_id": SYSTEM.uuid,
                    "logged_in_user": username,
                    "event_id": str(uuid.uuid4()),
                    "file_path": file_path.split("/")[-1],
                    "document_id": document_id,
                    "document_type": strac_doc.document_type,
                    "detected_element": strac_doc.is_sensitive,
                    "detected_element_types": detected_elements_types,
                    "detected_elements": [
                        {"type": "rule_match", "value": match}
                        for match in self._alter_matches(detected_elements_types)
                    ],
                    "last_updated": datetime.now(timezone.utc).isoformat()[:-6] + "Z",
                    "creation_date": datetime.now(timezone.utc).isoformat()[:-6] + "Z",
                    "event_date": datetime.now(timezone.utc).isoformat()[:-6] + "Z",
                    "app_name": strac_doc.app_name,
                }
                if url is not None:
                    payload["url"] = url
                self.logger.debug(f"store_event payload='{payload}'")

                response = await async_client.post(
                    STRAC_API_ENDPOINT_PROCESS_MESSAGE,
                    json=payload,
                    headers=STRAC_API_HEADERS,
                    timeout=self.TIMEOUT_SECONDS,
                )
                if response.status_code <= 299:
                    self.logger.debug(
                        f"store_event response_status='{response.status_code}' document_id='{document_id}' file_path='{file_path}' response='{response.text}'"
                    )
                    return True
                else:
                    self.logger.error(
                        f"store_event response_status='{response.status_code}' document_id='{document_id}' file_path='{file_path}' response='{response.text}'"
                    )
                return True
        except Exception as e:
            self.logger.error(
                f"store_event document_id='{document_id}' file_path='{file_path}' exception='{str(e)}'"
            )
            return True

    async def process_document(self, file_access):
        """
        Process a single document through the complete workflow.

        Args:
            file_access (tuple): Queue entry containing document information

        Note:
            This method handles the complete document processing workflow:
            1. Document creation
            2. Sensitive content detection
            3. Event storage
            4. Status updates

        Examples:
            >>> queued_doc = (timestamp, filepath, app_name)
            >>> client = StracApi()
            >>> client.process_document(queued_doc)
        """
        _, filepath, app_name, url = file_access
        try:
            document_id = await self.create_document(filepath, app_name)
            await asyncio.sleep(2)
            await self.process_message(document_id, filepath, url)
            # don't know why, but slowing it down makes it more consistent
            await asyncio.sleep(2)
            await self.store_event(document_id, filepath, url)
            # send heartbeat after all other operations are complete
            await self.send_heartbeat()
        except Exception as e:
            self.logger.error(f"process_document exception='{str(e)}'")


def pulse_check():
    try:
        pulse_headers = STRAC_API_HEADERS.copy()
        pulse_headers.update(
            {
                "x-device_id": SYSTEM.uuid,
                "x-logged_in_user": SYSTEM.current_user,
                "x-version": f"v{APP_VERSION}_{SYSTEM.os_architecture}",
                "x-operating-system": SYSTEM.os_name,
                "x-architecture": SYSTEM.os_architecture,
                "x-last-request-at": datetime.now(timezone.utc).isoformat(),
                "x-request-count": "0",
            }
        )
        with httpx.Client(verify=False) as client:
            response = client.get(
                STRAC_API_ENDPOINT_CONFIG, headers=pulse_headers, timeout=5
            )
            if response.status_code != 200:
                logger.warning(f"synchronous heartbeat error: {response.text}")
                return None
            else:
                return response.json()
    except Exception as e:
        logger.error(f"synchronous heartbeat error: {str(e)}")
        return None


def log_to_strac_api(log_lines, start_time, end_time):
    """
    Ship log lines to the Strac API. make sure to create start_time early and recreate it after each log_to_strac_api call.

    Args:
        log_lines (str): Log content to ship
        start_time (datetime): ISO formatted start time of logs
        end_time (datetime): ISO formatted end time of logs

    Examples:
        >>> logs = "INFO Something Happened"
        >>> start = datetime.datetime.now(datetime.timezone.utc) # should be the start of the log file
        >>> end = datetime.datetime.now() # should be the end of the log file
        >>> log_to_strac_api(logs, start, end)
    """
    try:
        headers = {
            "X-Api-Key": STRAC_API_KEY,
            "Content-Type": "application/json",
        }
        payload = {
            "resource_type": STRAC_API_PUT_LOGS_RESOURCE_TYPE,
            "device_id": SYSTEM.uuid,
            "logged_in_user": SYSTEM.current_user,
            "log_start_date_time": str(start_time),
            "log_end_date_time": str(end_time),
            "log_lines": [log_lines],
        }
        with httpx.Client(verify=False) as client:
            response = client.post(
                STRAC_API_ENDPOINT_PROCESS_MESSAGE,
                headers=headers,
                json=payload,
                timeout=httpx.Timeout(connect=1, read=5, write=10, pool=5),
            )
    except Exception as e:
        logger.warning(f"log_to_strac_api exception='{str(e)}'")
