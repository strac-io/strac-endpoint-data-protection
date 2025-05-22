import logging
from datetime import timedelta
from pathlib import Path

from config import NOTIFICATION_ICON_PATH, SYSTEM

logger = logging.getLogger("storage-notifications")

if SYSTEM.OS_IS_MACOS:
    try:
        from mac_notifications import client
    except ImportError:
        logger.error(
            "mac_notifications package not installed, notifications won't work on macOS"
        )
else:
    try:
        from plyer import notification
    except ImportError:
        logger.error(
            "plyer package not installed, notifications won't work on Linux/Windows"
        )


def send_notification(title, subtitle=None, message=None, sound=True, timeout=10):
    """Notification handling module for cross-platform desktop notifications.

    This module provides a unified interface for sending desktop notifications
    across different operating systems (macOS, Windows, Linux). It automatically
    detects the current platform and uses the appropriate notification system.

    For macOS, it uses the mac_notifications package.
    For Windows and Linux, it uses the plyer package.

    Attributes:
        logger: Logger instance for this module.
        app_name: Application name used in notifications.

    Examples:
        Basic usage:

        >>> from storage.notifications import send_notification
        >>> send_notification("Download Complete", message="Your file is ready")

        With all parameters on macOS:

        >>> send_notification(
        ...     title="Process Complete",
        ...     subtitle="Background task",
        ...     message="Your requested operation has finished",
        ...     sound=True
        ... )

        With timeout on Windows/Linux:

        >>> send_notification(
        ...     title="Update Available",
        ...     message="A new version is ready to install",
        ...     timeout=30
        ... )
    """
    logger.debug(f"attempting to send notification: {title}")

    try:
        if SYSTEM.OS_IS_MACOS:
            return _send_macos_notification(title, subtitle, message, sound)
        elif SYSTEM.OS_IS_LINUX or SYSTEM.OS_IS_WINDOWS:
            return _send_plyer_notification(title, message, timeout)
        else:
            logger.warning(
                f"notifications not supported on this platform: {SYSTEM.os_name}"
            )
            return False
    except Exception as e:
        logger.error(f"failed to send notification: {str(e)}")
        return False


def _send_macos_notification(title, subtitle=None, message=None, sound=None):
    """Sends a notification on macOS using the mac_notifications package.

    Args:
        title: The title of the notification.
        subtitle: Optional subtitle text.
        message: Optional main message text.
        sound: Optional boolean to enable notification sound.

    Returns:
        bool: True if notification was sent successfully, False otherwise.

    Examples:
        this is meant to be used internally by the module
    """
    try:
        # create notification
        client.create_notification(
            title=title,
            subtitle=subtitle,
            text=message,
            sound=sound,
            icon=Path(NOTIFICATION_ICON_PATH)
            if Path(NOTIFICATION_ICON_PATH).exists()
            else None,
            snooze_button_str="Snooze",
            delay=timedelta(minutes=500),
        )

        logger.debug("macOS notification sent successfully")
        return True
    except Exception as e:
        logger.error(f"error sending macOS notification: {str(e)}")
        return False


def _send_plyer_notification(title, message, timeout):
    """Sends a notification using the plyer library.

    This function attempts to send a notification using the plyer library,
    which supports cross-platform notifications.

    Args:
        title (str): The title of the notification.
        message (str): The message body of the notification.
        timeout (int): The notification timeout in seconds.

    Returns:
        bool: True if notification was sent successfully, False otherwise.

    Examples:
        this is meant to be used internally by the module
    """
    try:
        # send notification
        notification.notify(
            title=title,
            message=message if message else "",
            app_name="Strac Auditor",
            timeout=timeout,
        )
        logger.debug(f"{SYSTEM.os_name} notification sent successfully")
        return True
    except Exception as e:
        logger.error(f"error sending {SYSTEM.os_name} notification: {str(e)}")
        return False


def send_sensitive_data_alert(document_name, sensitive_types):
    """Sends a notification alert for sensitive data found in a document.

    This function formats and sends a notification to the user when sensitive data
    is detected in a document. The notification includes the document name and
    the types of sensitive data found.

    Args:
        document_name (str): The name of the document containing sensitive data.
        sensitive_types (list): A list of strings representing the types of sensitive
            data found in the document (e.g., ["SSN", "Credit Card", "Phone Number"]).

    Returns:
        bool: True if the notification was sent successfully, False otherwise.

    Example:
        >>> send_sensitive_data_alert("confidential.pdf", ["SSN", "Credit Card"])
        True
    """
    try:
        # format the sensitive types into a readable string
        if len(sensitive_types) > 2:
            types_str = ", ".join(sensitive_types[:-1]) + f", and {sensitive_types[-1]}"
        elif len(sensitive_types) == 2:
            types_str = f"{sensitive_types[0]} and {sensitive_types[1]}"
        elif len(sensitive_types) == 1:
            types_str = sensitive_types[0]
        else:
            types_str = "sensitive information"

        title = "Sensitive Data Alert"
        subtitle = f"Found in: {document_name}"
        message = f"This document contains {types_str}. Please handle with care."

        logger.info(f"sending sensitive data alert for document: {document_name}")
        return send_notification(title, subtitle, message)
    except Exception as e:
        logger.error(f"failed to send sensitive data alert: {str(e)}")
        return False
