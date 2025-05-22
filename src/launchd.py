import logging
import os
import plistlib
import subprocess

from config import APP_EXECUTABLE, LOG_PATH, ORG_IDENTIFIER

logger = logging.getLogger(__name__)


def _get_launchd_plist_path(daemon_name):
    return f"/Library/LaunchDaemons/{ORG_IDENTIFIER}.{daemon_name}.plist"


def _create_launchd_plist(daemon_name, interval=14400):
    plist_content = {
        "Label": f"{ORG_IDENTIFIER}.{daemon_name}",
        "ProgramArguments": [
            APP_EXECUTABLE,
            "restart",
            daemon_name,
        ],
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": f"{LOG_PATH}/launchd-{daemon_name}.log",
        "StandardErrorPath": f"{LOG_PATH}/launchd-{daemon_name}_error.log",
        "ThrottleInterval": interval,
    }
    return plist_content


def _is_launchd_daemon_installed(daemon_name):
    plist_path = _get_launchd_plist_path(daemon_name)
    return os.path.exists(plist_path)


def _is_launchd_daemon_running(daemon_name):
    try:
        result = subprocess.run(
            ["launchctl", "list", f"{ORG_IDENTIFIER}.{daemon_name}"],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0
    except Exception:
        return False


def install_launchd_daemon(daemon_name, interval=14400):
    plist_path = _get_launchd_plist_path(daemon_name)
    if not os.path.exists(APP_EXECUTABLE):
        logger.error("auditor executable not found at %s", APP_EXECUTABLE)
        return False

    if _is_launchd_daemon_installed(daemon_name):
        logger.error("launchd daemon is already installed")
        return False

    try:
        plist_content = _create_launchd_plist(daemon_name, interval)

        with open(plist_path, "wb") as f:
            plistlib.dump(plist_content, f)

        # set correct permissions
        os.chmod(plist_path, 0o644)

        # load the daemon
        subprocess.run(["launchctl", "bootstrap", " system", plist_path], check=True)
        logger.info("launchd daemon installed successfully")
        return True
    except Exception as e:
        logger.error("error installing launchd daemon: %s", str(e))
        return False


def uninstall_launchd_daemon(daemon_name):
    plist_path = _get_launchd_plist_path(daemon_name)
    if not _is_launchd_daemon_installed(daemon_name):
        logger.error("launchd daemon is not installed")
        return False

    try:
        # unload the daemon first
        subprocess.run(["launchctl", "bootout", "system", plist_path], check=True)

        # remove the plist file
        os.remove(plist_path)
        logger.info("launchd daemon uninstalled successfully")
        return True
    except Exception as e:
        logger.error("error uninstalling launchd daemon: %s", str(e))
        return False


def get_launchd_daemon_status(daemon_name):
    installed = _is_launchd_daemon_installed(daemon_name)
    running = _is_launchd_daemon_running(daemon_name)

    if not installed:
        return "not-installed"
    elif installed and running:
        return "enabled"
    else:
        return "disabled"


def get_service_launchd_plist(service_name, interval=None):
    """Generate the launchd plist for the specified service"""
    if service_name == "scanner":
        plist = {
            "Label": "com.strac.auditor-scanner",
            "RunAtLoad": True,
            "StandardErrorPath": f"{LOG_PATH}/scanner.stderr.log",
            "StandardOutPath": f"{LOG_PATH}/scanner.stdout.log",
            "ProgramArguments": [
                APP_EXECUTABLE,
                "start",
                "scanner",
                "--daemon",
            ],
        }
    elif service_name == "access":
        plist = {
            "Label": "com.strac.auditor-access",
            "RunAtLoad": True,
            "StandardErrorPath": f"{LOG_PATH}/access.stderr.log",
            "StandardOutPath": f"{LOG_PATH}/access.stdout.log",
            "ProgramArguments": [
                APP_EXECUTABLE,
                "start",
                "access",
                "--daemon",
            ],
        }
    elif service_name == "network":
        plist = {
            "Label": "com.strac.auditor-network",
            "RunAtLoad": True,
            "StandardErrorPath": f"{LOG_PATH}/network.stderr.log",
            "StandardOutPath": f"{LOG_PATH}/network.stdout.log",
            "ProgramArguments": [
                APP_EXECUTABLE,
                "start",
                "network",
                "--daemon",
            ],
        }
    elif service_name == "downloads":
        plist = {
            "Label": "com.strac.auditor-downloads",
            "RunAtLoad": True,
            "StandardErrorPath": f"{LOG_PATH}/downloads.stderr.log",
            "StandardOutPath": f"{LOG_PATH}/downloads.stdout.log",
            "ProgramArguments": [
                APP_EXECUTABLE,
                "start",
                "downloads",
                "--daemon",
            ],
        }
    elif service_name == "usb":
        plist = {
            "Label": "com.strac.auditor-usb",
            "RunAtLoad": True,
            "StandardErrorPath": f"{LOG_PATH}/usb.stderr.log",
            "StandardOutPath": f"{LOG_PATH}/usb.stdout.log",
            "ProgramArguments": [
                APP_EXECUTABLE,
                "start",
                "usb",
                "--daemon",
            ],
        }
    elif service_name == "virtenv":
        plist = {
            "Label": "com.strac.auditor-virtenv",
            "RunAtLoad": True,
            "StandardErrorPath": f"{LOG_PATH}/virtenv.stderr.log",
            "StandardOutPath": f"{LOG_PATH}/virtenv.stdout.log",
            "ProgramArguments": [
                APP_EXECUTABLE,
                "start",
                "virtenv",
                "--daemon",
            ],
        }
    else:
        return None

    if interval:
        plist["StartInterval"] = interval

    return plist
