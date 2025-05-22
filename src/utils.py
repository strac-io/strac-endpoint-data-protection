import base64
import grp
import hashlib
import ipaddress
import logging
import os
import platform
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import filetype
import psutil

logger = logging.getLogger(__name__)

OS_IS_WINDOWS = os.name == "nt"
OS_IS_LINUX = sys.platform == "linux"
OS_IS_MACOS = sys.platform == "darwin"
IS_COMPILED = getattr(sys, "frozen", False)


def remove_trailing_empty_lines(lines):
    """
    Remove trailing empty lines from a list of lines.

    Args:
        lines (list): List of strings representing file lines
    Returns:
        list: Lines with trailing empty lines removed
    """
    # remove empty lines from the end
    while lines and not lines[-1].strip():
        lines.pop()

    # ensure there's a single newline at the end of the file
    if lines:
        lines.append("\n")

    return lines


def is_base64_encoded(s):
    """
    Check if a string is base64 encoded.

    Args:
        s (str): String to check

    Returns:
        bool: True if the string is base64 encoded, False otherwise

    Examples:
        >>> is_base64_encoded("aGVsbG8gd29ybGQ=")
        True
        >>> is_base64_encoded("hello world")
        False
    """
    try:
        if not re.match("^[A-Za-z0-9+/]+={0,2}$", s):
            return False
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def compute_md5(data):
    """
    Compute the MD5 hash of the given data.

    Args:
        data (bytes): Data to hash

    Returns:
        str: MD5 hash of the data

    Examples:
        >>> data = b"hello world"
        >>> compute_md5(data)
        '5eb63bbbe01eeed093cb22bb8f5acdc3'

        >>> data = b"another example"
        >>> compute_md5(data)
        'b5c0b187fe309af0f4d35982fd961d7e'
    """
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()


def check_internet_connection(host="1.1.1.1", port=53, timeout=3):
    """
    Check if there is an active internet connection.

    This function attempts to establish a connection to a specified host and port
    within a given timeout period to determine if there is an active internet connection.

    Args:
        host (str): The host to connect to. Defaults to "1.1.1.1".
        port (int): The port to connect to. Defaults to 53.
        timeout (int): The timeout period in seconds. Defaults to 3.

    Returns:
        bool: True if the connection is successful, False otherwise.

    Examples:
        >>> check_internet_connection()
        True
        >>> check_internet_connection(host="8.8.8.8", port=53, timeout=1)
        True
        >>> check_internet_connection(host="invalid.host", port=53, timeout=1)
        False
    """
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error:
        return False


def get_local_dns_cache(domain):
    """
    Retrieve the local DNS cache entry for a given domain.

    This function attempts to retrieve the IP address for a specified domain
    from the local DNS cache. It supports macOS by using the `dscacheutil` command.

    Args:
        domain (str): The domain name to look up in the local DNS cache.

    Returns:
        str or None: The IP address if found in the local DNS cache, otherwise None.
    """
    if OS_IS_MACOS:
        try:
            result = subprocess.run(
                ["dscacheutil", "-q", "host", "-a", "name", domain],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0 and result.stdout:
                # Parse the output to find IP address
                for line in result.stdout.splitlines():
                    if "ip_address" in line.lower():
                        return [
                            {
                                "ip": line.split(":")[-1].strip(),
                                "dns_server": "local_dns_cache",
                            }
                        ]
        except subprocess.SubprocessError:
            try:
                ip = socket.gethostbyname(domain)
                if ip:
                    return [{"ip": ip, "dns_server": "socket_gethostbyname"}]
            except Exception as e:
                logger.error(
                    f"error getting ip with socket.gethostbyname for {domain}: {e}"
                )
    return None


def sanitize_url(url):
    """
    Sanitize a given URL by extracting its domain.

    This function takes a URL and extracts the domain name, removing any port numbers
    and ensuring the URL has a valid protocol.

    Args:
        url (str): The URL to sanitize.

    Returns:
        str or None: The sanitized domain name if successful, otherwise None.

    Examples:
        >>> sanitize_url("https://example.com:8080/path")
        'example.com'
        >>> sanitize_url("http://subdomain.example.com")
        'subdomain.example.com'
        >>> sanitize_url("example.com/path")
        'example.com'
        >>> sanitize_url("invalid-url")
        None
    """
    try:
        # handle cases where protocol is missing/other by swapping to a dummy protocol
        if not url.startswith(("http://", "https://")):
            if "://" in url:
                url = url.split("://", 1)[-1]
            url = "http://" + url

        parsed = urlparse(url)

        # extract hostname (domain with subdomains if present)
        domain = parsed.netloc

        # remove port number if present
        domain = domain.split(":")[0]

        # sanity check
        if not domain or "." not in domain:
            return None

        return domain
    except Exception as e:
        logger.error(f"error sanitizing url {url}: {e}")
        return None


def resolve_domain(domain):
    """
    Resolve the given domain to its corresponding IP address.

    This function attempts to resolve a domain name to an IP address using multiple
    DNS servers for reliability. If one DNS server fails, it tries others before
    falling back to checking the local DNS cache.

    Args:
        domain (str): The domain name to resolve.

    Returns:
        list or None: List of dictionaries containing IP addresses and DNS servers if successful, otherwise None.
    Examples:
        >>> resolve_domain("example.com")
        [{'ip': '93.184.216.34', 'dns_server': '1.1.1.1'}]
        >>> resolve_domain("nonexistentdomain.xyz")
        None
    """
    # First sanitize the domain
    sanitized_domain = sanitize_url(domain)
    if not sanitized_domain:
        logger.error(f"Could not sanitize domain: {domain}")
        return None

    # List of DNS servers to try in order
    nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    found_ips = []

    # Try to resolve using internet DNS servers if we have connection
    if check_internet_connection():
        for nameserver in nameservers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [nameserver]
                resolver.timeout = 2  # Set a timeout of 2 seconds
                resolver.lifetime = 4  # Set a lifetime of 4 seconds

                # Attempt to resolve using the current nameserver
                answers = resolver.resolve(sanitized_domain, "A")
                for ip in answers:
                    ip_text = ip.to_text()
                    if is_valid_ip(ip_text):  # Verify it's a valid IP
                        found_ips.append({"ip": ip_text, "dns_server": nameserver})

                # If we found IPs with this nameserver, no need to try others
                if found_ips:
                    return found_ips

            except (dns.exception.DNSException, Exception) as e:
                logger.warning(
                    f"Error resolving {sanitized_domain} with {nameserver}: {e}"
                )
                continue

    # If no IPs found or no internet connection, try local DNS cache
    cached_ips = get_local_dns_cache(sanitized_domain)
    if cached_ips:
        return cached_ips

    # As a last resort, try socket.gethostbyname
    try:
        ip = socket.gethostbyname(sanitized_domain)
        if is_valid_ip(ip):
            return [{"ip": ip, "dns_server": "socket_gethostbyname"}]
    except Exception as e:
        logger.error(f"Failed to resolve {sanitized_domain} with socket: {e}")

    # No success with any method
    logger.error(f"Could not resolve domain {domain} to any IP addresses")
    return None


def is_valid_ip(address):
    """Validate if a given string is a valid IP address.

    Args:
        address (str): The IP address to validate.

    Returns:
        bool: True if valid, False otherwise.

    Examples:
        >>> is_valid_ip("192.168.1.1")
        True
        >>> is_valid_ip("256.256.256.256")
        False
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def get_group_name(gid):
    """Retrieve group name for a given group ID.

    Args:
        gid (int): Group ID to look up.

    Returns:
        str | None: Group name if found, None otherwise.

    Examples:
        >>> get_group_name(1000)
        'users'
        >>> get_group_name(99999)
        None
    """
    try:
        return grp.getgrgid(int(gid)).gr_name
    except KeyError:
        return None


def get_process_name(pid):
    """Retrieve process name for a given process ID.

    Args:
        pid (int): Process ID to look up.

    Returns:
        str | None: Process name if found, None otherwise.
    """
    try:
        return psutil.Process(int(pid)).name()
    except psutil.NoSuchProcess:
        return None


def get_file_type(file_path):
    """Determine MIME type of a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        str | None: MIME type if determined, None otherwise.
    """
    try:
        result = filetype.guess(file_path)
        return f"{result.mime}"
    except Exception:
        return None


def get_permissions(mode):
    """Convert octal file mode to string representation.

    Args:
        mode (str): Octal file mode.

    Returns:
        str: String representation of permissions.
    """
    return stat.filemode(int(mode, 8))


def parse_proctitle(proctitle):
    """Decode a process title from hexadecimal representation.

    Args:
        proctitle (str): Hexadecimal encoded process title.

    Returns:
        str: Decoded process title.
    """
    try:
        return bytes.fromhex(proctitle[2:]).decode("utf-8")
    except Exception:
        return proctitle


class System:
    """A singleton class for managing system-related operations and paths.

    This class provides methods for system information retrieval, path management,
    and various system-level operations. It follows the singleton pattern to ensure
    only one instance exists.

    Args:
        app_name (str, optional): Application name. Defaults to "auditor".
        org_identifier (str, optional): Organization identifier.
            Defaults to "com.strac.endpointsecurity".

    Attributes:
        app_name (str): Name of the application.
        org_identifier (str): Organization identifier.
        os_name (str): Operating system name.
        os_version (str): Operating system version.
        os_architecture (str): System architecture.
        os_timezone (str): System timezone.
        file_system_type (str): Type of file system.
        config_path (str): Path to configuration directory.
        asset_path (str): Path to assets directory.
        log_path (str): Path to log directory.

    Examples:
        Basic initialization:
            >>> system = System(app_name="myapp")
            >>> system.os_name
            'macOS'

        Path management:
            >>> system = System()
            >>> system.set_config_path()
            '/etc/com.strac.endpointsecurity'
            >>> system.set_log_path("/custom/log/path")
            '/custom/log/path'

        System checks:
            >>> system = System()
            >>> system.is_application_installed("git")
            True
            >>> system.is_macos_system_integrity_enabled()
            True
    """

    _instance = None

    def __new__(cls, app_name="auditor", org_identifier="com.strac.auditor"):
        if cls._instance is None:
            cls._instance = super(System, cls).__new__(cls)
            cls._instance._initialize(app_name, org_identifier)

        return cls._instance

    def _initialize(self, app_name, org_identifier):
        self.app_name = app_name
        self.org_identifier = org_identifier
        self.OS_IS_WINDOWS = OS_IS_WINDOWS
        self.OS_IS_LINUX = OS_IS_LINUX
        self.OS_IS_MACOS = OS_IS_MACOS
        self.IS_COMPILED = IS_COMPILED
        self.BLACKLISTED_USERS = ["root", "daemon", "nobody", "interlaced"]
        self.os_name = self._get_os_name()
        self.os_version = self._get_os_version()
        self.os_architecture = self._get_os_architecture()
        self.os_timezone = self._get_os_timezone()
        self.file_system_type = self._get_file_system_type()
        self.uuid = self._get_machine_id()
        self.current_user = self.get_username()
        self.user_id = self._get_unique_user_id()
        self.set_config_path()
        self.set_asset_path()
        self.set_log_path()

    def get_username(self, uid=None):
        """Retrieve username for a given user ID.

        Args:
            uid (int, optional): User ID to look up. Defaults to None.

        Returns:
            str | None: Username if found, None otherwise.

        Examples:
            >>> get_username()
            'carl'
            >>> get_username(1000)
            'john_doe'
            >>> get_username(99999)
            None
        """
        if self.OS_IS_MACOS:
            try:
                if uid is not None:
                    return pwd.getpwuid(uid).pw_name
                else:
                    console_user = (
                        os.popen("who | grep -i console | awk '{print $1}' | head -1")
                        .read()
                        .strip()
                    )
                    if console_user and console_user not in self.BLACKLISTED_USERS:
                        return console_user
                    logname = os.environ.get("LOGNAME")
                    if logname and logname not in self.BLACKLISTED_USERS:
                        return logname
                    try:
                        pw_name = pwd.getpwuid(501).pw_name
                        if pw_name and pw_name not in self.BLACKLISTED_USERS:
                            return pw_name
                    except OSError:
                        try:
                            # fall back to pwd lookup of current effective uid
                            pw_name = pwd.getpwuid(os.geteuid()).pw_name
                            if pw_name and pw_name not in self.BLACKLISTED_USERS:
                                return pw_name
                            return "employee"
                        except (KeyError, OSError):
                            return "employee"
            except Exception as e:
                logger.error(f"failed to get username for {str(uid)}: {str(e)}")
                return "employee"
        elif self.OS_IS_LINUX:
            try:
                user_id = (
                    os.getenv("USERNAME")
                    or os.getenv("USER")
                    or os.popen("who | awk '{print $1}' | head -1").read().strip()
                )
                if user_id and user_id not in self.BLACKLISTED_USERS:
                    return user_id
                return "employee"
            except Exception as e:
                logger.error(f"failed to get username: {str(e)}")
                return "employee"
        elif self.OS_IS_WINDOWS:
            try:
                import pythoncom
                import wmi

                pythoncom.CoInitialize()
                c = wmi.WMI()
                for user in c.Win32_ComputerSystem():
                    return user.UserName.split("\\")[-1]
                return os.getenv("USERNAME")
            except Exception as e:
                logger.error(f"failed to get username: {str(e)}")
                return "employee"
        else:
            return "employee"

    def get_uid(self, username):
        """Retrieve user ID for a given username.

        Args:
            username (str): Username to look up.
        Examples:
            >>> get_uid('john_doe')
            1000
            >>> get_uid('unknown_user')
            None
        """
        if self.OS_IS_MACOS or self.OS_IS_LINUX:
            try:
                if username:
                    return pwd.getpwnam(username).pw_uid
                return pwd.getpwnam(self.current_user).pw_uid
            except Exception as e:
                logger.error(f"failed to get uid for {username}: {str(e)}")
                return 501
        else:
            raise OSError("unsupported operating system")

    def _get_machine_id(self):
        """Generate a consistent unique identifier for the machine.

        Returns:
            str: A unique hardware identifier that remains constant for the same machine.

        Raises:
            subprocess.CalledProcessError: If the system command fails
            OSError: If there is an error executing the command
            IndexError: If the command output cannot be parsed
        """
        try:
            if self.OS_IS_WINDOWS:
                cmd = ["wmic", "csproduct", "get", "uuid"]
                output = subprocess.check_output(cmd, stderr=subprocess.PIPE)
                uuid = output.decode("utf-8").strip().split("\n")[1].strip()
            elif self.OS_IS_MACOS:
                cmd = ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]
                output = subprocess.check_output(cmd, stderr=subprocess.PIPE)
                uuid_line = output.decode("utf-8")
                uuid = uuid_line.split('IOPlatformUUID" = "')[1].split('"')[0]
            elif self.OS_IS_LINUX:
                # try machine-id first as it's more reliable
                try:
                    with open("/etc/machine-id") as f:
                        return f.read().strip()
                except (IOError, OSError):
                    # fall back to blkid if machine-id not available
                    cmd = ["blkid", "-o", "value", "-s", "UUID"]
                    output = subprocess.check_output(cmd, stderr=subprocess.PIPE)
                    uuid = output.decode("utf-8").strip().split("\n")[0]
            else:
                raise OSError("unsupported operating system")

            return str(uuid).lower()

        except (subprocess.CalledProcessError, OSError, IndexError) as e:
            logger.error(f"failed to get machine ID: {str(e)}")
            # generate a random uuid as a last resort
            return str(uuid.uuid4())

    def _get_unique_user_id(self, username=None):
        try:
            if username is None:
                username = self.current_user
            # concat the username and machine uuid
            hash_object = hashlib.sha256(f"{username}{self.uuid}".encode())

            hash_int = int(hash_object.hexdigest()[:10], 16)
            hash_num = hash_int % 10000000000

            return str(hash_num + 1000000000 if hash_num < 1000000000 else hash_num)
        except Exception as e:
            logger.error(f"failed to get unique user ID: {str(e)}")
            return "5150999999"

    def _get_os_name(self):
        """Retrieve the current Operating System name.

        Returns:
            str: Current Operating System name.

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM._get_os_name()
            'macOS'
        """
        try:
            if self.OS_IS_MACOS:
                os_name = "macOS"
            elif self.OS_IS_LINUX:
                os_name = platform.freedesktop_os_release()["NAME"]
            elif self.OS_IS_WINDOWS:
                os_name = "Windows"
            else:
                os_name = platform.system()
            return os_name
        except Exception as e:
            logger.error(f"failed to get OS name: {str(e)}")
            raise OSError(f"failed to get OS name: {str(e)}")

    def _get_os_version(self):
        """Retrieve the current OS version.

        Returns:
            str: Current Operating System version.

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM._get_os_version()
            '14.0.0'
        """
        try:
            if self.OS_IS_MACOS:
                os_version = platform.mac_ver()[0]
            elif self.OS_IS_LINUX:
                os_version = platform.freedesktop_os_release()["VERSION_ID"]
            else:
                os_version = platform.release()
            return os_version
        except Exception as e:
            logger.error(f"failed to get OS version: {str(e)}")
            raise OSError(f"failed to get OS version: {str(e)}")

    def _get_os_architecture(self):
        """Retrieve the current Operating System architecture.

        Returns:
            str: Current Operating System architecture.

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM._get_os_architecture()
            'x86_64'
        """
        try:
            os_arch = platform.machine()
            return os_arch
        except Exception as e:
            logger.error(f"failed to get OS architecture: {str(e)}")
            raise OSError(f"failed to get OS architecture: {str(e)}")

    def _get_os_timezone(self):
        """Retrieve the current Operating System timezone.

        Returns:
            str: Current Operating System timezone.

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM._get_os_timezone()
            'America/New_York'
        """
        try:
            os_timezone = time.tzname[0]
            return os_timezone
        except Exception as e:
            logger.error(f"failed to get OS timezone: {str(e)}")
            raise OSError(f"failed to get OS timezone: {str(e)}")

    def _get_file_system_type(self, path="/"):
        """Determine file system type for a given path.

        Args:
            path (str, optional): Path to determine file system type. Defaults to "/".
        Returns:
            str: File system type for the given path.

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM._get_file_system_type('/')
            'ext4'
            >>> SYSTEM._get_file_system_type('C:\\')
            'NTFS'
        """
        try:
            if self.OS_IS_WINDOWS:
                import win32api

                drive = os.path.splitdrive(path)[0] or path
                fs_type = win32api.GetVolumeInformation(drive)[4]
            else:
                import psutil

                fs_type = psutil.disk_partitions(all=True)[0].fstype
            return fs_type
        except Exception as e:
            logger.error(f"failed to get file system type: {str(e)}")
            raise OSError(f"failed to get file system type: {str(e)}")

    def set_config_path(self, path=""):
        """Set the configuration path for the application.

        Args:
            path (str, optional): Custom configuration path. Defaults to "".

        Returns:
            str: Configuration path for the application.

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM.set_config_path()
            '/etc/com.strac.endpointsecurity/auditor'
        """
        try:
            if self.OS_IS_MACOS:
                self.config_path = (
                    f"/Library/Application Support/{self.org_identifier}"
                    if not path
                    else path
                )
            elif self.OS_IS_LINUX:
                self.config_path = f"/etc/{self.org_identifier}" if not path else path
            elif self.OS_IS_WINDOWS:
                self.config_path = (
                    f"C:\\ProgramData\\{self.org_identifier}\\{self.app_name}\\config"
                    if not path
                    else path
                )
            else:
                self.config_path = (
                    f"/etc/{self.org_identifier}/{self.app_name}" if not path else path
                )
            os.makedirs(self.config_path, exist_ok=True)
            return self.config_path
        except Exception as e:
            logger.error(f"failed to set config path: {str(e)}")
            raise OSError(f"failed to set config path: {str(e)}")

    def set_asset_path(self, path=""):
        """Set the asset path for the application.

        Args:
            path (str, optional): Custom asset path. Defaults to "".

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM.set_asset_path()
            '/Library/Application Support/com.strac.auditor'
        """
        try:
            if self.OS_IS_MACOS:
                self.asset_path = (
                    f"/Library/Application Support/{self.org_identifier}"
                    if not path
                    else path
                )
            elif self.OS_IS_LINUX:
                self.asset_path = (
                    f"/usr/local/lib/{self.org_identifier}" if not path else path
                )
            elif self.OS_IS_WINDOWS:
                self.asset_path = (
                    f"C:\\Program Files\\{self.org_identifier}\\{self.app_name}\\assets"
                    if not path
                    else path
                )
            else:
                self.asset_path = (
                    f"/usr/local/lib/{self.org_identifier}/{self.app_name}"
                    if not path
                    else path
                )
            os.makedirs(self.asset_path, exist_ok=True)
            return self.asset_path
        except Exception as e:
            logger.error(f"failed to set asset path: {str(e)}")
            raise OSError(f"failed to set asset path: {str(e)}")

    def set_log_path(self, path=""):
        """Set the log path for the application.

        Args:
            path (str, optional): Custom log path. Defaults to "".

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM.set_log_path()
            '/Library/Logs/com.strac.auditor'
        """
        try:
            if self.OS_IS_MACOS:
                self.log_path = (
                    f"/Library/Logs/{self.org_identifier}" if not path else path
                )
            elif self.OS_IS_LINUX:
                self.log_path = f"/var/log/{self.org_identifier}" if not path else path
            elif self.OS_IS_WINDOWS:
                self.log_path = (
                    f"C:\\ProgramData\\{self.org_identifier}\\{self.app_name}\\logs"
                    if not path
                    else path
                )
            else:
                self.log_path = (
                    f"/usr/local/lib/{self.org_identifier}/{self.app_name}"
                    if not path
                    else path
                )
            os.makedirs(self.log_path, exist_ok=True)
            return self.log_path
        except Exception as e:
            logger.error(f"failed to set log path: {str(e)}")
            raise OSError(f"failed to set log path: {str(e)}")

    def is_macos_system_integrity_enabled(self):
        """Check if macOS System Integrity Protection is enabled.

        Returns:
            bool: True if enabled, False otherwise.

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM.is_macos_system_integrity_enabled()
            True
        """
        if not self.OS_IS_MACOS:
            # system integrity protection is only available on macOS
            return False
        try:
            result = subprocess.run(
                ["csrutil", "status"], capture_output=True, text=True
            )
            is_enabled = "enabled" in result.stdout.lower()
            return is_enabled
        except Exception as e:
            logger.error(
                f"failed to check System Integrity Protection status: {str(e)}"
            )
            raise OSError(
                f"failed to check System Integrity Protection status: {str(e)}"
            )

    def is_selinux_enabled(self):
        """Check if SELinux is enabled.

        Returns:
            bool: True if enabled, False otherwise.

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM.is_selinux_enabled()
            True
        """
        if not self.OS_IS_LINUX:
            # SELinux is only available on Linux
            return False
        try:
            result = subprocess.run(["sestatus"], capture_output=True, text=True)
            is_enabled = "enabled" in result.stdout.lower()
            return is_enabled
        except Exception as e:
            logger.error(f"failed to check SELinux status: {str(e)}")
            raise OSError(f"failed to check SELinux status: {str(e)}")

    def is_application_installed(self, app_name):
        """Check if an application is installed.

        Args:
            app_name (str): Name of the application.

        Returns:
            bool: True if installed, False otherwise.

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM.is_application_installed('safari')
            True
        """
        if not self.OS_IS_MACOS or not self.OS_IS_LINUX:
            return False
        try:
            is_installed = shutil.which(app_name) is not None
            return is_installed
        except Exception as e:
            logger.error(f"failed to check if {app_name} is installed: {str(e)}")
            raise OSError(f"failed to check if {app_name} is installed: {str(e)}")

    def is_temp_folder_accessible(self):
        """Check if the application's temp folder is accessible.

        Returns:
            bool: True if accessible, False otherwise.

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM.is_temp_folder_accessible()
            True
        """
        if not self.OS_IS_MACOS:
            return False

        temp_dir = os.path.expanduser(f"/Library/Logs/{self.app_name}/")
        try:
            os.makedirs(temp_dir, exist_ok=True)
            test_file = os.path.join(temp_dir, "test_write.tmp")
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
            return True
        except Exception as e:
            logger.warning(f"temp folder is not accessible: {str(e)}")
            return False

    def get_nfs_mounts(self):
        """Retrieve NFS mount points.

        Returns:
            list[str]: List of NFS mount points.

        Examples:
            >>> from config import SYSTEM
            >>> nfs_mounts = SYSTEM.get_nfs_mounts()
            >>> print(nfs_mounts)
            ['/mnt/nfs1', '/mnt/nfs2']
        """
        try:
            if self.OS_IS_WINDOWS:
                result = subprocess.run(["net", "use"], capture_output=True, text=True)
                mounts = [
                    line.split()[2]
                    for line in result.stdout.splitlines()
                    if "NFS" in line
                ]
            elif self.OS_IS_MACOS:
                result = subprocess.run(["mount"], capture_output=True, text=True)
                mounts = [
                    line.split()[2]
                    for line in result.stdout.splitlines()
                    if "nfs" in line.lower()
                ]
            else:
                with open("/proc/mounts", "r") as f:
                    mounts = [line.split()[1] for line in f if "nfs" in line]
            return mounts
        except Exception as e:
            logger.error(f"failed to get NFS mounts: {str(e)}")
            raise OSError(f"failed to get NFS mounts: {str(e)}")

    def get_usb_mounts(self):
        """Retrieve USB mount points.

        Returns:
            list[str]: List of USB mount points.

        Examples:
            >>> from config import SYSTEM
            >>> usb_mounts = SYSTEM.get_usb_mounts()
            >>> print(usb_mounts)
            ['/Volumes/USB1', '/Volumes/USB2']
        """
        try:
            if self.OS_IS_WINDOWS:
                import win32file

                drives = win32file.GetLogicalDrives()
                mounts = [
                    d
                    for d in drives
                    if win32file.GetDriveType(d) == win32file.DRIVE_REMOVABLE
                ]
            elif self.OS_IS_MACOS:
                result = subprocess.run(
                    ["diskutil", "list"], capture_output=True, text=True
                )
                mounts = [
                    line.split()[-1]
                    for line in result.stdout.splitlines()
                    if "removable" in line.lower()
                ]
            elif self.OS_IS_LINUX:
                with open("/proc/mounts", "r") as f:
                    mounts = [
                        line.split()[1]
                        for line in f
                        if "/dev/sd" in line or "/dev/usb" in line
                    ]
            else:
                with open("/proc/mounts", "r") as f:
                    mounts = [
                        line.split()[1]
                        for line in f
                        if "/dev/sd" in line or "/dev/usb" in line
                    ]
            return mounts
        except Exception as e:
            logger.error(f"failed to get USB mounts: {str(e)}")
            raise OSError(f"failed to get USB mounts: {str(e)}")

    def get_active_network_interface(self):
        """
        Retrieve the active network interface on macOS.

        Returns:
            dict: A dictionary containing the active network interface details:
                - interface (str): The name of the network interface.
                - service_name (str): The name of the network service.
                - status (str): The status of the network interface ("active").

        Examples:
            >>> from config import SYSTEM
            >>> active_interface = SYSTEM.get_active_network_interface()
            >>> print(active_interface)
            {'interface': 'en0', 'service_name': 'Wi-Fi', 'status': 'active'}
        """
        if not self.OS_IS_MACOS:
            # network interface check is only available on macOS
            return None
        try:
            # first get all network services
            cmd = ["networksetup", "-listallnetworkservices"]
            services = subprocess.check_output(cmd).decode().split("\n")
            services = [s for s in services if not s.startswith("*") and s.strip()]

            # check each service for active status
            for service in services:
                try:
                    # get IP address for service
                    cmd = ["networksetup", "-getinfo", service]
                    info = subprocess.check_output(cmd).decode()

                    # ff service has an IP address, it's active
                    if re.search(r"IP address: \d", info):
                        # get device name
                        cmd = ["networksetup", "-listallhardwareports"]
                        ports = subprocess.check_output(cmd).decode()

                        # find matching hardware port
                        for section in ports.split("\n\n"):
                            if service in section:
                                device_match = re.search(r"Device: (\w+)", section)
                                if device_match:
                                    return {
                                        "interface": device_match.group(1),
                                        "service_name": service,
                                        "status": "active",
                                    }
                except subprocess.CalledProcessError:
                    continue

            return None
        except Exception as e:
            logger.error(f"failed to get active network interface: {str(e)}")
            raise OSError(f"failed to get active network interface: {str(e)}")

    def get_configured_vpns(self, network_service=None):
        """
        Retrieve the configured VPNs for the specified network service.

        Args:
            network_service (str, optional): The name of the network service to check. If None, the active network interface will be used.

        Returns:
            list: A list of dictionaries containing VPN configuration details. Each dictionary contains:
                - name (str): The name of the network service.
                - type (str): The type of VPN (e.g., PPPoE).
                - status (str, optional): The status of the VPN (for PPPoE).
                - protocol (str, optional): The protocol used by the VPN (for other VPN types).

        Raises:
            OSError: If there is an error retrieving the VPN configurations.

        Examples:
            >>> system = System()
            >>> system.get_configured_vpns()
            [{'name': 'MyVPN', 'type': 'L2TP', 'protocol': 'L2TP over IPSec'}]

            >>> system.get_configured_vpns('MyVPNService')
            [{'name': 'MyVPNService', 'type': 'PPPoE', 'status': 'PPPoE is connected'}]
        """
        if not self.OS_IS_MACOS:
            # VPN check is only available on macOS
            return None
        try:
            if network_service is None:
                active = self.get_active_network_interface()
                if active and "service_name" in active:
                    network_service = active["service_name"]
                else:
                    return {"error": "No active network interface found"}

            vpn_configs = []
            # check if service is VPN
            try:
                cmd = ["networksetup", "-showpppoestatus", network_service]
                status = subprocess.check_output(cmd).decode().strip()
                if "PPPoE is" in status:
                    vpn_configs.append(
                        {"name": network_service, "type": "PPPoE", "status": status}
                    )
            except subprocess.CalledProcessError:
                # not a PPPoE service, check for other VPN types
                try:
                    cmd = ["scutil", "--nc", "show", network_service]
                    output = subprocess.check_output(cmd).decode()
                    if "Protocol" in output:
                        config = {
                            "name": network_service,
                            "type": re.search(r"Type\s*:\s*(.+)", output).group(1),
                            "protocol": re.search(r"Protocol\s*:\s*(.+)", output).group(
                                1
                            ),
                        }
                        vpn_configs.append(config)
                except subprocess.CalledProcessError:
                    pass

            return vpn_configs
        except Exception as e:
            logger.error(f"failed to get configured VPNs: {str(e)}")
            raise OSError(f"failed to get configured VPNs: {str(e)}")

    def get_configured_socks_proxies(self, network_service=None):
        """
        Retrieve the configured SOCKS proxies for the specified network service.

        Args:
            network_service (str, optional): The name of the network service to check. If None, the active network interface will be used.

        Returns:
            list: A list of dictionaries containing the SOCKS proxy configuration for the specified network service. Each dictionary includes:
                - interface (str): The name of the network service.
                - enabled (bool): True if the SOCKS proxy is enabled, False otherwise.
                - server (str): The SOCKS proxy server address.
                - port (str): The SOCKS proxy server port.
                - error (str, optional): An error message if no active network interface is found.

        Raises:
            OSError: If there is an error retrieving the SOCKS proxy configuration.

        Examples:
            >>> system = System()
            >>> system.get_configured_socks_proxies()
            [{'interface': 'Wi-Fi', 'enabled': True, 'server': 'proxy.example.com', 'port': '1080'}]

            >>> system.get_configured_socks_proxies("Ethernet")
            [{'interface': 'Ethernet', 'enabled': False, 'server': '', 'port': ''}]
        """
        try:
            if network_service is None:
                active = self.get_active_network_interface()
                if active and "service_name" in active:
                    network_service = active["service_name"]
                else:
                    return {"error": "No active network interface found"}

            # get SOCKS proxy settings
            try:
                cmd = ["networksetup", "-getsocksfirewallproxy", network_service]
                output = subprocess.check_output(cmd).decode()

                if "Yes" in output or "No" in output:
                    return [
                        {
                            "interface": network_service,
                            "enabled": "Yes" in output.split("\n")[0],
                            "server": re.search(r"Server: (.+)", output).group(1),
                            "port": re.search(r"Port: (.+)", output).group(1),
                        }
                    ]
                return []
            except subprocess.CalledProcessError:
                return []

        except Exception as e:
            logger.error(f"failed to get configured SOCKS proxies: {str(e)}")
            raise OSError(f"failed to get configured SOCKS proxies: {str(e)}")

    def check_vpn_status(self, vpn_name):
        """
        Check the status of a given VPN.

        Args:
            vpn_name (str): The name of the VPN to check.

        Returns:
            dict: A dictionary containing the VPN status, including:
                - name (str): The name of the VPN.
                - interface (str): The network interface associated with the VPN.
                - status (str): The status of the VPN (e.g., "Connected", "Disconnected").
                - connected (bool): True if the VPN is connected, False otherwise.
                - error (str, optional): An error message if the VPN status could not be determined.

        Raises:
            OSError: If there is an error checking the VPN status.

        Examples:
            >>> system = System()
            >>> system.check_vpn_status("MyVPN")
            {'name': 'MyVPN', 'interface': 'en0', 'status': 'Connected', 'connected': True}

            >>> system.check_vpn_status("NonExistentVPN")
            {'error': 'VPN NonExistentVPN not found on active interface'}
        """
        try:
            # first check if VPN exists
            active = self.get_active_network_interface()
            if not active or "service_name" not in active:
                return {"error": "No active network interface found"}

            vpns = self.get_configured_vpns(active["service_name"])
            vpn_exists = any(vpn["name"] == vpn_name for vpn in vpns)

            if not vpn_exists:
                return {"error": f"VPN {vpn_name} not found on active interface"}

            # check status using scutil
            cmd = ["scutil", "--nc", "status", vpn_name]
            try:
                status = subprocess.check_output(cmd).decode()
                return {
                    "name": vpn_name,
                    "interface": active["interface"],
                    "status": status.strip(),
                    "connected": "Connected" in status,
                }
            except subprocess.CalledProcessError:
                # try PPPoE status check if scutil fails
                cmd = ["networksetup", "-showpppoestatus", vpn_name]
                try:
                    status = subprocess.check_output(cmd).decode()
                    return {
                        "name": vpn_name,
                        "interface": active["interface"],
                        "type": "PPPoE",
                        "status": status.strip(),
                        "connected": "connected" in status.lower(),
                    }
                except subprocess.CalledProcessError:
                    return {"error": f"Could not get status for VPN {vpn_name}"}
        except Exception as e:
            logger.error(f"failed to check VPN status: {str(e)}")
            raise OSError(f"failed to check VPN status: {str(e)}")

    def check_socks_proxy_status(self, interface_name=None):
        """
        Check the status of the SOCKS proxy for a given network interface.

        Args:
            interface_name (str, optional): The name of the network interface to check.
                                            If None, the active network interface will be used.

        Returns:
            dict: A dictionary containing the SOCKS proxy status, including:
                - interface (str): The name of the network interface.
                - enabled (bool): Whether the SOCKS proxy is enabled.
                - server (str): The SOCKS proxy server address.
                - port (str): The SOCKS proxy server port.
                - status (str): The status of the SOCKS proxy ("active" or "inactive").
                - error (str, optional): An error message if the status could not be determined.

        Raises:
            OSError: If there is an error checking the SOCKS proxy status.

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM.check_socks_proxy_status()
            {'interface': 'Wi-Fi', 'enabled': True, 'server': '127.0.0.1', 'port': '1080', 'status': 'active'}

            >>> SYSTEM.check_socks_proxy_status('Ethernet')
            {'interface': 'Ethernet', 'enabled': False, 'server': '', 'port': '', 'status': 'inactive'}
        """
        try:
            if interface_name is None:
                active = self.get_active_network_interface()
                if active and "service_name" in active:
                    interface_name = active["service_name"]
                else:
                    return {"error": "No active network interface found"}

            # get SOCKS proxy settings
            cmd = ["networksetup", "-getsocksfirewallproxy", interface_name]
            output = subprocess.check_output(cmd).decode()

            if "Yes" in output or "No" in output:
                return {
                    "interface": interface_name,
                    "enabled": "Yes" in output.split("\n")[0],
                    "server": re.search(r"Server: (.+)", output).group(1),
                    "port": re.search(r"Port: (.+)", output).group(1),
                    "status": (
                        "active" if "Yes" in output.split("\n")[0] else "inactive"
                    ),
                }
            else:
                return {"error": f"No SOCKS proxy configured on {interface_name}"}
        except Exception as e:
            logger.error(f"failed to check SOCKS proxy status: {str(e)}")
            raise OSError(f"failed to check SOCKS proxy status: {str(e)}")

    def is_file(self, filepath):
        """
        Check if the given path points to a file and not a directory or doesn't exist.

        Args:
            filepath (str): Path to check

        Returns:
            bool: True if path is a file, False if directory or doesn't exist

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM.is_file('/path/to/document.pdf')
            True
            >>> SYSTEM.is_file('/path/to/directory')
            False
        """
        try:
            return os.path.isfile(filepath) if filepath else False
        except Exception as e:
            logger.error(f"failed to check if {filepath} is a file: {str(e)}")
            raise False

    def is_directory(self, filepath):
        """
        Check if the given path points to a directory.

        Args:
            filepath (str): Path to check

        Returns:
            bool: True if path is a directory, False if file or doesn't exist

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM.is_directory('/path/to/directory')
            True
            >>> SYSTEM.is_directory('/path/to/document.pdf')
            False
        """
        try:
            return os.path.isdir(filepath) if filepath else False
        except Exception as e:
            logger.error(f"failed to check if {filepath} is a directory: {str(e)}")
            raise False

    def get_file_name(self, filepath):
        """
        Get the filename from a filepath.

        Args:
            filepath (str): Path to extract filename from

        Returns:
            str or None: Filename if valid path, None if empty or directory path

        Examples:
            >>> from config import SYSTEM
            >>> SYSTEM.get_file_name('/path/to/document.pdf')
            'document.pdf'

            >>> SYSTEM.get_file_name('/path/to/directory/')
            None

            >>> SYSTEM.get_file_name('')
            None
        """
        potential_file_name = os.path.basename(filepath)
        if potential_file_name == "" or potential_file_name.endswith(os.path.sep):
            return None
        return potential_file_name

    def get_file_owner(self, filepath):
        """
        Get the owner username and whether it's a human user for a given file.

        Args:
            filepath (str): Path to the file to check ownership of

        Returns:
            tuple: A tuple containing:
                - str: Username of the file owner
                - bool: Whether the owner is likely a human user (True) or system user (False)

        Examples:
            >>> from config import SYSTEM
            >>> username, is_human = SYSTEM.get_file_owner('/path/to/document.pdf')
            >>> print(username)
            'csagan'
            >>> print(is_human)
            True

            >>> from config import SYSTEM
            >>> username, _ = SYSTEM.get_file_owner('/path/to/document.pdf')
            >>> print(username)
            'carl'

            >>> username, is_human = SYSTEM.get_file_owner('/usr/bin/python3')
            >>> print(username)
            'root'
            >>> print(is_human)
            False
        """
        try:
            uid = os.stat(filepath).st_uid
            username = pwd.getpwuid(uid).pw_name
            system_uid_threshold = 500 if os.uname().sysname == "Darwin" else 1000
            is_human_user = uid >= system_uid_threshold
            return username, is_human_user
        except Exception as e:
            logger.warning(f"get_file_owner filepath='{filepath}' exception='{str(e)}'")
            return "root", False
