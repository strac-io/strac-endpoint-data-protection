import logging
import os

import certifi

from utils import System

# -- GENERAL CONFIGURATION -- #
# Core application identifiers and versioning
APP_NAME = "auditor"
ORG_IDENTIFIER = f"com.strac.{APP_NAME}"
APP_VERSION = "1.5.10"
APP_EXECUTABLE = "/usr/local/bin/auditor"
SYSTEM = System(app_name=APP_NAME, org_identifier=ORG_IDENTIFIER)
ASSET_PATH = SYSTEM.set_asset_path()
DEBUG_ON = True

# -- NOTIFICATIONS CONFIGURATION -- #
NOTIFICATION_SERVICE_ENABLED = False
NOTIFICATION_ICON_URL = "https://i.ibb.co/t0qdQQb/strac-notification-small.png"
NOTIFICATION_ICON_PATH = f"{ASSET_PATH}/strac-notification-small.png"

# -- LOGGING CONFIGURATION -- #
# Logging setup with rotation policies
LOG_LEVEL = logging.DEBUG if DEBUG_ON else logging.INFO
LOG_FORMAT = "%(asctime)s - %(levelname)-5s - %(name)-20.20s - %(message)s - (%(filename)s:%(lineno)s)"
LOG_PATH = SYSTEM.set_log_path()
LOG_FILE = f"{LOG_PATH}/{APP_NAME}.log"
LOG_FILE_MAX_BYTES = 10**7  # 10 MB - Maximum size before rotation
LOG_FILE_BACKUP_COUNT = 5  # Number of backup files to maintain

# -- DATABASE CONFIGURATION -- #
# SQLite database location settings
DB_PATH = SYSTEM.set_asset_path()
DB_NAME = f"{DB_PATH}/{APP_NAME}.db"

# -- STRAC API CONFIGURATION -- #
STRAC_API_CUSTOMER = "BOGUS_CUSTOMER"
STRAC_API_KEY = "BOGUS_KEY"
STRAC_API_BASE_URL = "api.live.yourapi.com"


STRAC_API_VERIFY_SSL_CERT = certifi.where()
if not os.path.isfile(STRAC_API_VERIFY_SSL_CERT):
    STRAC_API_VERIFY_SSL_CERT = False

STRAC_API_MAX_RETRIES = 3  # maximum retry attempts for failed API calls
STRAC_API_HEADERS = {
    "x-api-key": STRAC_API_KEY,
    "clientId": "your_client_id",
}
STRAC_API_ENDPOINT_CREATE_DOCUMENT = f"https://{STRAC_API_BASE_URL}/documents"
STRAC_API_ENDPOINT_CREATE_DOCUMENT_LARGE = f"https://{STRAC_API_BASE_URL}/documents/url"
STRAC_API_ENDPOINT_DETECT = f"https://{STRAC_API_BASE_URL}/detect"
STRAC_API_ENDPOINT_PROCESS_MESSAGE = (
    f"https://{STRAC_API_BASE_URL}/endpoint-dlp/process-message"
)
STRAC_API_ENDPOINT_CONFIG = f"https://{STRAC_API_BASE_URL}/endpoint-dlp/config"
STRAC_API_DOCUMENT_SIZE_LIMIT = 6.3 * 1024 * 1024  # 6.6 MB
STRAC_API_DEVICE_ID = SYSTEM.uuid
STRAC_API_RESOURCE_TYPE = "FILE_SCAN"
STRAC_API_PUT_LOGS_RESOURCE_TYPE = "PUT_LOGS"
STRAC_API_REMEDIATION_TYPE = "DETECT"
STRAC_API_DOCUMENT_TYPE_DEFAULT = "generic"
# STRAC_API_LOGGED_IN_USER = "auditor-macos-"

# -- NETWORK MANAGER CONFIGURATION -- #
# Packet filtering and DNS settings
PF_SERVICE_ENABLED = True
PF_DNS_SERVER = "1.1.1.1"  # Cloudflare DNS server
PF_RULES_PATH = "/etc/pf.conf"  # Active packet filter rules
PF_RULES_ORIGINAL_PATH = "/etc/pf.conf.original"  # Backup of original rules
PF_BLOCKED_SITES_PATH = "/etc/pf.blocked_ips"  # File to store blocked IPs
PF_IGNORED_SITES_PATH = "/etc/pf.ignored_ips"  # File to store ignored IPs
PF_NOTIFICATIONS_ENABLED = False  # Control user notifications
PF_NOTIFICATION_MESSAGE = "Access to {website} has been blocked."
PF_IGNORE_IPS = [
    "127.0.0.1",
    "127.0.0.0",
    "127.0.0.2",
    "192.168.1.1",
    "192.168.0.1",
    "192.168.1.2",
    "192.168.0.2",
    "76.76.21.21",
]

# -- ACCESS MANAGER CONFIGURATION -- #
# System directories to exclude from monitoring
ACCESS_SERVICE_ENABLED = True
ACCESS_IGNORE_DIRECTORIES = [
    ".config",
    ".metadata-v2",
    "/Application Support/",
    "/Applications",
    "/bin",
    "/cache/morgue",
    "/dev/",
    "/etc",
    "/Frameworks",
    "/Library/",
    "/private",
    "/bin",
    "/sbin",
    "/Slack/Service Worker/",
    "/System",
    "/tmp",
    "/usr",
    "/usr/lib",
    "/usr/share",
    "/var",
    "/opt",
    ">>",
    "A/_CodeSignature",
    "A/.DS_Store",
    "A/",
    "A/AFNetworking",
    "A/AFNetworking",
    "A/AppKit",
    "A/CarbonCore",
    "A/FMDB",
    "A/Headers",
    "A/HIServices",
    "A/ISO8601DateFormatter",
    "A/LaunchServices",
    "A/Lumberjack",
    "A/MASShortcut",
    "A/PrivateHeaders",
    "A/Resources",
    "A/RMSharedPreferences",
    "A/SSZipArchive",
    "A/SVGKit",
    "A/Topee",
    "A/XPCKit",
    "AFNetworking",
    "AppleInternal",
    "B/",
    "C/",
    "C/Resources",
    "C/Topee",
    "Cache",
    "cache",
    "CacheStorage",
    "Chrome/Default/Extensions",
    "CodeSignature",
    "CoreServices",
    "default.metallib",
    "FMDB",
    "Google/Chrome",
    "HIServices",
    "LaunchServices",
    "Library",
    "MASShortcut",
    "moz-extension+++",
    "private",
    "private/var",
    "QuickLook",
    "RMSharedPreferences",
    "rpath",
    "SSZipArchive",
    "WebKit.",
    "WebKitCache",
    "XPCKit",
    "XPCServices",
]
ACCESS_IGNORE_APPS = {
    "BiomeAgent",
    "com.apple.appkit.xpc.openAn",
    "com.apple.appkit.xpc.openAndSave",
    "com.apple.quicklook.ThumbnailsAgent",
    "com.apple.safari.safebrowsing.se",
    "com.apple.Safari.SafeBrowsing.Se",
    "com.apple.SafariServices",
    "com.crowdstrike.falcon.agent",
    "Discord Helper (GPU)",
    "Discord Helper (Plugin)",
    "Discord Helper (Renderer)",
    "Discord Helper",
    "duetexpertd",
    "Finder",
    "Google Chrome Helper (GPU)",
    "Google Chrome Helper (Plugin)",
    "Google Chrome Helper (Renderer)",
    "Google Chrome Helper",
    "imagethumbnailextension",
    "knowledge-agent",
    "knowledgeconstructiond",
    "officethumbnailextension",
    "SafariAssistantWorker",
    "safaribookmarkssyncagent",
    "safarilaunchagent",
    "siriknowledged",
    "siriknowledged",
    "Slack Helper (GPU)",
    "Slack Helper (Plugin)",
    "Slack Helper (Renderer)",
    "Slack Helper",
    "spotlightknowledged",
    "Zalo Helper (GPU)",
    "Zalo Helper (Plugin)",
    "Zalo Helper (Renderer)",
    "Zalo Helper",
    "zoomupdater",
}
ACCESS_IGNORE_FILENAMES = [
    ".app",
    ".bak",
    ".bundle",
    ".bundle",
    ".crdownload",
    ".ds_store",
    ".dylib",
    ".framework",
    ".kext",
    ".ldb",
    ".localized",
    ".lock",
    ".log",
    ".Networking",
    ".plist",
    ".so",
    ".strings",
    ".swp",
    ".tmp",
    "(GPU)",
    "(Plugin)",
    "(Renderer)",
    "AppleInternal",
    "com.apple",
    "default.metallib",
    "default.metalllib",
    "Extras2.rsrc",
    "thumbs.db",
]

ACCESS_IGNORE_FILENAME_EXACT = [
    "A",
    "C",
    ".",
]

# -- SCANNER MANAGER CONFIGURATION -- #
# Plugin system settings and enabled module lists
SCANNER_SERVICE_ENABLED = False
SCANNER_SKIP_PLUGIN_REQUIREMENTS = (
    True  # Set to True to skip installing plugin requirements
)
SCANNER_PROCESSORS_PATH = "processors"
SCANNER_DETECTORS_PATH = "detectors"
# Enabled processor modules for different file types
SCANNER_ENABLED_PROCESSORS = [
    "archive_processor",
    "email_processor",
    "excel_processor",
    "gds_processor",
    "image_processor",
    "iwork_processor",
    "pdf_processor",
    "powerpoint_processor",
    "text_processor",
    "word_processor",
]
# Enabled detector modules for content analysis
SCANNER_ENABLED_DETECTORS = [
    "au_passport_detector",
    "confidential_detector",
    "dob_detector",
    "email_detector",
    "financial_account_detector",
    "iban_detector",
    "ip_detector",
    "pci_detector",
    "phone_number_detector",
    "us_drivers_license_detector",
    "us_passport_detector",
    "us_ssn_detector",
    "us_taxpayer_id_detector",
]
# File scanning settings and exclusions
SCANNER_IGNORE_FILENAMES = [
    ".",
    ".DS_Store",
    "package-lock.json",
    "package.json",
    "thumbs.db",
]
SCANNER_IGNORE_EXTENSIONS = [".tmp", ".log", ".py"]
SCANNER_MAX_FILE_SIZE_MB = 100
# File system scanning configuration
SCANNER_HOME_ROOT_PATH = "/Users"
SCANNER_IGNORE_DIRECTORIES = [
    "_",
    ".",
    ".local",
    ".localized",
    ".npm",
    "Applications (Parallels)",
    "Applications",
    "Creative Cloud Files",
    "Development",
    "Library",
    "node_modules",
    "Parallels",
    "Pictures",
    "Postman",
    "Public",
    "Scraps",
    "Shared",
    "temp",
    "Virtual Machines",
]

# -- USB MANAGER CONFIGURATION -- #
USB_SERVICE_ENABLED = False
USB_DRIVE_WHITELIST = ["Macintosh HD", "mordor", "Recovery", "System", "Time Machine"]
USB_IGNORE_FILES = [".", "zsh"]
USB_IGNORE_FOLDERS = [".", "sbin", "System"]

# -- BROWSER MANAGER CONFIGURATION -- #
BROWSER_SERVICE_ENABLED = True
BROWSER_CHROME_MACOS_HISTORY_PATH = (
    "Library/Application Support/Google/Chrome/Default/History"
)
BROWSER_CHROME_WINDOWS_HISTORY_PATH = "Google\\Chrome\\User Data\\Default\\History"
BROWSER_CHROME_LINUX_HISTORY_PATH = ".config/google-chrome/Default/History"
BROWSER_FIREFOX_MACOS_HISTORY_PATH = "Library/Application Support/Firefox/Profiles"
BROWSER_FIREFOX_WINDOWS_HISTORY_PATH = "Mozilla\\Firefox\\Profiles"
BROWSER_FIREFOX_LINUX_HISTORY_PATH = ".mozilla/firefox/Profiles"
BROWSER_SAFARI_MACOS_HISTORY_PATH = "Library/Safari/Downloads.plist"
BROWSER_SERVICE_BROWSERS_ENABLED = ["chrome", "safari"]

# -- VIRTUAL ENVIRONMENT MANAGER CONFIGURATION -- #
# Settings for monitoring browser downloads in virtual machines
VIRTENV_SERVICE_ENABLED = True
VIRTENV_CHECK_INTERVAL = 300  # 5 minutes
VIRTENV_SUPPORTED_VM_TYPES = ["vmware", "virtualbox", "parallels"]

# -- LOCAL TESTING CONFIGURATION -- #
# Development and testing paths
# TEST_PATH = "/Users/strac-test/Documents/test_files"
TEST_PATH = "/Users/strac/Development/strac/auditor/assets/test_files"
TEST_FILE = f"{TEST_PATH}/test_image_8.tiff"
