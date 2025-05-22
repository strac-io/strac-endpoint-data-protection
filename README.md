# Auditor

`auditor` is plugin-based, cross-platform service application designed to audit and process sensitive files and actions on customer managed workstations. The application is customizable via the addition of managers, processors, and detectors. Its modular architecture allows for the seamless integration of new functionalities, making it adaptable to a wide range of use cases in file analysis and security auditing.

> [!IMPORTANT]  
> As of 2025-05-22, the Strac Endpoint Agent repository has been made public. 

## Table of contents

- [Auditor](#auditor)
  - [Architecture](#architecture)
  - [Usage](#usage)
    - [Command Line Interface](#command-line-interface)
    - [Example Usage](#example-usage)
  - [Local Development & Packaging](#local-development--packaging)
    - [macOS Developer Setup](#macos-developer-setup)
      - [Setup 1Password](#setup-1password)
    - [Linux Setup](#linux-setup)
  - [Packaging Auditor](#packaging-auditor)
    - [Versioning](#versioning)
    - [Importing macOS Signing Certificates](#importing-macos-signing-certificates)
    - [Building macOS Installer Packages](#building-macos-installer-packages)
    - [Directory Structure](#directory-structure)
    - [Other Development Info](#other-development-info)
      - [Compiler Tools](#compiler-tools)
      - [Packaging Tools](#packaging-tools)
      - [Binary Optimization](#binary-optimization)
      - [Profiling Auditor](#profiling-auditor)
    - [Manually Signing and Notarizing a macOS Installer](#manually-signing-and-notarizing-a-macos-installer)
      - [Prerequisites](#prerequisites)
      - [Get certificates](#get-certificates)
      - [Create entitlements file](#create-entitlements-file)
      - [Sign the binary](#sign-the-binary)
      - [Create package](#create-package)
        - [With postinstall script](#with-postinstall-script)
        - [Without postinstall script](#without-postinstall-script)
      - [Productbuild](#productbuild)
      - [Notarize and Staple](#notarize-and-staple)
  - [Auditor Components](#auditor-components)
    - [Managers](#managers)
    - [Processors](#processors)
    - [Detectors](#detectors)
  - [Configuration](#configuration)
    - [Scanner Manager Plugin Configuration](#scanner-manager-plugin-configuration)
    - [Scanner Manager File Extension Configuration](#scanner-manager-file-extension-configuration)
    - [Scanner Manager Ignoring Directories, Filenames, and Extensions](#scanner-manager-ignoring-directories-filenames-and-extensions)
    - [Strac API Configuration](#strac-api-configuration)
  - [Extending Auditor](#extending-auditor)
    - [Creating New Components](#creating-new-components)
      - [Creating a Manager](#creating-a-manager)
      - [Creating a Processor](#creating-a-processor)
      - [Creating a Detector](#creating-a-detector)
    - [Integrating New Scanner Components](#integrating-new-scanner-components)
    - [Integrating New Access Manager Components](#integrating-new-access-manager-components)
  - [Future Work](#future-work)
    - [Running as a Background Service](#running-as-a-background-service)
      - [Linux (_systemd_)](#linux-_systemd_)
      - [macOS (_launchd_)](#macos-_launchd_)
    - [Tagging Releases and Storing Them in GitHub](#tagging-releases-and-storing-them-in-github)

## Architecture

The architecture of `auditor` revolves around three main component types:

- **Managers**: Orchestrate the overall workflow and lifecycle of the application. They manage resources, coordinate tasks, and facilitate communication between components.

- **Processors**: Handle file parsing and data extraction. Each processor is responsible for processing specific file types or formats, converting them into a standardized format for analysis.

- **Detectors**: Analyze the processed data to detect specific patterns, conditions, or anomalies. Detectors implement the logic for identifying sensitive information, security threats, or other defined criteria.

There are two main local storage mechanisms for the application, both of which are located in operating system specific directories. Both files can be cleaned by running `sudo auditor reset`:

- **SQLite**: Used for queueing, records management, and other stateful data. This file is managed by the ORM abstractions in `src/storage/database.py` and should not be modified directly. The database configuration settings are all prefixed with `DB_`.

- **Log Files**: Used for detailed debugging logs. Currently this means that the logs also show line numbers and file names. This should be modified if this is undesirable to have on a customer machine. The logging configuration settings are all prefixed with `LOG_`.


## Usage

Auditor is designed to be run interactively by a `superuser` or non-interactively by `root`, and is installed on the hosts executable path (`/usr/local/bin/auditor`). Once installed, it's respective services can be interacted with via the `auditor` command line interface.

### Command Line Interface

The currently available CLI commands and their options:

| Command | Options | Description |
|---------|---------|-------------|
| `start` | `scanner`, `access`, `network`, `browser`, `usb` | Start a specific service |
| `stop` | `scanner`, `access`, `network`, `browser`, `usb` | Stop a specific service |
| `restart` | `scanner`, `access`, `network`, `browser`, `usb` | Restart a specific service |
| `status` | `scanner`, `access`, `network`, `browser`, `usb` | Get status of a specific service |
| `uninstall` | - | Uninstall local installation |
| `show` | `config`, `logs`, `system` | Show configuration or logs |
| `reset` | - | Reset local installation |
| `version` | - | Show version |

Notes:
- all commands must be run with `sudo` privileges
- `scanner` and `network` services currently show an invalid license error message as they are `noop`
- `show config` displays all *safe to show* configuration values
- `show logs` displays the last 120 lines of the local log file
- `show system` displays the a few values of the current host system
- `reset` will remove all data and reset the application to a clean state
- `uninstall` will remove data and uninstall the application completely

### Example Usage

After installing the **auditor** application from a Strac built `.pkg`, you can use the following commands to start and stop the services:

> [!TIP]
> You can enable DEBUG logs by setting the `AUDITOR_DEBUG` environment variable to `true`.

Start the browser service:
```bash
sudo auditor start browser
```

Start the access service:
```bash
sudo auditor start access
```

Stop the access service:
```bash
sudo auditor stop access
```

Show the current configuration:
```bash
sudo auditor show config
```

Show the help menu:
```bash
sudo auditor --help
```

## Local Development & Packaging

### macOS Developer Setup

```bash
# Install python3.12 from the Python.org website

# download the installer to your desktop
curl -o ~/Desktop/python-3.12.10-macos11.pkg https://www.python.org/ftp/python/3.12.10/python-3.12.10-macos11.pkg

# run the installer and check all options
open ~/Desktop/python-3.12.10-macos11.pkg

# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Reload your shell after Homebrew install
exec zsh

# Install binary requirements
brew install poppler upx openblas gcc ruby git most wget nano 1password-cli 1password bat

# Add Ruby to the path
echo 'export GEM_HOME=~/.ruby' >> ~/.bashrc
echo 'export PATH=~/.ruby/bin:$PATH' >> ~/.bashrc
echo 'export PATH="/usr/local/opt/ruby/bin:$PATH"' >> ~/.zshrc

source ~/.bashrc

# Install fpm via ruby gem - DO NOT use brew install fpm as it installs something else
gem install fpm

# Clone the Auditor repository
git clone https://github.com/strac-io/auditor.git
cd auditor

# Create a local virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate

# Install the required packages into the virtual environment
python3 -m pip install -r requirements-dev.txt

# Confirm the version of the application
cd src
sudo python3 cli.py version
```

#### Setup 1Password

Install the 1Password CLI and then follow [these instructions](https://developer.1password.com/docs/cli/get-started/#step-1-install-1password-cli) to setup the 1Password CLI.

```bash
# Install 1Password CLI
brew install 1password-cli
```

### Linux Setup

```bash
# Install binary requirements
sudo apt-get install python3 upx gcc ruby poppler-utils libopenblas-dev qhull-dev libqhull-dev unrar

# Install fpm via ruby gem - DO NOT use apt install fpm as it installs something else
mkdir ~/.ruby

echo 'export GEM_HOME=~/.ruby' >> ~/.bashrc
echo 'export PATH=~/.ruby/bin:$PATH' >> ~/.bashrc

source ~/.bashrc

gem install fpm

sudo cp -Rf ~/.ruby/bin/fpm /usr/local/bin/fpm

# Clone the Auditor repository (if not already done)
# git clone https://github.com/strac-io/auditor.git
# cd auditor

# Create a local virtual environment (if not already done)
# python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate

# Update pip
python3 -m pip install --compile --no-cache-dir -U pip

# Install the required packages into the virtual environment
python3 -m pip install --compile --no-cache-dir -r requirements-dev.txt

# Confirm the version of the application
cd src
sudo python3 cli.py version
```

### macOS Developer Setup
```bash
# Install python3.12 from the Python.org website

# download the installer to your desktop
curl -o ~/Desktop/python-3.12.9-macos11.pkg https://www.python.org/ftp/python/3.12.9/python-3.12.9-macos11.pkg

# run the installer and check all options
open ~/Desktop/python-3.12.9-macos11.pkg

#
```

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Reload your shell after Homebrew install
exec zsh

# Install binary requirements
brew install poppler upx openblas gcc ruby

# Install fpm via ruby gem - DO NOT use brew install fpm as it installs something else
gem install fpm

# Clone the Auditor repository
git clone https://github.com/strac-io/auditor.git
cd auditor

# Create a local virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate

# Install the required packages into the virtual environment
python3 -m pip install -r requirements-dev.txt

# Confirm the version of the application
cd src
sudo python3 cli.py version
```
#### Setup 1Password

Install the 1Password CLI and then follow [these instructions](https://developer.1password.com/docs/cli/get-started/#step-1-install-1password-cli) to setup the 1Password CLI.

```bash
# Install 1Password CLI
brew install 1password-cli
```

## Packaging Auditor

### Versioning

Versioning is handled automatically with the `make bump-version` command. This command increments the patch version number inside the `.version` file and replaces the `config.py` value with the same value. To adjust the build version, edit the `.version` file directly, not the `config.py` file. it should only be run once per release, not once per architecture.

### Importing macOS Signing Certificates

Importing the macOS signing certificates is handled with the `make import-macos-certificates` command. This command will fetch the certificates from the `auditor-secrets` vault using the 1Password CLI and import them into your local `login` keychain. You will need to have the [1Password CLI installed and configured](#setup-1password) to use this command.

> [!NOTE]
> You will only need to run this command once per machine.

### Building macOS Installer Packages

The building of macOS **auditor** insatller packages is handled with the `make` command. The following commands should be used on an arm64 machine to produce `arm64` macOS installers and on an x86_64 machine to produce `x86_64` macOS installers. Note that you will need to have the [1Password CLI installed and configured](#setup-1password) to use these commands.

```bash
# enter the root directory of the auditor repository
cd auditor

# activate the arm64 virtual environment
source .venv/bin/activate

# increment the version number
make bump-version

# build the installers. Replace "clientA" with the customer name you want to use. CUSTOMER will default to "test" if not specified
make CUSTOMER="clientA" arm-macos-installers

# deactivate the virtual environment
deactivate
```

### Directory Structure

- `build/` - Temporary build artifacts
- `dist/` - Final distributable packages and executables
  - `pyinstaller/` - PyInstaller outputs
- `assets/` - Additional assets used for the installer
  - `pkgbuild/` - macOS installer assets (e.g. `entitlements.plist`)
  - `customer_scripts/` - Customer specific *pre* and *post* install scripts (e.g. `clientA`)

> [!NOTE]
> The `customer_scripts` directory contains customer specific *pre* and *post* install scripts that specify what should happen when the installer is run. These scripts are used to customize the installer for the customer and to startup speicifc `auditor` managers, automatically. These scripts are only installed and executed in the **MDM** installer.

### Other Development Info

#### Compiler Tools

- **[PyInstaller](https://pyinstaller.org/en/stable/)** - Bundles Python applications into standalone executables. Known for its straightforward approach and broad compatibility across different operating systems.

#### Packaging Tools

- **macOS**: [pkgbuild](https://www.manpagez.com/man/1/pkgbuild/) - Creates native `.pkg` installers
- **Linux**: [fpm](https://fpm.readthedocs.io/) - Simplifies creation of `.deb` and `.rpm` packages (implementation pending)

#### Binary Optimization

[UPX](https://upx.github.io/) is utilized to compress the resulting executable. It reduce the overall file size and improves load times.

### Manually Signing and Notarizing a macOS Installer

The signing and notarization process is fully automated and does not need to be run manually. The following docs are provided for reference only.

#### Prerequisites

- apple developer admin account (*see your apple developer account admin*)
- xcode installed
- strac's "Developer ID Application" certificate from developer.apple.com (*see your apple developer account*)
- a **PyInstaller** built binary

#### Get certificates

```bash
# 1. create Certificate Signing Request in Keychain Access
# 2. download Developer ID Application certificate from developer.apple.com
# 3. install certificate to Keychain
```

#### Create entitlements file

This should already be in `./assets/pkgbuild/entitlements.plist`, but if not, here's the template:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <!-- required for binaries built by PyInstaller -->
        <key>com.apple.security.cs.allow-jit</key>
        <true/>
        <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
        <true/>
        <key>com.apple.security.cs.disable-library-validation</key>
        <true/>
</dict>
</plist>
```

#### Sign the binary

```bash
codesign --force --timestamp --sign "F80534528D879A29E0222B68355E0848BD709CCA" --entitlements ./assets/pkgbuild/entitlements.plist --options runtime ./dist/pyinstaller/auditor-X.X.X-ARCH/auditor
```

#### Create package

##### With postinstall script

This includes a macOS compatible bash script that installs `launchd` daemons for both the `access` and `uploads` managers. This script is run immediately after success installation and also kickstarts both managers.

```bash
pkgbuild --root ./dist/pyinstaller/auditor-X.X.X-ARCH/auditor \
  --scripts assets/pkgbuild/Scripts \
  --identifier "com.strac.auditor" \
  --version "1.0" \
  --install-location "/Applications" \
  --sign "0EDE190D1910FDCD363710B46E85A439DBD6E06E" \
  auditor-X.X.X-ARCH.pkg
```

##### Without postinstall script

```bash
pkgbuild --root ./dist/pyinstaller/auditor-X.X.X-ARCH/auditor \
  --identifier "com.strac.auditor" \
  --version "1.0" \
  --install-location "/Applications" \
  --sign "0EDE190D1910FDCD363710B46E85A439DBD6E06E" \
  auditor-X.X.X-ARCH.pkg
```

#### Productbuild

```bash
productbuild --sign "Developer ID Installer: Strac Incorporated (992GD587TM)" --package auditor-X.X.X-ARCH.pkg auditor-X.X.X-ARCH-READY.pkg
```

#### Notarize and Staple

```bash
# cleanup pkgs
rm -rf auditor-X.X.X-ARCH.pkg
mv auditor-X.X.X-ARCH-READY.pkg auditor-X.X.X-ARCH.pkg

# submit for notarization and wait for completion
xcrun notarytool submit auditor-X.X.X-ARCH.pkg --keychain-profile "notary-strac.io" --wait

# staple the notarization
xcrun stapler staple auditor-X.X.X-ARCH.pkg

# verify the notarization
xcrun stapler validate auditor-X.X.X-ARCH.pkg
```
#### Migrating macOS Signing Certificates

1. Export the existing certificates from your local keychain:
```bash
# export the Developer ID Application certificate
security export -k login.keychain -t identities -f pkcs12 -P "YOUR_PASSWORD" -o developer_id_app.p12 "Developer ID Application: Strac Incorporated (992GD587TM)"

# export the Developer ID Installer certificate
security export -k login.keychain -t identities -f pkcs12 -P "YOUR_PASSWORD" -o developer_id_installer.p12 "Developer ID Installer: Strac Incorporated (992GD587TM)"
```

2. Zip up the certificates and transfer the newly exported`.p12` files to their new destination machine using a secure method (*like AirDrop, secure file transfer, or private network share*).

3. Import the certificates into the keychain on the new machine:
```bash
# Import Developer ID Application certificate
security import developer_id_app.p12 -k login.keychain -P "YOUR_PASSWORD" -T /usr/bin/codesign

# Import Developer ID Installer certificate
security import developer_id_installer.p12 -k login.keychain -P "YOUR_PASSWORD" -T /usr/bin/productbuild
```
4. Setup the notarization profile on the new machine:
> [!NOTE]
> You will need to retrieve the `apple-id`, `team-id`, and `password` from the `auditor-secrets` 1Password Vault.

```bash
xcrun notarytool store-credentials "notary-strac.io" --apple-id "SOME_ID" --team-id "SOME_ID" --password "SOME_PASSWORD"
```

5. Verify the certificates and profile are setup correctly:
```bash
# List certificates to confirm they're properly imported
security find-identity -v -p codesigning
```

## Auditor Components

### Managers

Managers are responsible for orchestrating the processing workflow. They coordinate the operations of processors and detectors, manage systems application execution, tasks and resources, and ensure efficient execution of their respective pipelines.

**Available Managers:**

| Manager           | Description                                                                                   |
|-------------------|-----------------------------------------------------------------------------------------------|
| **Access_Manager** | Manages system call access monitoring, including file monitoring and application execution    |
| **Browser_Manager** | Manages browser download activity monitoring and detection                                   |
| **Network_Manager** | Manages website blocking rules and the packet filtering service                              |
| **Scanner_Manager** | Manages the file scanning processes, including sensitive data detection, queuing, and processing |
| **USB__Manager** | Manages the USB drive mount scanner |

### Processors

Processors parse and extract data from various file types. Each processor is designed to handle a specific file format, converting the raw data into a format suitable for analysis by detectors.

**Available Processors:**

| Processor            | Description                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------|
| **Archive_Processor** | Handles compressed archives (`.zip`, `.rar`, `.7z`) and processes their contents                   |
| **Email_Processor**   | Parses email files and extracts message contents (`.eml`, `.msg`)                                |
| **Excel_Processor**   | Processes Microsoft Excel files (`.xls`, `.xlsx`)                                                |
| **GDS_Processor**     | Processes schematic files (`.gds`, `.gdsii`, `.oas`)                                               |
| **Image_Processor**   | Handles image files, extracting text via OCR when necessary (`.png`, `.jpg`, `.jpeg`, `.tiff`, `.gif`, `.bmp`, `.webp`) |
| **iWork_Processor**   | Extracts text from iWork documents (`.pages`, `.numbers`, `.keynote`)                              |
| **PDF_Processor**     | Extracts text and metadata from PDF files (`.pdf`)                                             |
| **PowerPoint_Processor** | Extracts content from PowerPoint presentations (`.ppt`, `.pptx`)                              |
| **Text_Processor**    | Processes plain text files, including CSV, JSON, YAML, and more (`.txt`, `.csv`, `.json`, `.yaml`, `.yml`) |
| **Word_Processor**    | Extracts text from Microsoft Word documents (`.doc`, `.docx`)                                    |

### Detectors

Detectors analyze the processed content to identify specific patterns, sensitive information, or anomalies. They apply detection logic such as pattern matching, keyword search, and content classification.

**Available Detectors:**

| Detector | Description |
|----------|-------------|
| **Confidential_Detector** | Identifies confidential or sensitive information |
| **DOB_Detector** | Identifies Date of Birth |
| **Email_Detector** | Identifies email addresses and patterns |
| **Financial_Detector** | Identifies financial data and patterns |
| **IBAN_Detector** | Identifies International Bank Account Numbers (IBANs) |
| **IN_AADHAR_Detector** | Identifies Indian AADHAAR numbers |
| **IN_NREGA_Detector** | Identifies Indian NREGA numbers |
| **IP_Detector** | Identifies IP addresses and patterns |
| **PCI_Detector** | Detects Payment Card Industry-related sensitive data |
| **Phone_Number_Detector** | Identifies phone numbers and patterns |
| **UK_NHS_Detector** | Identifies United Kingdom National Health Service (NHS) numbers |
| **UK_NINO_Detector** | Identifies United Kingdom National Insurance Number (NINO) numbers |
| **UK_UTR_Detector** | Identifies United Kingdom Unique Taxpayer Reference (UTR) numbers |
| **US_Driver_License_Detector** | Identifies United States Driver License numbers |
| **US_License_Plate_Detector** | Identifies United States License Plate numbers |
| **US_Passport_Detector** | Identifies United States Passport numbers |
| **US_SSN_Detector** | Detects United States Social Security Number (SSN) patterns |
| **US_Taxpayer_ID_Detector** | Identifies United States Taxpayer Identification Number (TIN) numbers |
| **VIN_Detector** | Identifies Vehicle Identification Numbers (VINs) |

## Configuration

Auditor's behavior can be customized through the `config.py` file and other configuration settings. This allows users to enable or disable components, set specific processing parameters, and adjust the application's operation to suit different environments and requirements.

**TODO**: Add configuration sync with the Strac API.

### Scanner Manager Plugin Configuration

To configure which plugins are loaded for the Scanner Manager:

- **Enable or disable plugin requirements installation**: This is controlled by the `SCANNER_SKIP_PLUGIN_REQUIREMENTS` flag in the `config.py` file. Setting it to `False` ensures that the required dependencies for each plugin are installed.

```python
SCANNER_SKIP_PLUGIN_REQUIREMENTS = False  # Set to True to skip installing plugin requirements
```

- **Enable or disable specific processors or detectors**: Modify the `SCANNER_ENABLED_PROCESSORS` and `SCANNER_ENABLED_DETECTORS` lists in the `config.py` file to include only the plugins you want to load.

```python
# Enabled processor modules for different file types
SCANNER_ENABLED_PROCESSORS = [
    "pdf_processor",
    "archive_processor",
    "text_processor",
    "word_processor",
    "excel_processor",
    "powerpoint_processor",
    "image_processor",
    "email_processor",
]

# Enabled detector modules for content analysis
SCANNER_ENABLED_DETECTORS = [
    "pci_detector",
    "confidential_detector",
    "pattern_detector",
    "keyword_detector",
]
```

### Scanner Manager File Extension Configuration

Each processor defines the file extensions it supports. To configure file extensions for processors:

- **Modify the `supported_extensions` attribute** in the processor's class.

For example, to add support for `.md` files in the `Text_Processor`:

```python
class Processor:
    # ...
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
```

### Scanner Manager Ignoring Directories, Filenames, and Extensions

To configure directories, filenames, or file extensions to ignore during scanning, modify the following settings in the `config.py` file:

```python
# Directories to ignore during scanning
SCANNER_IGNORE_DIRECTORIES = [
    "_",
    ".",
    "Shared",
    "node_modules",
    "Pictures",
    "Applications",
    "Library",
]

# Filenames to ignore
SCANNER_IGNORE_FILENAMES = ["thumbs.db", ".ds_store", "package.json"]

# File extensions to ignore
SCANNER_IGNORE_EXTENSIONS = [".tmp", ".log", ".py"]
```

### Strac API Configuration

To configure the Strac API settings, including the Customers API key and related parameters, update the relevant fields in the `config.py` file:

```python
STRAC_API_KEY = "YOUR_API_KEY_HERE"  # Replace with your actual API key
STRAC_API_HEADERS = {
    "x-api-key": STRAC_API_KEY,
    "clientId": "your_client_id",
}
STRAC_API_BASE_URL = "https://api.test.yourapi.com"
STRAC_API_ENDPOINT_CREATE_DOCUMENT = f"{STRAC_API_BASE_URL}/documents"
STRAC_API_ENDPOINT_CREATE_DOCUMENT_LARGE = f"{STRAC_API_BASE_URL}/documents/url"
STRAC_API_ENDPOINT_DETECT = f"{STRAC_API_BASE_URL}/detect"
STRAC_API_ENDPOINT_PROCESS_MESSAGE = f"{STRAC_API_BASE_URL}/endpoint-dlp/process-message"
STRAC_API_ENDPOINT_CONFIG = f"{STRAC_API_BASE_URL}/endpoint-dlp/config"
STRAC_API_DOCUMENT_SIZE_LIMIT = 6.3 * 1024 * 1024  # 6.3 MB
```

**Note**: Ensure that you securely handle your `STRAC_API_KEY`. Do not hardcode sensitive information in your configuration files if they are part of version control. Consider using environment variables or a secure secrets management system.

## Extending Auditor

Adding functionality to `auditor` can be done by creating new managers, processors, or detectors. The following sections provide guidance and examples on how to develop and integrate new components.

### Creating New Components

#### Creating a Manager

To create a new manager, there is no current base manager class to inherit from nor is there a contract that is needed to be met. Implement the methods required for your custom needs:

```python
import logging
class CustomManager:
    def __init__(self):
        self.logger = logging.getLogger("manager-custom")

    def start(self):
        # Startup code if needed
        pass

    def process(self, data):
        # Processing logic if needed
        pass
```

#### Creating a Processor

To develop a new processor:

1. Create a new directory under `src/processors` with the name of your processor (e.g., `custom_processor`).
2. Within this directory, create an `__init__.py` file and your processor implementation file (e.g., `custom_processor.py`).
3. Inherit from the base `Processor` class and implement the necessary methods.

Example:

```python
import logging

class Processor:
    name = "Custom Processor"
    version = "1.0"
    supported_extensions = [".custom"]

    def __init__(self):
        self.logger = logging.getLogger("processor-custom")

    async def process_file_async(self, file_path, scanner):
        # Asynchronous processing logic
        pass

    def process_file(self, file_path, scanner):
        # Synchronous processing logic
        pass
```

#### Creating a Detector

To create a new detector:

1. Create a new directory under `src/detectors` with the name of your detector (e.g., `custom_detector`).
2. Within this directory, create an empty `__init__.py` file, your detector implementation file (e.g., `custom_detector.py`), and a `requirements.txt` file.
3. Inherit from the base `Detector` class and implement the required methods.

Example:

```python
import logging

class Detector:
    description = "Custom Detector" # include a brief description of this detector
    version = "1.0" # include the version of this detector

    def __init__(self):
        self.name = "detector-custom" # include the name of this detector in this format
        self.logger = logging.getLogger(self.name)

    async def process_text(self, text_content):
        # Detection logic
        findings = []
        # Analyze text_content and populate findings
        return findings
```

```python
some-package==1.2.3
some-other-package==3.2.1
```

### Integrating New Scanner Components

After creating new components:

1. **Register the component** by adding it to the appropriate enabled list in `config.py`.

```python
SCANNER_ENABLED_PROCESSORS = [
    # Existing processors
    "custom_processor",  # Add your new processor
]

SCANNER_ENABLED_DETECTORS = [
    # Existing detectors
    "custom_detector",  # Add your new detector
]
```

2. **Install any required dependencies** by adding them to a `requirements.txt` file inside your component's directory.

For example, if your processor requires `somepackage`:

```text
somepackage==1.2.3
```

3. **Ensure the application installs plugin requirements** by setting `SCANNER_SKIP_PLUGIN_REQUIREMENTS` to `False` in `config.py`.

### Integrating New Access Manager Components

After creating your new Manager:

1. **Integrate with the CLI** by adding your new manager to `config.py` and creating the appropriate cli commands.

## Future Work

### Running as a Background Service

The following sections outline the steps to run `auditor` as a background service on Linux and macOS. They should be implemented if `auditor` is to be run as a background service (*i.e. not interactively/headless*).

#### Linux (_systemd_)

1. Copy the service file to the `systemd` directory:

```bash
sudo cp dist/auditor.service /etc/systemd/system/
```

2. Reload `systemd` and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable auditor
sudo systemctl start auditor
```

**Example `auditor.service` file:**

```ini
[Unit]
Description=Auditor Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/auditor
Restart=always
RestartSec=42s

[Install]
WantedBy=multi-user.target
```

#### macOS (_launchd_)

This has ben implemented in `cli.py` and as a `postinstall` script for kickstarting the acess manager and the downloads manager only. This implementation is specific to the clientB customer and needs to be revisited for a more generic implementation.

### Tagging Releases and Storing Them in GitHub

This is likely where we want to be creating and storing our releases as a first step, prior to sharing with customers.

1. Tagging a Release:

   To tag a new release, use the following command in your terminal:

   ```bash
   git tag -a vX.Y.Z -m "Release version X.Y.Z"
   ```

   Replace `X.Y.Z` with the version number you are releasing. The `-m` flag allows you to add a message to the tag.

2. Pushing the Tag to GitHub:

   After creating the tag, push it to the GitHub repository:

   ```bash
   git push origin vX.Y.Z
   ```

3. Creating a Release on GitHub:

   - Go to your repository on GitHub.
   - Click on the ["Releases"](https://github.com/strac-io/auditor/releases/) tab.
   - Click the "**Draft a new release**" button.
   - In the "**Tag version**" dropdown, select the tag you just pushed (e.g., `vX.Y.Z`).
   - Fill in the release title and description.
   - Use the "**Attach binaries by dropping them here or selecting them**" section to upload the `auditor` installers.
   - Click the "**Publish release**" button.