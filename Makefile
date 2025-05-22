# general
APP_NAME := auditor
VERSION_FILE = .version
VERSION := $(shell cat $(VERSION_FILE) 2>/dev/null || echo "0.1.0")
DEVELOPER_ID_APPLICATION := "APPLE_DEVELOPER_ID_APPLICATION"
DEVELOPER_ID_APPLICATION_FULL := "Developer ID Application: $(DEVELOPER_ID_APPLICATION)"
DEVELOPER_ID_INSTALLER := "APPLE_DEVELOPER_ID_INSTALLER"
DEVELOPER_ID_INSTALLER_FULL := "Developer ID Installer: $(DEVELOPER_ID_INSTALLER)"
APPLE_DISTRIBUTION_CERTIFICATE := "APPLE_DISTRIBUTION_CERTIFICATE"
THIRD_PARTY_MAC_DEVELOPER_INSTALLER := "THIRD_PARTY_MAC_DEVELOPER_INSTALLER"

# working directories
BUILD_DIR := build
DIST_DIR := dist
SRC_DIR := src
ENTRY_POINT := cli.py

# tools
PYTHON := python3
PYINSTALLER := PyInstaller
UPX := /opt/homebrew/bin/upx
CX_FREEZE := cx_Freeze
NUITKA := nuitka
NUITKA_FLAGS = --follow-imports --standalone --onefile --plugin-enable=upx --upx-binary=$(UPX)
PKGBUILD := /usr/bin/pkgbuild
FPM := fpm

UNAME_S := $(shell uname -s)
check-dir = $(if $(wildcard $1),$1,$2)
PYTHON_ARM64 := .venv/bin/python3
PYTHON_X86_64 := .venv/bin/python3
ARCH_ARM64 := arm64
ARCH_X86_64 := x86_64
CUSTOMER ?= test
STRAC_API_KEY = ""
STRAC_API_BASE_URL = ""
SCRIPTS_DIR = "assets/pkgbuild/customer_scripts/$(CUSTOMER)"

# linux package formats
DEB_FORMAT := deb
RPM_FORMAT := rpm
LINUX_PREFIX := /usr/local/bin

ifeq ($(UNAME_S),Darwin)
    SED_CMD := sed -i ''
    PYTHON_ARM64 := .venv/bin/python3
    PYTHON_X86_64 := .venv/bin/python3
else
    SED_CMD := sed -i
    PYTHON_ARM64 := python3
    PYTHON_X86_64 := python3
endif

#  ██╗  ██╗ ██████╗ ██╗    ██╗   ████████╗ ██████╗ 
#  ██║  ██║██╔═══██╗██║    ██║   ╚══██╔══╝██╔═══██╗
#  ███████║██║   ██║██║ █╗ ██║█████╗██║   ██║   ██║
#  ██╔══██║██║   ██║██║███╗██║╚════╝██║   ██║   ██║
#  ██║  ██║╚██████╔╝╚███╔███╔╝      ██║   ╚██████╔╝
#  ╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝       ╚═╝    ╚═════╝ 
#                                                  
#   - this is the new way to build the installers
#
#	cd auditor/
#	# ----- activate the arm64 virtual environment -----
#	source .venv/bin/activate
#	make bump-version # only run this once so that the versions stay the same across the two architectures
#	# CUSTOMER is the 1password 'auditor-secrets' vault key name. this will default to 'test' if no CUSTOMER is specified
#	make CUSTOMER="clientA" arm-macos-installers 
#	cp dist/auditor-*.pkg ~/Desktop/
#	deactivate;
#	# ----- activate the x86_64/intel virtual environment -----
#	# CUSTOMER is the 1password 'auditor-secrets' vault key name. this will default to 'test' if no CUSTOMER is specified
#	make CUSTOMER="clientB" intel-macos-installers 
#	cp dist/auditor-*.pkg ~/Desktop/
#	deactivate;
#
#  ▗▖  ▗▖ ▗▄▖ ▗▄▄▄▖▗▖  ▗▖    ▗▄▄▄▖▗▄▖ ▗▄▄▖  ▗▄▄▖▗▄▄▄▖▗▄▄▄▖▗▄▄▖
#  ▐▛▚▞▜▌▐▌ ▐▌  █  ▐▛▚▖▐▌      █ ▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌     █ ▐▌   
#  ▐▌  ▐▌▐▛▀▜▌  █  ▐▌ ▝▜▌      █ ▐▛▀▜▌▐▛▀▚▖▐▌▝▜▌▐▛▀▀▘  █  ▝▀▚▖
#  ▐▌  ▐▌▐▌ ▐▌▗▄█▄▖▐▌  ▐▌      █ ▐▌ ▐▌▐▌ ▐▌▝▚▄▞▘▐▙▄▄▖  █ ▗▄▄▞▘
#
#	- base targets
#	- these will default to the TEST Customer if no CUSTOMER is specified
.PHONY: clean bump-version arm-macos-installers intel-macos-installers arm-ubuntu-installers intel-ubuntu-installers arm-redhat-installers intel-redhat-installers

# original dual-arch target kept for reference
macos-installers: clean check-credentials fetch-credentials bump-version pyinstaller macos-codesign macos-installer macos-productsign macos-submit-notarization build-result

# new single-arch targets
#	NOTE: these DO NOT 'bump-version'  - that should be done once prior to building either
arm-macos-installers: macos-pyinstaller-arm64 macos-codesign-arm64 macos-pkgbuild-arm64 macos-productsign-arm64 macos-notarization-arm64 macos-build-result-arm64
intel-macos-installers: fetch-credentials macos-pyinstaller-x86_64 macos-codesign-x86_64 macos-pkgbuild-x86_64 macos-productsign-x86_64 macos-notarization-x86_64 macos-build-result-x86_64

# new targets for linux installers
arm-ubuntu-installers: check-credentials fetch-credentials linux-pyinstaller-arm64 linux-deb-installer-arm64 linux-build-result-arm64-ubuntu
intel-ubuntu-installers: check-credentials fetch-credentials linux-pyinstaller-x86_64 linux-deb-installer-x86_64 linux-build-result-x86_64-ubuntu
arm-redhat-installers: check-credentials fetch-credentials linux-pyinstaller-arm64 linux-rpm-installer-arm64 linux-build-result-arm64-redhat
intel-redhat-installers: check-credentials fetch-credentials linux-pyinstaller-x86_64 linux-rpm-installer-x86_64 linux-build-result-x86_64-redhat

#
#   ▗▄▖ ▗▖  ▗▖▗▄▄▄▖    ▗▄▄▖  ▗▄▖  ▗▄▄▖ ▗▄▄▖▗▖ ▗▖ ▗▄▖ ▗▄▄▖ ▗▄▄▄ 
#  ▐▌ ▐▌▐▛▚▖▐▌▐▌       ▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▌  █
#  ▐▌ ▐▌▐▌ ▝▜▌▐▛▀▀▘    ▐▛▀▘ ▐▛▀▜▌ ▝▀▚▖ ▝▀▚▖▐▌ ▐▌▐▌ ▐▌▐▛▀▚▖▐▌  █
#  ▝▚▄▞▘▐▌  ▐▌▐▙▄▄▖    ▐▌   ▐▌ ▐▌▗▄▄▞▘▗▄▄▞▘▐▙█▟▌▝▚▄▞▘▐▌ ▐▌▐▙▄▄▀
# 
#	- utility targets for 1password. you must have the 1password cli installed and configured
check-credentials:
	@KEY_VALUE=$$(op read "op://auditor-secrets/$(CUSTOMER)/credential" 2>/dev/null); \
	if [ -z "$$KEY_VALUE" ]; then \
		echo "❌ Error: Key '$(CUSTOMER)' not found in 1Password item 'auditor-secrets'"; \
		exit 1; \
	fi
	@echo "👍 Customer credentials exist for: $(CUSTOMER)"
fetch-credentials:
	@echo "Fetching --=[ $(CUSTOMER) ]=-- configuration from 1Password..."
	$(eval API_KEY := $(shell op read "op://auditor-secrets/$(CUSTOMER)/credential"))
	$(eval API_BASE_URL := $(shell op read "op://auditor-secrets/$(CUSTOMER)/hostname"))
	$(eval export STRAC_API_KEY := $(API_KEY))
	$(eval export STRAC_API_BASE_URL := $(API_BASE_URL))
	@echo "Updating config.py with customer configuration..."
	@$(SED_CMD) 's/STRAC_API_CUSTOMER = ".*"/STRAC_API_CUSTOMER = "$(CUSTOMER)"/' src/config.py
	@$(SED_CMD) 's|STRAC_API_KEY = ".*"|STRAC_API_KEY = "$(API_KEY)"|' src/config.py
	@$(SED_CMD) 's|STRAC_API_BASE_URL = ".*"|STRAC_API_BASE_URL = "$(API_BASE_URL)"|' src/config.py
	@echo "📝 Customer configuration updated in config.py"
	@echo "🔑 STRAC_API_KEY:  $(STRAC_API_KEY)"
	@echo "🌎 STRAC_API_BASE_URL:  $(STRAC_API_BASE_URL)"
import-macos-certificates:
	@echo "Importing macOS signing certificates from 1Password..."
	@echo "Fetching Developer ID Application certificate..."
	@op read "op://auditor-secrets/developer_id_app/file" --out-file /tmp/developer_id_app.p12
	@echo "Fetching Developer ID Installer certificate..."
	@op read "op://auditor-secrets/developer_id_installer/file" --out-file /tmp/developer_id_installer.p12
	@echo "Fetching certificate password..."
	@CERT_PASSWORD=$$(op read "op://auditor-secrets/developer_id_app/password") && \
	echo "Importing Developer ID Application certificate..." && \
	security import /tmp/developer_id_app.p12 -k login.keychain -P "$$CERT_PASSWORD" -T /usr/bin/codesign && \
	echo "Importing Developer ID Installer certificate..." && \
	security import /tmp/developer_id_installer.p12 -k login.keychain -P "$$CERT_PASSWORD" -T /usr/bin/productbuild
	@echo "Cleaning up temporary files..."
	@rm -f /tmp/developer_id_app.p12 /tmp/developer_id_installer.p12
	@echo "✅ macOS signing certificates imported successfully"
	@echo "Verifying certificates..."
	@security find-identity -v -p codesigning
	@echo "Setting up notarization profile in keychain..."
	@xcrun notarytool store-credentials "notary-strac.io" \
		--apple-id "apple.id@youremail.com" \
		--team-id "TEAM_ID" \
		--password "PASSWORD"
	@echo "✅ Notarization profile 'notary-strac.io' created successfully"


#
#  ▗▖ ▗▖▗▄▄▄▖▗▄▄▄▖▗▖   ▗▄▄▄▖▗▄▄▄▖▗▄▄▄▖▗▄▄▄▖ ▗▄▄▖
#  ▐▌ ▐▌  █    █  ▐▌     █    █    █  ▐▌   ▐▌   
#  ▐▌ ▐▌  █    █  ▐▌     █    █    █  ▐▛▀▀▘ ▝▀▚▖
#  ▝▚▄▞▘  █  ▗▄█▄▖▐▙▄▄▖▗▄█▄▖  █  ▗▄█▄▖▐▙▄▄▖▗▄▄▞▘
#
#   - utility targets
define inc_ver
    awk -F. '{$$NF = $$NF + 1;} 1' OFS=. $(VERSION_FILE) > $(VERSION_FILE).tmp && mv $(VERSION_FILE).tmp $(VERSION_FILE); \
    $(SED_CMD) 's/APP_VERSION = ".*"/APP_VERSION = "$(VERSION)"/' src/config.py
endef

clean:
	@echo "Cleaning build and dist directories..."
	rm -rf $(BUILD_DIR) $(DIST_DIR)
	@echo "Deleting all .spec files from the root directory..."
	rm -f *.spec

bump-version:
	@if [ ! -f $(VERSION_FILE) ]; then echo "0.1.0" > $(VERSION_FILE); fi
	@$(call inc_ver)
	@echo "Building version $$(cat $(VERSION_FILE))"

version:
	@echo $$(cat $(VERSION_FILE))

build-result:
	@echo ""
	@echo " ================================================"
	@echo " ||            	 Build Result	              ||"
	@echo " ================================================"
	@echo " Application:    $(APP_NAME)"
	@echo " Version:        $(VERSION)"
	@echo " Customer:       $(CUSTOMER)"
	@echo " STRAC_API_KEY:  $$STRAC_API_KEY"
	@echo " STRAC_API_BASE_URL:  $$STRAC_API_BASE_URL"
	@echo " arm64 pkg:      $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg"
	@echo " x86_64 pkg:     $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg"
	@echo " ================================================"
	@echo ""

macos-build-result-arm64:
	@echo ""
	@echo " ╔════════════════════════════════════════════════════════════════════╗"
	@echo " ║                                                                    ║"
	@echo " ║                         arm64 Build Results                        ║"
	@echo " ║                                                                    ║"
	@echo " ╠════════════════════════════════════════════════════════════════════╣"
	@echo " "
	@echo "   Application:          $(APP_NAME)"
	@echo "   Version:              $(VERSION)"
	@echo "   Customer:             $(CUSTOMER)"
	@echo "   Scripts:              $(SCRIPTS_DIR)"
	@echo "   STRAC_API_KEY:        $$STRAC_API_KEY"
	@echo "   STRAC_API_BASE_URL:   $$STRAC_API_BASE_URL"
	@echo "   Manual Installer:     $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg"
	@echo "   MDM Installer:        $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-MDM.pkg"
	@echo " ══════════════════════════════════════════════════════════════════════"
	@echo ""

macos-build-result-x86_64:
	@echo ""
	@echo " ╔════════════════════════════════════════════════════════════════════╗"
	@echo " ║                                                                    ║"
	@echo " ║                        x86_64 Build Results                        ║"
	@echo " ║                                                                    ║"
	@echo " ╠════════════════════════════════════════════════════════════════════╣"
	@echo " "
	@echo "   Application:          $(APP_NAME)"
	@echo "   Version:              $(VERSION)"
	@echo "   Customer:             $(CUSTOMER)"
	@echo "   Scripts:              $(SCRIPTS_DIR)"
	@echo "   STRAC_API_KEY:        $$STRAC_API_KEY"
	@echo "   STRAC_API_BASE_URL:   $$STRAC_API_BASE_URL"
	@echo "   Manual Installer:     $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg"
	@echo "   MDM Installer:        $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-MDM.pkg"
	@echo " ══════════════════════════════════════════════════════════════════════"
	@echo ""

#
#   ▗▄▄▖ ▗▄▖ ▗▖  ▗▖▗▄▄▖▗▄▄▄▖▗▖   ▗▄▄▄▖▗▄▄▖  ▗▄▄▖
#  ▐▌   ▐▌ ▐▌▐▛▚▞▜▌▐▌ ▐▌ █  ▐▌   ▐▌   ▐▌ ▐▌▐▌   
#  ▐▌   ▐▌ ▐▌▐▌  ▐▌▐▛▀▘  █  ▐▌   ▐▛▀▀▘▐▛▀▚▖ ▝▀▚▖
#  ▝▚▄▄▖▝▚▄▞▘▐▌  ▐▌▐▌  ▗▄█▄▖▐▙▄▄▖▐▙▄▄▖▐▌ ▐▌▗▄▄▞▘
#
#   - os agnostic python compiler targets. only pyinstaller is supported 
macos-pyinstaller:
	@echo "Building with PyInstaller for ARM64 and x86_64..."
	# ARM64 build
	mkdir -p $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)
	ARCHFLAGS="-arch arm64" $(PYTHON_ARM64) -m $(PYINSTALLER) --name $(APP_NAME)-$(VERSION) --upx-dir $(UPX) --onefile $(SRC_DIR)/$(ENTRY_POINT)
	mv dist/$(APP_NAME)-$(VERSION) $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)/$(APP_NAME)
	# x86_64 build
	mkdir -p $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)
	ARCHFLAGS="-arch x86_64" $(PYTHON_X86_64) -m $(PYINSTALLER) --name $(APP_NAME)-$(VERSION) --upx-dir $(UPX) --onefile $(SRC_DIR)/$(ENTRY_POINT)
	mv dist/$(APP_NAME)-$(VERSION) $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)/$(APP_NAME)

macos-pyinstaller-arm64:
	@echo "Building with PyInstaller for ARM64..."
	# arm64 build
	mkdir -p $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)
	ARCHFLAGS="-arch arm64" $(PYTHON_ARM64) -m $(PYINSTALLER) --name $(APP_NAME)-$(VERSION) --target-arch arm64 --upx-dir $(UPX) --onefile $(SRC_DIR)/$(ENTRY_POINT)
	mv dist/$(APP_NAME)-$(VERSION) $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)/$(APP_NAME)

macos-pyinstaller-x86_64:
	@echo "Building with PyInstaller for x86_64..."
	# x86_64 build
	mkdir -p $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)
	ARCHFLAGS="-arch x86_64" $(PYTHON_X86_64) -m $(PYINSTALLER) --name $(APP_NAME)-$(VERSION) --target-arch x86_64 --upx-dir $(UPX) --onefile $(SRC_DIR)/$(ENTRY_POINT)
	mv dist/$(APP_NAME)-$(VERSION) $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)/$(APP_NAME)

macos-nuitka:
	@echo "Building with Nuitka for ARM64 and x86_64..."
	# ARM64 build
	mkdir -p $(DIST_DIR)/nuitka
	ARCHFLAGS="-arch arm64" $(PYTHON_ARM64) -m $(NUITKA) $(NUITKA_FLAGS) --output-dir=$(DIST_DIR)/nuitka/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64) --output-filename=$(APP_NAME) $(SRC_DIR)/$(ENTRY_POINT)
	# x86_64 build
	ARCHFLAGS="-arch x86_64" $(PYTHON_X86_64) -m $(NUITKA) $(NUITKA_FLAGS) --output-dir=$(DIST_DIR)/nuitka/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64) --output-filename=$(APP_NAME) $(SRC_DIR)/$(ENTRY_POINT)

#
#  ▗▖  ▗▖ ▗▄▖  ▗▄▄▖ ▗▄▖  ▗▄▄▖    ▗▄▄▖  ▗▄▖  ▗▄▄▖▗▖ ▗▖ ▗▄▖  ▗▄▄▖▗▄▄▄▖▗▖  ▗▖ ▗▄▄▖
#  ▐▛▚▞▜▌▐▌ ▐▌▐▌   ▐▌ ▐▌▐▌       ▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌▗▞▘▐▌ ▐▌▐▌     █  ▐▛▚▖▐▌▐▌   
#  ▐▌  ▐▌▐▛▀▜▌▐▌   ▐▌ ▐▌ ▝▀▚▖    ▐▛▀▘ ▐▛▀▜▌▐▌   ▐▛▚▖ ▐▛▀▜▌▐▌▝▜▌  █  ▐▌ ▝▜▌▐▌▝▜▌
#  ▐▌  ▐▌▐▌ ▐▌▝▚▄▄▖▝▚▄▞▘▗▄▄▞▘    ▐▌   ▐▌ ▐▌▝▚▄▄▖▐▌ ▐▌▐▌ ▐▌▝▚▄▞▘▗▄█▄▖▐▌  ▐▌▝▚▄▞▘
#
#   - macOS specific packaging targets
macos-codesign:
	@echo "+--------------------------------------------+"
	@echo "Signing binary [pyinstaller-arm64] ..."
	codesign --force --timestamp --sign $(DEVELOPER_ID_APPLICATION) --entitlements ./assets/pkgbuild/entitlements.plist --options runtime $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)/$(APP_NAME)
	@echo "+--------------------------------------------+"
	@echo "Verifying binary signature [pyinstaller-arm64] ..."
	codesign --verify --verbose $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)/$(APP_NAME)
	@echo "+--------------------------------------------+"
	@echo "Signing binary [pyinstaller-x86_64] ..."
	codesign --force --timestamp --sign $(DEVELOPER_ID_APPLICATION) --entitlements ./assets/pkgbuild/entitlements.plist --options runtime $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)/$(APP_NAME)
	@echo "+--------------------------------------------+"
	@echo "Verifying binary signature [pyinstaller-x86_64] ..."
	codesign --verify --verbose $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)/$(APP_NAME)
	@echo "+--------------------------------------------+"

macos-codesign-arm64:
	@echo "+--------------------------------------------+"
	@echo "Signing binary [pyinstaller-arm64] ..."
	codesign --force --timestamp --sign $(DEVELOPER_ID_APPLICATION_FULL) --entitlements ./assets/pkgbuild/entitlements.plist --options runtime $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)/$(APP_NAME)
	@echo "+--------------------------------------------+"
	@echo "Verifying binary signature [pyinstaller-arm64] ..."
	codesign --verify --verbose $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)/$(APP_NAME)
	@echo "+--------------------------------------------+"

macos-codesign-x86_64:
	@echo "+--------------------------------------------+"
	@echo "Signing binary [pyinstaller-x86_64] ..."
	codesign --force --timestamp --sign $(DEVELOPER_ID_APPLICATION_FULL) --entitlements ./assets/pkgbuild/entitlements.plist --options runtime $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)/$(APP_NAME)
	@echo "+--------------------------------------------+"
	@echo "Verifying binary signature [pyinstaller-x86_64] ..."
	codesign --verify --verbose $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)/$(APP_NAME)
	@echo "+--------------------------------------------+"

macos-installer:
ifeq ($(UNAME_S),Darwin)
	@echo "Building macOS .pkg installers for ARM64 and x86_64..."
	# ARM64 installer
	pkgbuild --root $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64) \
		--identifier com.strac.$(APP_NAME) \
		--version $(VERSION) \
		--install-location /usr/local/bin \
		$(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg
	# x86_64 installer
	pkgbuild --root $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64) \
		--identifier com.strac.$(APP_NAME) \
		--version $(VERSION) \
		--install-location /usr/local/bin \
		$(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg
endif

macos-installer-with-postinstall:
ifeq ($(UNAME_S),Darwin)
	@echo "Building macOS .pkg installers for ARM64 and x86_64..."
	# ARM64 installer
	pkgbuild --root $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64) \
		--scripts $(SCRIPTS_DIR) \
		--identifier com.strac.$(APP_NAME) \
		--version $(VERSION) \
		--install-location /usr/local/bin \
		$(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg
	# x86_64 installer
	pkgbuild --root $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64) \
		--scripts $(SCRIPTS_DIR) \
		--identifier com.strac.$(APP_NAME) \
		--version $(VERSION) \
		--install-location /usr/local/bin \
		$(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg
endif

macos-pkgbuild-arm64:
ifeq ($(UNAME_S),Darwin)
	@echo "Building macOS .pkg installers for ARM64..."
	# ARM64 MDM Installer
	pkgbuild --root $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64) \
		--scripts $(SCRIPTS_DIR) \
		--identifier com.strac.$(APP_NAME) \
		--version $(VERSION) \
		--install-location /usr/local/bin \
		$(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-MDM.pkg
	# ARM64 Manual Installer
	pkgbuild --root $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64) \
		--identifier com.strac.$(APP_NAME) \
		--version $(VERSION) \
		--install-location /usr/local/bin \
		$(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg
endif

macos-pkgbuild-x86_64:
ifeq ($(UNAME_S),Darwin)
	@echo "Building macOS .pkg installers for x86_64..."
	# x86_64 MDM Installer
	pkgbuild --root $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64) \
		--scripts $(SCRIPTS_DIR) \
		--identifier com.strac.$(APP_NAME) \
		--version $(VERSION) \
		--install-location /usr/local/bin \
		$(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-MDM.pkg
	# x86_64 Manual Installer
	pkgbuild --root $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64) \
		--identifier com.strac.$(APP_NAME) \
		--version $(VERSION) \
		--install-location /usr/local/bin \
		$(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg
endif

macos-productsign:
	@echo "Signing product - arm64..."
	productbuild --sign "Developer ID Installer: Strac Incorporated (992GD587TM)" --package $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-ready.pkg
	@echo "Signing product - x86_64..."
	productbuild --sign "Developer ID Installer: Strac Incorporated (992GD587TM)" --package $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-ready.pkg
	@echo "Cleaning up..."
	rm -rf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg
	rm -rf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg
	mv $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-ready.pkg $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg
	mv $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-ready.pkg $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg

macos-productsign-arm64:
	@echo "Signing arm64 Products..."
	productbuild --sign "Developer ID Installer: Strac Incorporated (992GD587TM)" --package $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-MDM.pkg $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-MDM-ready.pkg
	productbuild --sign "Developer ID Installer: Strac Incorporated (992GD587TM)" --package $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-ready.pkg
	@echo "Cleaning up..."
	rm -rf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg
	rm -rf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-MDM.pkg
	mv $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-ready.pkg $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg
	mv $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-MDM-ready.pkg $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-MDM.pkg

macos-productsign-x86_64:
	@echo "Signing x86_64 Products..."
	productbuild --sign "Developer ID Installer: Strac Incorporated (992GD587TM)" --package $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-MDM.pkg $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-MDM-ready.pkg
	productbuild --sign "Developer ID Installer: Strac Incorporated (992GD587TM)" --package $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-ready.pkg
	@echo "Cleaning up..."
	rm -rf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg
	rm -rf $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-MDM.pkg
	mv $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-ready.pkg $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg
	mv $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-MDM-ready.pkg $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-MDM.pkg

macos-notarization-arm64:
	@echo "+--------------------------------------------+"
	@echo "|                [ARM64]-[MDM]               |"
	@echo "+--------------------------------------------+"
	@echo "| Submitting to Apple Notarization...        |"
	@echo "+--------------------------------------------+"
	xcrun notarytool submit $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-MDM.pkg --keychain-profile "notary-strac.io" --wait
	xcrun stapler staple $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-MDM.pkg
	xcrun stapler validate $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)-MDM.pkg
	@echo "+--------------------------------------------+"
	@echo "|              [ARM64]-[MANUAL]              |"
	@echo "+--------------------------------------------+"
	xcrun notarytool submit $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg --keychain-profile "notary-strac.io" --wait
	xcrun stapler staple $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg
	xcrun stapler validate $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).pkg

macos-notarization-x86_64:
	@echo "+--------------------------------------------+"
	@echo "|               [X86_64]-[MDM]               |"
	@echo "+--------------------------------------------+"
	@echo "| Submitting to Apple Notarization...        |"
	@echo "+--------------------------------------------+"
	xcrun notarytool submit $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-MDM.pkg --keychain-profile "notary-strac.io" --wait
	xcrun stapler staple $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-MDM.pkg
	xcrun stapler validate $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)-MDM.pkg
	@echo "+--------------------------------------------+"
	@echo "|             [X86_64]-[MANUAL]              |"
	@echo "+--------------------------------------------+"
	xcrun notarytool submit $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg --keychain-profile "notary-strac.io" --wait
	xcrun stapler staple $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg
	xcrun stapler validate $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).pkg

#
#  ▗▖   ▗▄▄▄▖▗▖  ▗▖▗▖ ▗▖▗▖  ▗▖
#  ▐▌     █  ▐▛▚▖▐▌▐▌ ▐▌ ▝▚▞▘ 
#  ▐▌     █  ▐▌ ▝▜▌▐▌ ▐▌  ▐▌  
#  ▐▙▄▄▖▗▄█▄▖▐▌  ▐▌▝▚▄▞▘▗▞▘▝▚▖
#
#   - linux specific packaging targets
# linux pyinstaller builds
linux-pyinstaller-arm64:
	@echo "Building with PyInstaller for ARM64 (Linux)..."
	mkdir -p $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)
	ARCHFLAGS="-arch arm64" $(PYTHON_ARM64) -m $(PYINSTALLER) --name $(APP_NAME)-$(VERSION) --target-arch arm64 --upx-dir $(UPX) --onefile $(SRC_DIR)/$(ENTRY_POINT)
	mv dist/$(APP_NAME)-$(VERSION) $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64)/$(APP_NAME)

linux-pyinstaller-x86_64:
	@echo "Building with PyInstaller for x86_64 (Linux)..."
	mkdir -p $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)
	ARCHFLAGS="-arch x86_64" $(PYTHON_X86_64) -m $(PYINSTALLER) --name $(APP_NAME)-$(VERSION) --target-arch x86_64 --upx-dir $(UPX) --onefile $(SRC_DIR)/$(ENTRY_POINT)
	mv dist/$(APP_NAME)-$(VERSION) $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64)/$(APP_NAME)

# ubuntu deb installers
linux-deb-installer-arm64:
	@echo "Building Ubuntu .deb installer for ARM64..."
	$(FPM) -s dir -t $(DEB_FORMAT) -n $(APP_NAME) -v $(VERSION) \
		--prefix $(LINUX_PREFIX) \
		--architecture $(ARCH_ARM64) \
		--description "Strac Auditor for Linux (ARM64)" \
		--vendor "Strac Incorporated" \
		-C $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64) \
		--package $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).$(DEB_FORMAT) .

linux-deb-installer-x86_64:
	@echo "Building Ubuntu .deb installer for x86_64..."
	$(FPM) -s dir -t $(DEB_FORMAT) -n $(APP_NAME) -v $(VERSION) \
		--prefix $(LINUX_PREFIX) \
		--architecture $(ARCH_X86_64) \
		--description "Strac Auditor for Linux (x86_64)" \
		--vendor "Strac Incorporated" \
		-C $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64) \
		--package $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).$(DEB_FORMAT) .

# red hat rpm installers
linux-rpm-installer-arm64:
	@echo "Building Red Hat .rpm installer for ARM64..."
	$(FPM) -s dir -t $(RPM_FORMAT) -n $(APP_NAME) -v $(VERSION) \
		--prefix $(LINUX_PREFIX) \
		--architecture $(ARCH_ARM64) \
		--description "Strac Auditor for Linux (ARM64)" \
		--vendor "Strac Incorporated" \
		-C $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64) \
		--package $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).$(RPM_FORMAT) .

linux-rpm-installer-x86_64:
	@echo "Building Red Hat .rpm installer for x86_64..."
	$(FPM) -s dir -t $(RPM_FORMAT) -n $(APP_NAME) -v $(VERSION) \
		--prefix $(LINUX_PREFIX) \
		--architecture $(ARCH_X86_64) \
		--description "Strac Auditor for Linux (x86_64)" \
		--vendor "Strac Incorporated" \
		-C $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64) \
		--package $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).$(RPM_FORMAT) .

# linux build results
linux-build-result-arm64-ubuntu:
	@echo ""
	@echo " ╔════════════════════════════════════════════════════════════════════╗"
	@echo " ║                                                                    ║"
	@echo " ║                   Ubuntu ARM64 Build Results                       ║"
	@echo " ║                                                                    ║"
	@echo " ╠════════════════════════════════════════════════════════════════════╣"
	@echo " "
	@echo "   Application:          $(APP_NAME)"
	@echo "   Version:              $(VERSION)"
	@echo "   Customer:             $(CUSTOMER)"
	@echo "   STRAC_API_KEY:        $$STRAC_API_KEY"
	@echo "   STRAC_API_BASE_URL:   $$STRAC_API_BASE_URL"
	@echo "   Ubuntu Package:       $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).$(DEB_FORMAT)"
	@echo " ══════════════════════════════════════════════════════════════════════"
	@echo ""

linux-build-result-x86_64-ubuntu:
	@echo ""
	@echo " ╔════════════════════════════════════════════════════════════════════╗"
	@echo " ║                                                                    ║"
	@echo " ║                   Ubuntu x86_64 Build Results                      ║"
	@echo " ║                                                                    ║"
	@echo " ╠════════════════════════════════════════════════════════════════════╣"
	@echo " "
	@echo "   Application:          $(APP_NAME)"
	@echo "   Version:              $(VERSION)"
	@echo "   Customer:             $(CUSTOMER)"
	@echo "   STRAC_API_KEY:        $$STRAC_API_KEY"
	@echo "   STRAC_API_BASE_URL:   $$STRAC_API_BASE_URL"
	@echo "   Ubuntu Package:       $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).$(DEB_FORMAT)"
	@echo " ══════════════════════════════════════════════════════════════════════"
	@echo ""

linux-build-result-arm64-redhat:
	@echo ""
	@echo " ╔════════════════════════════════════════════════════════════════════╗"
	@echo " ║                                                                    ║"
	@echo " ║                   Red Hat ARM64 Build Results                      ║"
	@echo " ║                                                                    ║"
	@echo " ╠════════════════════════════════════════════════════════════════════╣"
	@echo " "
	@echo "   Application:          $(APP_NAME)"
	@echo "   Version:              $(VERSION)"
	@echo "   Customer:             $(CUSTOMER)"
	@echo "   STRAC_API_KEY:        $$STRAC_API_KEY"
	@echo "   STRAC_API_BASE_URL:   $$STRAC_API_BASE_URL"
	@echo "   Red Hat Package:      $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_ARM64).$(RPM_FORMAT)"
	@echo " ══════════════════════════════════════════════════════════════════════"
	@echo ""

linux-build-result-x86_64-redhat:
	@echo ""
	@echo " ╔════════════════════════════════════════════════════════════════════╗"
	@echo " ║                                                                    ║"
	@echo " ║                   Red Hat x86_64 Build Results                     ║"
	@echo " ║                                                                    ║"
	@echo " ╠════════════════════════════════════════════════════════════════════╣"
	@echo " "
	@echo "   Application:          $(APP_NAME)"
	@echo "   Version:              $(VERSION)"
	@echo "   Customer:             $(CUSTOMER)"
	@echo "   STRAC_API_KEY:        $$STRAC_API_KEY"
	@echo "   STRAC_API_BASE_URL:   $$STRAC_API_BASE_URL"
	@echo "   Red Hat Package:      $(DIST_DIR)/$(APP_NAME)-$(VERSION)-$(ARCH_X86_64).$(RPM_FORMAT)"
	@echo " ══════════════════════════════════════════════════════════════════════"
	@echo ""

# legacy targets - kept for backward compatibility
linux-deb-installer:
ifeq ($(UNAME_S),Linux)
	@echo "Building Ubuntu .deb installer..."
	fpm -s dir -t deb -n $(APP_NAME) -v $(VERSION) \
		--prefix /usr/local/bin \
		-C $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION) .
endif

linux-rpm-installer:
ifeq ($(UNAME_S),Linux)
	@echo "Building Red Hat .rpm installer..."
	fpm -s dir -t rpm -n $(APP_NAME) -v $(VERSION) \
		--prefix /usr/local/bin \
		-C $(DIST_DIR)/pyinstaller/$(APP_NAME)-$(VERSION) .
endif