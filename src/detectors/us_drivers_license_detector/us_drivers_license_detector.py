import logging
import re


class Detector:
    description = "US Drivers License Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-us-drivers-license"
        self.logger = logging.getLogger(self.name)

        self.dl_patterns = [
            # washington - WDL + alphanumeric
            re.compile(r"\bWDL[A-Z0-9]{7}\b"),
            # virginia - 1 letter + 8 digits
            re.compile(r"\b[A-Z]\d{8}\b"),
            # alaska - 7 digits
            re.compile(r"\b\d{7}\b"),
            # california - 1 letter + 7 digits
            re.compile(r"\b[A-Z]\d{7}\b"),
            # florida - 1 letter + 12 digits
            re.compile(r"\b[A-Z]\d{12}\b"),
            # texas - 7-8 digits
            re.compile(r"\b\d{7,8}\b"),
            # new york - 1 letter + 7 digits or 8 digits
            re.compile(r"\b[A-Z]\d{7}\b|\b\d{8}\b"),
            # illinois - 1 letter + 11-12 digits
            re.compile(r"\b[A-Z]\d{11,12}\b"),
            # generic patterns (common formats)
            re.compile(r"\b[A-Z]\d{6,8}\b"),  # letter followed by 6-8 digits
            re.compile(r"\b[A-Z]{1,2}\d{4,8}\b"),  # 1-2 letters followed by 4-8 digits
            re.compile(r"\b\d{6,9}\b"),  # 6-9 digits
        ]

        self.dl_keywords = [
            "drivers license",
            "driver license",
            "driving license",
            "driver's license",
            "dl number",
            "dl #",
            "license number",
            "license #",
            "driving permit",
            "driver permit",
            "permit number",
            "permit #",
            "state id",
            "state identification",
            "identification number",
            "id number",
            "id card",
            "dmv",
            "department of motor vehicles",
            "motor vehicle department",
            "mvd",
            # state names
            "alabama",
            "alaska",
            "arizona",
            "arkansas",
            "california",
            "colorado",
            "connecticut",
            "delaware",
            "florida",
            "georgia",
            "hawaii",
            "idaho",
            "illinois",
            "indiana",
            "iowa",
            "kansas",
            "kentucky",
            "louisiana",
            "maine",
            "maryland",
            "massachusetts",
            "michigan",
            "minnesota",
            "mississippi",
            "missouri",
            "montana",
            "nebraska",
            "nevada",
            "new hampshire",
            "new jersey",
            "new mexico",
            "new york",
            "north carolina",
            "north dakota",
            "ohio",
            "oklahoma",
            "oregon",
            "pennsylvania",
            "rhode island",
            "south carolina",
            "south dakota",
            "tennessee",
            "texas",
            "utah",
            "vermont",
            "virginia",
            "washington",
            "west virginia",
            "wisconsin",
            "wyoming",
        ]

        # test and commonly used demo drivers license numbers
        self.dl_whitelist = {
            # washington state (format: WDLxxxxxxxx)
            "WDL1234567",
            "WDL9999999",
            "WDLABCD123",
            "WDL0000000",
            "WDLTEST123",
            "WDLDEMO12",
            # virginia (format: 1 letter + 8 digits)
            "A12345678",
            "A00000000",
            "A99999999",
            "T12345678",
            "D00000000",
            # generic test numbers
            "A123456",
            "AB123456",
            "123456789",
            "DL123456",
            "TEST1234",
            "DEMO1234",
            "SAMPLE12",
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_drivers_license(self, text):
        findings = []
        try:
            for pattern in self.dl_patterns:
                for match in pattern.finditer(text):
                    dl_number = match.group()

                    if dl_number in self.dl_whitelist:
                        self.logger.debug(
                            f"skipping whitelisted drivers license: {dl_number}"
                        )
                        continue

                    context = self._get_context(text, match.start(), match.end())
                    if self._contains_keyword(context, self.dl_keywords):
                        findings.append(
                            {
                                "type": "US_DRIVERS_LICENSE",
                                "content": dl_number,
                                "context": context,
                            }
                        )
                        self.logger.debug(
                            f"found potential drivers license: {dl_number}"
                        )
        except Exception as e:
            self.logger.error(f"error scanning drivers licenses: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_drivers_license(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
