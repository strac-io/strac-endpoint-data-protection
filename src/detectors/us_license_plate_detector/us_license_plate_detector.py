import logging
import re


class Detector:
    description = "US License Plate Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-us-license-plate"
        self.logger = logging.getLogger(self.name)

        self.plate_patterns = [
            # pattern for XXX-1234 or XXX 1234 format
            re.compile(r"\b[A-Z]{3}[-\s]?\d{4}\b"),
            # pattern for 123-ABC or 123 ABC format
            re.compile(r"\b\d{3}[-\s]?[A-Z]{3}\b"),
            # pattern for ABC-1234 or ABC 1234 format
            re.compile(r"\b[A-Z]{2,3}[-\s]?\d{3,4}\b"),
            # pattern for 12345 or 123456 format
            re.compile(r"\b[A-Z0-9]{5,7}\b"),
        ]

        # license plate contextual keywords including state names
        self.plate_keywords = [
            # general terms
            "license plate",
            "license number",
            "vehicle plate",
            "plate number",
            "registration plate",
            "car plate",
            "vehicle registration",
            "dmv",
            "dept of motor vehicles",
            "department of motor vehicles",
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

        # test and commonly used demo license plates
        self.plate_whitelist = {
            "ABC123",  # common test plate
            "TEST123",
            "DEMO123",
            "SAMPLE1",
            "XXX0000",
            "AAA111",
            "ZZZ999",
            "123ABC",
            "999XXX",
            "12345",  # common 5-digit test plates
            "ABCDEF",  # common 6-char test plates
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_license_plate(self, text):
        findings = []
        try:
            for pattern in self.plate_patterns:
                for match in pattern.finditer(text):
                    plate = match.group()

                    if plate in self.plate_whitelist:
                        self.logger.debug(
                            f"skipping whitelisted license plate: {plate}"
                        )
                        continue

                    context = self._get_context(text, match.start(), match.end())
                    if self._contains_keyword(context, self.plate_keywords):
                        findings.append(
                            {
                                "type": "US_LICENSE_PLATE",
                                "content": plate,
                                "context": context,
                            }
                        )
                        self.logger.debug(f"found potential license plate: {plate}")
        except Exception as e:
            self.logger.error(f"error scanning license plates: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_license_plate(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
