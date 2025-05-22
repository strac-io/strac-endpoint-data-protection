import logging
import re


class Detector:
    description = "Indian Aadhaar Number Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-in-aadhaar"
        self.logger = logging.getLogger(self.name)

        self.aadhaar_patterns = [
            # pattern with spaces (xxxx xxxx xxxx)
            re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"),
            # pattern with dashes (xxxx-xxxx-xxxx)
            re.compile(r"\b\d{4}-\d{4}-\d{4}\b"),
            # pattern without separators (xxxxxxxxxxxx)
            re.compile(r"\b\d{12}\b"),
        ]

        self.aadhaar_keywords = [
            "aadhaar",
            "aadhar",
            "आधार",  # hindi
            "uid",
            "uidai",
            "unique identification",
            "unique id",
            "biometric id",
            "identity number",
            "aadhaar number",
            "aadhar number",
            "aadhaar card",
            "aadhar card",
            "aadhaar details",
            "aadhar details",
            "resident id",
            "भारतीय विशिष्ट पहचान",  # hindi - indian unique identification
            "आधार कार्ड",  # hindi - aadhaar card
            "आधार नंबर",  # hindi - aadhaar number
            "e-kyc",
            "ekyc",
            "demographic id",
            "identity verification",
            "proof of identity",
            "identity proof",
            "id proof",
            "government id",
            "national id",
            "digital identity",
        ]

        self.aadhaar_whitelist = {
            # common test numbers
            "111111111111",
            "222222222222",
            "123412341234",
            "432143214321",
            # same numbers with spaces
            "1111 1111 1111",
            "2222 2222 2222",
            "1234 1234 1234",
            # same numbers with dashes
            "1111-1111-1111",
            "2222-2222-2222",
            "1234-1234-1234",
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_aadhaar(self, text):
        findings = []
        try:
            for pattern in self.aadhaar_patterns:
                for match in pattern.finditer(text):
                    aadhaar = match.group()

                    # normalize the number for whitelist check
                    normalized_aadhaar = aadhaar.replace("-", "").replace(" ", "")
                    if normalized_aadhaar in self.aadhaar_whitelist:
                        self.logger.debug(f"skipping whitelisted aadhaar: {aadhaar}")
                        continue

                    context = self._get_context(text, match.start(), match.end())
                    if self._contains_keyword(context, self.aadhaar_keywords):
                        findings.append(
                            {
                                "type": "IN_AADHAAR",
                                "content": aadhaar,
                                "context": context,
                            }
                        )
                        self.logger.debug(f"found potential aadhaar: {aadhaar}")
        except Exception as e:
            self.logger.error(f"error scanning aadhaar numbers: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_aadhaar(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
