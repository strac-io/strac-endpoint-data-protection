import logging
import re


class Detector:
    description = "US Passport Number Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-us-passport"
        self.logger = logging.getLogger(self.name)

        self.passport_patterns = [
            re.compile(r"\b[0-9]{9}\b"),
            re.compile(r"\b[A-Z][0-9]{8}\b"),
        ]

        self.passport_keywords = [
            "passport",
            "passport number",
            "passport no",
            "passport#",
            "us passport",
            "passport id",
            "passportid",
            "passportno",
            "travel document",
            "travel document number",
            "document number",
            "travel id",
            "passport card",
            "passeport",  # french
            "reisepass",  # german
            "passaporto",  # italian
            "pasaporte",  # spanish
        ]

        # test and commonly used demo passport numbers
        self.passport_whitelist = {
            "123456789",
            "A12345678",  # common test number
            "123123123",
            "A00000000",
            "999999999",
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_passport(self, text):
        findings = []
        try:
            for pattern in self.passport_patterns:
                for match in pattern.finditer(text):
                    passport = match.group()

                    if passport in self.passport_whitelist:
                        self.logger.debug(f"skipping whitelisted passport: {passport}")
                        continue

                    context = self._get_context(text, match.start(), match.end())
                    if self._contains_keyword(context, self.passport_keywords):
                        findings.append(
                            {
                                "type": "US_PASSPORT_NUMBER",
                                "content": passport,
                                "context": context,
                            }
                        )
                        self.logger.debug(f"found potential passport: {passport}")
        except Exception as e:
            self.logger.error(f"error scanning passports: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_passport(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
