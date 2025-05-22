import logging
import re


class Detector:
    description = "Australian Passport Number Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-au-passport"
        self.logger = logging.getLogger(self.name)

        # australian passport numbers are one or two capital letters followed by 7 digits
        self.passport_patterns = [
            re.compile(r"\b[A-Z][0-9]{7}\b"),
            re.compile(r"\b[A-Z][A-Z][0-9]{7}\b"),
        ]

        self.passport_keywords = [
            "au passport",
            "aus passport",
            "aussie passport",
            "australia passport",
            "australian passport",
            "commonwealth of australia",
            "department of immigration",
            "document number",
            "immigration and citizenship",
            "issuing authority",
            "national identity card",
            "oz passport",
            "passport #",
            "passport card",
            "passport details",
            "passport id",
            "passport no",
            "passport number",
            "passport numbers",
            "passport",
            "passport#",
            "passportid",
            "passportno",
            "passportnumber",
            "passportnumbers",
            "passports",
            "travel document number",
            "travel document",
            "travel id",
        ]

        # test and commonly used demo australian passport numbers
        self.passport_whitelist = {
            "N1234567",  # common test number
            "AU1234567",
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
                                "type": "AU_PASSPORT_NUMBER",
                                "content": passport,
                                "context": context,
                            }
                        )
                        self.logger.debug(
                            f"found potential australian passport: {passport}"
                        )
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
