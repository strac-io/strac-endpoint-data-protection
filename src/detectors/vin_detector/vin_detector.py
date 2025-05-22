import logging
import re


class Detector:
    description = "Vehicle Identification Number Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-vin"
        self.logger = logging.getLogger(self.name)

        self.vin_pattern = re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")

        self.vin_keywords = [
            "vin",
            "vin number",
            "vehicle identification number",
            "vehicle id",
            "vehicle number",
            "chassis number",
            "frame number",
            "car id",
            "automobile id",
            "vehicle registration",
            "registration number",
            "vehicle details",
            "car details",
            "vehicle info",
            "car information",
            "vehicle documentation",
            "vehicle history",
            "carfax",
            "autocheck",
        ]

        # test and commonly used demo vin numbers
        self.vin_whitelist = {
            "11111111111111111",  # test vin
            "AAAAAAAAAAAAAAAAA",  # test vin
            "1HGCM82633A123456",  # honda test vin
            "WVWZZZ1JZXW123456",  # volkswagen test vin
            "JH4NA1157MT001832",  # acura test vin
            "1G1BL52P7TR115520",  # chevrolet test vin
            "2FAFP71W1XX123456",  # ford test vin
            "5YJSA1DN5CFP01657",  # tesla test vin
            "WP0AA2991YS620152",  # porsche test vin
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_vin(self, text):
        findings = []
        try:
            for match in self.vin_pattern.finditer(text):
                vin = match.group()

                if vin in self.vin_whitelist:
                    self.logger.debug(f"skipping whitelisted vin: {vin}")
                    continue

                context = self._get_context(text, match.start(), match.end())
                if self._contains_keyword(context, self.vin_keywords):
                    findings.append({"type": "VIN", "content": vin, "context": context})
                    self.logger.debug(f"found potential vin: {vin}")
        except Exception as e:
            self.logger.error(f"error scanning vins: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_vin(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
