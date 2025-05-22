import logging
import re


class Detector:
    description = "IBAN Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-iban"
        self.logger = logging.getLogger(self.name)

        self.iban_pattern = re.compile(
            r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b"
        )

        self.iban_keywords = [
            "IBAN",
            "bank account",
            "international account",
            "bank transfer",
            "wire transfer",
            "swift",
            "sepa",
            "account number",
            "banking details",
            "beneficiary",
            "remittance",
            "payment details",
            "bank details",
            "account details",
            "international banking",
            "bank identifier",
        ]

        # test and commonly used demo account numbers
        self.iban_whitelist = {
            "GB82WEST12345698765432",  # uk iban
            "DE89370400440532013000",  # german iban
            "FR7630006000011234567890189",  # french iban
            "BE71096123456769",  # belgian iban
            "NL02ABNA0123456789",  # dutch iban
            "ES7921000813610123456789",  # spanish iban
            "IT60X0542811101000000123456",  # italian iban
            "CH9300762011623852957",  # swiss iban
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_iban(self, text):
        findings = []
        try:
            for match in self.iban_pattern.finditer(text):
                iban = match.group()

                if iban in self.iban_whitelist:
                    self.logger.debug(f"skipping whitelisted IBAN: {iban}")
                    continue

                context = self._get_context(text, match.start(), match.end())
                if self._contains_keyword(context, self.iban_keywords):
                    findings.append(
                        {"type": "IBAN", "content": iban, "context": context}
                    )
                    self.logger.debug(f"found potential IBAN: {iban}")
        except Exception as e:
            self.logger.error(f"error scanning IBANs: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_iban(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
