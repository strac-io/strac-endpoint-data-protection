import logging
import re


class Detector:
    description = "UK UTR Number Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-uk-utr"
        self.logger = logging.getLogger(self.name)

        self.utr_patterns = [
            # pattern with spaces
            re.compile(r"\b\d{5}\s\d{5}\b"),
            # pattern with hyphen
            re.compile(r"\b\d{5}-\d{5}\b"),
            # pattern without separator
            re.compile(r"\b\d{10}\b"),
        ]

        self.utr_keywords = [
            "utr",
            "unique taxpayer reference",
            "tax reference",
            "taxpayer reference",
            "hmrc reference",
            "tax identifier",
            "tax id",
            "self assessment",
            "sa reference",
            "tax return",
            "hmrc",
            "inland revenue",
            "corporation tax",
            "company tax",
            "tax office",
            "tax account",
            "tax registration",
            "tax number",
            "tax reference number",
            "tax identifier number",
            "revenue reference",
            "revenue number",
            "tax authority reference",
            "tax authority number",
            "tax department reference",
            "tax department number",
        ]

        # test and commonly used demo utr numbers
        self.utr_whitelist = {
            "1234567890",
            "0000000000",
            "1111111111",
            # same numbers with separators
            "12345 67890",
            "00000 00000",
            "11111 11111",
            "12345-67890",
            "00000-00000",
            "11111-11111",
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_utr(self, text):
        findings = []
        try:
            for pattern in self.utr_patterns:
                for match in pattern.finditer(text):
                    utr = match.group()

                    # normalize the utr for whitelist check
                    normalized_utr = utr.replace("-", "").replace(" ", "")
                    if normalized_utr in self.utr_whitelist:
                        self.logger.debug(f"skipping whitelisted utr: {utr}")
                        continue

                    context = self._get_context(text, match.start(), match.end())
                    if self._contains_keyword(context, self.utr_keywords):
                        findings.append(
                            {
                                "type": "UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER",
                                "content": utr,
                                "context": context,
                            }
                        )
                        self.logger.debug(f"found potential utr: {utr}")
        except Exception as e:
            self.logger.error(f"error scanning utrs: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_utr(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
