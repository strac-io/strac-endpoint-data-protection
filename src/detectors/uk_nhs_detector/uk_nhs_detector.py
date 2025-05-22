import logging
import re


class Detector:
    description = "UK NHS Number Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-uk-nhs"
        self.logger = logging.getLogger(self.name)

        self.nhs_patterns = [
            # with spaces
            re.compile(r"\b\d{3}\s\d{3}\s\d{4}\b"),
            # with hyphens
            re.compile(r"\b\d{3}-\d{3}-\d{4}\b"),
            # no separators
            re.compile(r"\b\d{10}\b"),
        ]

        self.nhs_keywords = [
            "nhs",
            "nhs number",
            "national health service",
            "health service number",
            "patient number",
            "patient id",
            "hospital number",
            "medical record number",
            "healthcare number",
            "health record",
            "nhs patient",
            "nhs identifier",
            "patient identifier",
            "medical id",
            "health id",
            "hospital id",
            "medical number",
            "patient reference",
            "nhs ref",
            "health service id",
            "medical record id",
            "hospital reference",
            "clinic number",
            "gp number",
            "practice number",
        ]

        self.nhs_whitelist = {
            # common test numbers
            "1234567890",
            "0123456789",
            "9999999999",
            "0000000000",
            # same as above with separators
            "123 456 7890",
            "012 345 6789",
            "999 999 9999",
            "000 000 0000",
            "123-456-7890",
            "012-345-6789",
            "999-999-9999",
            "000-000-0000",
            # other test numbers
            "1111111111",
            "2222222222",
            "3333333333",
            "4444444444",
            "5555555555",
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_nhs(self, text):
        findings = []
        try:
            for pattern in self.nhs_patterns:
                for match in pattern.finditer(text):
                    nhs = match.group()

                    # normalize the number for whitelist check
                    normalized_nhs = nhs.replace("-", "").replace(" ", "")
                    if normalized_nhs in self.nhs_whitelist:
                        self.logger.debug(f"skipping whitelisted nhs number: {nhs}")
                        continue

                    context = self._get_context(text, match.start(), match.end())
                    if self._contains_keyword(context, self.nhs_keywords):
                        findings.append(
                            {
                                "type": "UK_NHS_NUMBER",
                                "content": nhs,
                                "context": context,
                            }
                        )
                        self.logger.debug(f"found potential nhs number: {nhs}")
        except Exception as e:
            self.logger.error(f"error scanning nhs numbers: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_nhs(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
