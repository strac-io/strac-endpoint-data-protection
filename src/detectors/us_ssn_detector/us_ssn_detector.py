import logging
import re


class Detector:
    description = "US SSN Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-ssn"
        self.logger = logging.getLogger(self.name)

        # ssn patterns
        self.ssn_patterns = [
            # hyphens
            re.compile(
                r"\b(?:0[1-9][0-9]|00[1-9]|[1-5][0-9]{2}|6[0-5][0-9]|66[0-5789]|7[0-2][0-9]|73[0-3]|7[56][0-9]|77[012])-(?:0[1-9]|[1-9][0-9])-(?:0[1-9][0-9]{2}|00[1-9][0-9]|000[1-9]|[1-9][0-9]{3})\b"
            ),
            # spaces
            re.compile(
                r"\b(?:0[1-9][0-9]|00[1-9]|[1-5][0-9]{2}|6[0-5][0-9]|66[0-5789]|7[0-2][0-9]|73[0-3]|7[56][0-9]|77[012]) (?:0[1-9]|[1-9][0-9]) (?:0[1-9][0-9]{2}|00[1-9][0-9]|000[1-9]|[1-9][0-9]{3})\b"
            ),
            # no spaces
            re.compile(
                r"\b(?:0[1-9][0-9]|00[1-9]|[1-5][0-9]{2}|6[0-5][0-9]|66[0-5789]|7[0-2][0-9]|73[0-3]|7[56][0-9]|77[012])(?:0[1-9]|[1-9][0-9])(?:0[1-9][0-9]{2}|00[1-9][0-9]|000[1-9]|[1-9][0-9]{3})\b"
            ),
        ]

        # ssn contextual keywords
        self.ssn_keywords = [
            "SSA Number",
            "social security number",
            "social security #",
            "social security#",
            "social security no",
            "Social Security#",
            "Soc Sec",
            "SSN",
            "SSNS",
            "SSNS#",
            "SSN#",
            "SS#",
            "SSID",
        ]

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_ssn(self, text):
        findings = []
        try:
            for pattern in self.ssn_patterns:
                for match in pattern.finditer(text):
                    ssn = match.group()
                    context = self._get_context(text, match.start(), match.end())
                    # check for SSN contextual keywords or just match an SSN
                    if self._contains_keyword(context, self.ssn_keywords):
                        findings.append(
                            {"type": "SSN", "content": ssn, "context": context}
                        )
                        self.logger.debug(f"found potential ssn: {ssn}")
        except Exception as e:
            self.logger.error(f"error scanning ssns: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_ssn(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
