import logging
import re


class Detector:
    description = "US Taxpayer ID Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-us-taxpayer-id"
        self.logger = logging.getLogger(self.name)

        self.taxpayer_patterns = [
            # pattern with hyphen
            re.compile(r"\b[0-9]{2}-[0-9]{7}\b"),
            # pattern with space
            re.compile(r"\b[0-9]{2}\s[0-9]{7}\b"),
            # pattern without separator
            re.compile(r"\b[0-9]{9}\b"),
        ]

        self.taxpayer_keywords = [
            "ein",
            "ein number",
            "employer id",
            "employer identification",
            "tax id",
            "taxpayer id",
            "federal tax",
            "federal id",
            "tax identification",
            "business tax",
            "corporate tax",
            "employer number",
            "tax number",
            "irs number",
            "internal revenue",
            "form w-9",
            "w9",
            "w-9",
            "form 1120",
            "form 1065",
            "form 990",
            "business registration",
            "tax registration",
            "federal employer",
            "fein",
            "f.e.i.n",
            "tax exempt",
            "non-profit id",
            "nonprofit id",
            "business id",
            "company tax",
        ]

        # test and commonly used demo taxpayer ids
        self.taxpayer_whitelist = {
            "00-0000000",
            "11-1111111",
            "22-2222222",
            "33-3333333",
            "44-4444444",
            "55-5555555",
            "66-6666666",
            "77-7777777",
            "88-8888888",
            "99-9999999",
            "12-3456789",
            "98-7654321",
            # same numbers without hyphen
            "000000000",
            "111111111",
            "222222222",
            "333333333",
            "444444444",
            "555555555",
            "666666666",
            "777777777",
            "888888888",
            "999999999",
            "123456789",
            "987654321",
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_taxpayer_id(self, text):
        findings = []
        try:
            for pattern in self.taxpayer_patterns:
                for match in pattern.finditer(text):
                    taxpayer_id = match.group()

                    # normalize the id for whitelist check
                    normalized_id = taxpayer_id.replace("-", "").replace(" ", "")
                    if normalized_id in self.taxpayer_whitelist:
                        self.logger.debug(
                            f"skipping whitelisted taxpayer id: {taxpayer_id}"
                        )
                        continue

                    context = self._get_context(text, match.start(), match.end())
                    if self._contains_keyword(context, self.taxpayer_keywords):
                        findings.append(
                            {
                                "type": "US_TAXPAYER_ID",
                                "content": taxpayer_id,
                                "context": context,
                            }
                        )
                        self.logger.debug(f"found potential taxpayer id: {taxpayer_id}")
        except Exception as e:
            self.logger.error(f"error scanning taxpayer ids: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_taxpayer_id(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
