import logging
import re


class Detector:
    description = "UK National Insurance Number Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-uk-nino"
        self.logger = logging.getLogger(self.name)

        self.nino_patterns = [
            # pattern with spaces
            re.compile(
                r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b",
                re.IGNORECASE,
            ),
            # no spaces
            re.compile(
                r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b", re.IGNORECASE
            ),
        ]

        self.nino_keywords = [
            "national insurance",
            "ni number",
            "nino",
            "insurance number",
            "ni no",
            "ni #",
            "national insurance contributions",
            "nic",
            "hmrc",
            "dwp",
            "benefits",
            "universal credit",
            "state pension",
            "job seekers",
            "employment support",
            "tax credits",
            "child benefit",
            "personal tax",
            "self assessment",
            "payroll",
            "p45",
            "p60",
            "new starter",
            "employee details",
            "employment details",
        ]

        # test and commonly used demo uk national insurance numbers
        self.nino_whitelist = {
            "AB123456C",
            "AA000000A",
            "BB111111B",
            "NK010101A",  # commonly used test number
            "TN373834A",  # commonly used test number
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_nino(self, text):
        findings = []
        try:
            for pattern in self.nino_patterns:
                for match in pattern.finditer(text):
                    nino = match.group()

                    # normalize the nino for whitelist check
                    normalized_nino = nino.replace(" ", "").upper()
                    if normalized_nino in self.nino_whitelist:
                        self.logger.debug(f"skipping whitelisted nino: {nino}")
                        continue

                    context = self._get_context(text, match.start(), match.end())
                    if self._contains_keyword(context, self.nino_keywords):
                        findings.append(
                            {
                                "type": "UK_NATIONAL_INSURANCE_NUMBER",
                                "content": nino,
                                "context": context,
                            }
                        )
                        self.logger.debug(f"found potential nino: {nino}")
        except Exception as e:
            self.logger.error(f"error scanning ninos: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_nino(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
