import logging
import re


class Detector:
    description = "Indian NREGA Number Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-in-nrega"
        self.logger = logging.getLogger(self.name)

        self.nrega_patterns = [
            # pattern with spaces (xx-xxx-xxx-xxx)
            re.compile(r"\b\d{2}-\d{3}-\d{3}-\d{3}\b"),
            # pattern without separators
            re.compile(r"\b\d{11}\b"),
        ]

        self.nrega_keywords = [
            "nrega",
            "mgnrega",
            "job card",
            "employment guarantee",
            "rural employment",
            "nrega card",
            "mgnrega card",
            "mahatma gandhi nrega",
            "rozgar guarantee",
            "रोजगार गारंटी",  # hindi - employment guarantee
            "मनरेगा",  # hindi - mnrega
            "नरेगा",  # hindi - nrega
            "जॉब कार्ड",  # hindi - job card
            "gram rozgar",
            "ग्राम रोजगार",  # hindi - rural employment
            "employment scheme",
            "hundred days work",
            "100 days work",
            "rural worker",
            "job seeker",
            "work guarantee",
            "employment card",
            "worker registration",
            "nrega registration",
            "mgnrega registration",
            "rural development",
            "panchayat rozgar",
            "employment id",
            "worker id",
            "nrega worker",
            "mgnrega worker",
        ]

        self.nrega_whitelist = {
            "11-111-111-111",
            "22-222-222-222",
            "55-555-555-555",
            # same numbers without separators
            "11111111111",
            "22222222222",
            "55555555555",
            # common test numbers
            "12-345-678-901",
            "98-765-432-109",
            "12345678901",
            "98765432109",
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_nrega(self, text):
        findings = []
        try:
            for pattern in self.nrega_patterns:
                for match in pattern.finditer(text):
                    nrega = match.group()

                    # normalize the number for whitelist check
                    normalized_nrega = nrega.replace("-", "")
                    if normalized_nrega in self.nrega_whitelist:
                        self.logger.debug(f"skipping whitelisted nrega: {nrega}")
                        continue

                    context = self._get_context(text, match.start(), match.end())
                    if self._contains_keyword(context, self.nrega_keywords):
                        findings.append(
                            {
                                "type": "IN_NREGA",
                                "content": nrega,
                                "context": context,
                            }
                        )
                        self.logger.debug(f"found potential nrega: {nrega}")
        except Exception as e:
            self.logger.error(f"error scanning nrega numbers: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_nrega(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
