import logging
import re


class Detector:
    description = "Date of Birth Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-dob"
        self.logger = logging.getLogger(self.name)

        self.numerical_date_patterns = [
            # MM/DD/YYYY
            re.compile(
                r"\b(0?[1-9]|1[0-2])[/](0?[1-9]|[12][0-9]|3[01])[/](19|20)\d\d\b"
            ),
            # MM-DD-YYYY
            re.compile(
                r"\b(0?[1-9]|1[0-2])[-](0?[1-9]|[12][0-9]|3[01])[-](19|20)\d\d\b"
            ),
            # MM.DD.YYYY
            re.compile(
                r"\b(0?[1-9]|1[0-2])[.](0?[1-9]|[12][0-9]|3[01])[.](19|20)\d\d\b"
            ),
            # MM/DD/YY
            re.compile(r"\b(0?[1-9]|1[0-2])[/](0?[1-9]|[12][0-9]|3[01])[/]\d{2}\b"),
            # MM-DD-YY
            re.compile(r"\b(0?[1-9]|1[0-2])[-](0?[1-9]|[12][0-9]|3[01])[-]\d{2}\b"),
            # MM.DD.YY
            re.compile(r"\b(0?[1-9]|1[0-2])[.](0?[1-9]|[12][0-9]|3[01])[.]\d{2}\b"),
            # DD/MM/YYYY
            re.compile(
                r"\b(0?[1-9]|[12][0-9]|3[01])[/](0?[1-9]|1[0-2])[/](19|20)\d\d\b"
            ),
            # DD-MM-YYYY
            re.compile(
                r"\b(0?[1-9]|[12][0-9]|3[01])[-](0?[1-9]|1[0-2])[-](19|20)\d\d\b"
            ),
            # DD.MM.YYYY
            re.compile(
                r"\b(0?[1-9]|[12][0-9]|3[01])[.](0?[1-9]|1[0-2])[.](19|20)\d\d\b"
            ),
            # DD/MM/YY
            re.compile(r"\b(0?[1-9]|[12][0-9]|3[01])[/](0?[1-9]|1[0-2])[/]\d{2}\b"),
            # DD-MM-YY
            re.compile(r"\b(0?[1-9]|[12][0-9]|3[01])[-](0?[1-9]|1[0-2])[-]\d{2}\b"),
            # DD.MM.YY
            re.compile(r"\b(0?[1-9]|[12][0-9]|3[01])[.](0?[1-9]|1[0-2])[.]\d{2}\b"),
        ]

        self.text_date_patterns = [
            # Month DD, YYYY
            re.compile(
                r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(0?[1-9]|[12][0-9]|3[01])(?:st|nd|rd|th)?,?\s+(19|20)\d\d\b",
                re.IGNORECASE,
            ),
            # Month no comma (DD YYYY)
            re.compile(
                r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(0?[1-9]|[12][0-9]|3[01])(?:st|nd|rd|th)?\s+(19|20)\d\d\b",
                re.IGNORECASE,
            ),
            # Month no year (DD)
            re.compile(
                r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(0?[1-9]|[12][0-9]|3[01])(?:st|nd|rd|th)?\b",
                re.IGNORECASE,
            ),
            # abbreviated month (Jan DD, YYYY)
            re.compile(
                r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[.]?\s+(0?[1-9]|[12][0-9]|3[01])(?:st|nd|rd|th)?,?\s+(19|20)\d\d\b",
                re.IGNORECASE,
            ),
            # abbreviated month no comma(Jan DD YYYY)
            re.compile(
                r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[.]?\s+(0?[1-9]|[12][0-9]|3[01])(?:st|nd|rd|th)?\s+(19|20)\d\d\b",
                re.IGNORECASE,
            ),
            # abbreviated month (Jan DD) (no year)
            re.compile(
                r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[.]?\s+(0?[1-9]|[12][0-9]|3[01])(?:st|nd|rd|th)?\b",
                re.IGNORECASE,
            ),
        ]

        self.dob_keywords = [
            "date of birth",
            "birth date",
            "birthdate",
            "birthday",
            "born on",
            "born in",
            "DOB",
            "D.O.B",
            "D.O.B.",
            "birth certificate",
            "birth record",
        ]

        # test and commonly used demo dates
        self.whitelist_dates = [
            "01/01/1970",  # unix epoch
            "1/1/1970",  # unix epoch
            "January 1, 1970",  # unix epoch
            "Jan 1, 1970",  # unix epoch
        ]

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    def _is_whitelisted(self, date_str):
        return any(
            date_str.lower() == whitelist_date.lower()
            for whitelist_date in self.whitelist_dates
        )

    async def scan_numerical_dates(self, text):
        findings = []
        try:
            for pattern in self.numerical_date_patterns:
                for match in pattern.finditer(text):
                    date_str = match.group()

                    if self._is_whitelisted(date_str):
                        continue

                    context = self._get_context(text, match.start(), match.end())

                    if self._contains_keyword(context, self.dob_keywords):
                        findings.append(
                            {"type": "DOB", "content": date_str, "context": context}
                        )
                        self.logger.debug(
                            f"found potential DOB (numerical): {date_str}"
                        )
        except Exception as e:
            self.logger.error(f"error scanning numerical dates: {e}")
        return findings

    async def scan_text_dates(self, text):
        findings = []
        try:
            for pattern in self.text_date_patterns:
                for match in pattern.finditer(text):
                    date_str = match.group()

                    if self._is_whitelisted(date_str):
                        continue

                    context = self._get_context(text, match.start(), match.end())

                    if self._contains_keyword(context, self.dob_keywords):
                        findings.append(
                            {"type": "DOB", "content": date_str, "context": context}
                        )
                        self.logger.debug(f"found potential DOB (text): {date_str}")
        except Exception as e:
            self.logger.error(f"error scanning text dates: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_numerical_dates(text))
            findings.extend(await self.scan_text_dates(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
