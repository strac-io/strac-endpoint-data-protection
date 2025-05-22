import asyncio
import logging
import re
from datetime import datetime


class Detector:
    description = "PCI Detector"
    version = "1.8"

    def __init__(self):
        self.name = "detector-pci"
        self.logger = logging.getLogger(self.name)

        # compiles regex patterns once during initialization
        self.cc_patterns = [
            # visa
            re.compile(r"\b4\d{3}-\d{4}-\d{4}-\d{4}\b"),
            re.compile(r"\b4\d{3} \d{4} \d{4} \d{4}\b"),
            re.compile(r"\b4\d{15}\b"),
            # mastercard
            re.compile(r"\b5[1-5]\d{2}-\d{4}-\d{4}-\d{4}\b"),
            re.compile(r"\b5[1-5]\d{2} \d{4} \d{4} \d{4}\b"),
            re.compile(r"\b5[1-5]\d{14}\b"),
            re.compile(r"\b2[2-7]\d{2}-\d{4}-\d{4}-\d{4}\b"),
            re.compile(r"\b2[2-7]\d{2} \d{4} \d{4} \d{4}\b"),
            re.compile(r"\b2[2-7]\d{14}\b"),
            # amex
            re.compile(r"\b3[47]\d{2} \d{6} \d{5}\b"),
            re.compile(r"\b3[47]\d{2}-\d{6}-\d{5}\b"),
            re.compile(r"\b3[47]\d{13}\b"),
            # discover
            re.compile(r"\b6011-\d{4}-\d{4}-\d{4}\b"),
            re.compile(r"\b6011 \d{4} \d{4} \d{4}\b"),
            re.compile(r"\b6011\d{12}\b"),
            re.compile(r"\b64[4-9]\d-\d{4}-\d{4}-\d{4}\b"),
            re.compile(r"\b64[4-9]\d \d{4} \d{4} \d{4}\b"),
            re.compile(r"\b64[4-9]\d{13}\b"),
            re.compile(r"\b65\d{2}-\d{4}-\d{4}-\d{4}\b"),
            re.compile(r"\b65\d{2} \d{4} \d{4} \d{4}\b"),
            re.compile(r"\b65\d{14}\b"),
            # diners club
            re.compile(r"\b30[0-5]\d-\d{6}-\d{4}\b"),
            re.compile(r"\b30[0-5]\d \d{6} \d{4}\b"),
            re.compile(r"\b30[0-5]\d{11}\b"),
            re.compile(r"\b3[689]\d{2}-\d{6}-\d{4}\b"),
            re.compile(r"\b3[689]\d{2} \d{6} \d{4}\b"),
            re.compile(r"\b3[689]\d{12}\b"),
            # jcb
            re.compile(r"\b352[89]-\d{4}-\d{4}-\d{4}\b"),
            re.compile(r"\b352[89] \d{4} \d{4} \d{4}\b"),
            re.compile(r"\b352[89]\d{12}\b"),
            re.compile(r"\b35[3-8]\d-\d{4}-\d{4}-\d{4}\b"),
            re.compile(r"\b35[3-8]\d \d{4} \d{4} \d{4}\b"),
            re.compile(r"\b35[3-8]\d{13}\b"),
        ]

        # cvv contextual keywords
        self.cvv_keywords = ["CVV", "CVC", "CVV2", "CID"]

        # expiration contextual keywords
        self.expiration_keywords = [
            "Exp",
            "Expires",
            "Expiration Date",
            "Good Through",
            "Good Thru",
            "Good Until",
            "Valid Through",
            "Valid Thru",
            "Valid Until",
        ]

        # cvv patterns
        self.cvv_patterns = [
            re.compile(r"\b([0-9]{3,4})\b"),
        ]

        # expiration patterns
        self.exp_date_patterns = [
            re.compile(r"\b((0[1-9]|1[0-2])/(?:[0-9]{2}|20[0-9]{2}))\b"),
        ]

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    # implements defaco luhn algo
    def _luhn_check(self, card_number):
        try:
            digits = [int(d) for d in card_number]
            checksum = 0
            parity = len(digits) % 2
            for i, digit in enumerate(digits):
                if i % 2 == parity:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                checksum += digit
            return checksum % 10 == 0
        except Exception as e:
            self.logger.error(f"error in luhn check for: {card_number} error: {e}")
            return False

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    def _validate_expiration_date(self, date_str):
        try:
            if "/" in date_str:
                parts = date_str.split("/")
                month = int(parts[0])
                year = int(parts[1])
                if year < 100:  # YY format
                    year += 2000
                exp_date = datetime(year, month, 1)
                current_date = datetime.now()
                lower_valid_date = current_date.replace(year=current_date.year - 10)
                upper_valid_date = current_date.replace(year=current_date.year + 10)
                if lower_valid_date <= exp_date <= upper_valid_date:
                    return True
            return False
        except Exception as e:
            self.logger.error(f"error validating CC_EXPIRATION: {date_str} error: {e}")
            return False

    async def scan_credit_card_numbers(self, text):
        findings = []
        try:
            for pattern in self.cc_patterns:
                for match in pattern.finditer(text):
                    cc_number = re.sub(r"[\s-]", "", match.group())
                    if 13 <= len(cc_number) <= 16:
                        is_valid = await self.validate_credit_card(cc_number)
                        if is_valid:
                            context = self._get_context(
                                text, match.start(), match.end()
                            )
                            findings.append(
                                {
                                    "type": "CC_NUMBER",
                                    "content": cc_number,
                                    "context": context,
                                }
                            )
                            self.logger.debug(f"found valid CC_NUMBER: {cc_number}")
        except Exception as e:
            self.logger.error(f"error scanning CC_NUMBERs: {e}")
        return findings

    async def validate_credit_card(self, card_number):
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._luhn_check, card_number)
        except Exception as e:
            self.logger.error(f"error validating CC_NUMBER: {card_number} error: {e}")
            return False

    async def scan_cvv(self, text):
        findings = []
        try:
            for pattern in self.cvv_patterns:
                for match in pattern.finditer(text):
                    cvv = match.group(1)
                    if 3 <= len(cvv) <= 4:
                        context = self._get_context(
                            text, match.start(), match.end(), context_window=30
                        )
                        # checks for CC_CVV contextual keywords OR valid CC_NUMBER in context
                        if self._contains_keyword(
                            context, self.cvv_keywords
                        ) or await self.find_valid_credit_card_in_text(context):
                            findings.append(
                                {"type": "CC_CVV", "content": cvv, "context": context}
                            )
                            self.logger.debug(f"found potential CC_CVV: {cvv}")
        except Exception as e:
            self.logger.error(f"error scanning CC_CVVs: {e}")
        return findings

    async def scan_expiration_dates(self, text):
        findings = []
        try:
            for pattern in self.exp_date_patterns:
                for match in pattern.finditer(text):
                    exp_date_str = match.group(1)
                    if self._validate_expiration_date(exp_date_str):
                        context = self._get_context(
                            text, match.start(), match.end(), context_window=30
                        )
                        # checks for CC_EXPIRATION contextual keywords OR valid CC_NUMBER in context
                        if self._contains_keyword(
                            context, self.expiration_keywords
                        ) or await self.find_valid_credit_card_in_text(context):
                            findings.append(
                                {
                                    "type": "CC_EXPIRATION",
                                    "content": exp_date_str,
                                    "context": context,
                                }
                            )
                            self.logger.debug(
                                f"found potential CC_EXPIRATION: {exp_date_str}"
                            )
        except Exception as e:
            self.logger.error(f"error scanning CC_EXPIRATIONs: {e}")
        return findings

    async def find_valid_credit_card_in_text(self, text):
        try:
            for pattern in self.cc_patterns:
                for match in pattern.finditer(text):
                    cc_number = re.sub(r"[\s-]", "", match.group())
                    if 13 <= len(cc_number) <= 16:
                        is_valid = await self.validate_credit_card(cc_number)
                        if is_valid:
                            self.logger.debug(
                                f"found valid CC_NUMBER in context: {cc_number}"
                            )
                            return True
            return False
        except Exception as e:
            self.logger.error(f"error finding credit card in context: {e}")
            return False

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_credit_card_numbers(text))
            findings.extend(await self.scan_cvv(text))
            findings.extend(await self.scan_expiration_dates(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
