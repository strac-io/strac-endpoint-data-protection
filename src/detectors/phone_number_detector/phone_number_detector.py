import logging
import re


class Detector:
    description = "Phone Number Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-phone"
        self.logger = logging.getLogger(self.name)

        # phone number patterns
        self.phone_patterns = [
            # us formats - with and without country code
            re.compile(
                r"\b\+?1?[-.]?\s*\(?([0-9]{3})\)?[-.\s]*([0-9]{3})[-.\s]*([0-9]{4})\b"
            ),  # +1 (xxx) xxx-xxxx or variations
            re.compile(
                r"\b\(?([0-9]{3})\)?[-.\s]*([0-9]{3})[-.\s]*([0-9]{4})\b"
            ),  # (xxx) xxx-xxxx or variations
            re.compile(
                r"\b([0-9]{3})([0-9]{3})([0-9]{4})\b"
            ),  # xxxxxxxxxx (no separators)
            re.compile(r"\b([0-9]{3})\.([0-9]{3})\.([0-9]{4})\b"),  # xxx.xxx.xxxx
            # international formats
            # +{country-code} format with flexible length
            re.compile(
                r"\b\+[1-9][0-9]{0,3}[-.\s]*\(?([0-9]{1,4})\)?[-.\s]*([0-9]{2,12})\b"
            ),
            # 00{country-code} format with flexible length
            re.compile(
                r"\b00[1-9][0-9]{0,3}[-.\s]*\(?([0-9]{1,4})\)?[-.\s]*([0-9]{2,12})\b"
            ),
            # common international formats without country code
            re.compile(
                r"\b([0-9]{2})[-.\s]([0-9]{4})[-.\s]([0-9]{4})\b"
            ),  # xx xxxx xxxx
            re.compile(r"\b([0-9]{2})([0-9]{4})([0-9]{4})\b"),  # xxxxxxxxxxxx
            re.compile(r"\b([0-9]{2})\.([0-9]{4})\.([0-9]{4})\b"),  # xx.xxxx.xxxx
            # specific country formats
            # uk: +44 xxxx xxxxxx or +44 xxx xxxx xxxx
            re.compile(r"\b\+?44[-.\s]*\(?([0-9]{3,5})\)?[-.\s]*([0-9]{6,8})\b"),
            # australia: +61 x xxxx xxxx
            re.compile(
                r"\b\+?61[-.\s]*\(?([0-9]{1})\)?[-.\s]*([0-9]{4})[-.\s]*([0-9]{4})\b"
            ),
            # india: +91 xxxxx xxxxx
            re.compile(r"\b\+?91[-.\s]*\(?([0-9]{5})\)?[-.\s]*([0-9]{5})\b"),
            # china: +86 xxx xxxx xxxx
            re.compile(
                r"\b\+?86[-.\s]*\(?([0-9]{3})\)?[-.\s]*([0-9]{4})[-.\s]*([0-9]{4})\b"
            ),
            # variations without separators
            re.compile(
                r"\b\+?[1-9][0-9]{1,3}([0-9]{6,14})\b"
            ),  # +{country-code}xxxxxxxxx
            re.compile(
                r"\b00[1-9][0-9]{1,3}([0-9]{6,14})\b"
            ),  # 00{country-code}xxxxxxxxx
            # period-separated variations
            re.compile(r"\b\+?[1-9][0-9]{0,3}\.([0-9]{1,4})\.([0-9]{2,12})\b"),
            re.compile(r"\b([0-9]{1,4})\.([0-9]{3,4})\.([0-9]{3,4})\b"),
        ]

        self.phone_keywords = [
            # general
            "phone",
            "phone number",
            "telephone",
            "tel",
            "mobile",
            "cell",
            "contact",
            "call",
            "dial",
            "number",
            "phone line",
            "landline",
            "fax",
            # international variants
            "international",
            "country code",
            "dial code",
            "ext",
            "extension",
            # business context
            "customer service",
            "support line",
            "helpline",
            "hotline",
            "reception",
            "switchboard",
            "front desk",
            "office phone",
            # common prefixes
            "tel:",
            "phone:",
            "mobile:",
            "cell:",
            "fax:",
            "direct line:",
            "office:",
            # international terms
            "téléphone",  # french
            "telefon",  # german
            "teléfono",  # spanish
            "telefone",  # portuguese
            "電話",  # japanese
            "电话",  # chinese simplified
            "전화",  # korean
        ]

        # test and commonly used demo phone numbers
        self.phone_whitelist = {
            # us numbers with different separators
            "0000000000",
            "000.000.0000",
            "000-000-0000",
            "(000)0000000",
            "(000) 000 0000",
            "1111111111",
            "111.111.1111",
            "111-111-1111",
            "(111)1111111",
            "12345678900",
            "123.456.7890",
            "123-456-7890",
            "(123)4567890",
            "5555555555",
            "555.555.5555",
            "555-555-5555",
            "(555)5555555",
            # international numbers with different formats
            "+442071234567",
            "+44.207.123.4567",
            "+44 20 7123 4567",
            "00442071234567",
            "+33123456789",
            "+33.1.23.45.67.89",
            "+33 1 23 45 67 89",
            "+4930123456789",
            "+49.30.1234.5678",
            "+49 30 1234 5678",
            "+81312345678",
            "+81.3.1234.5678",
            "+86.10.1234.5678",
            "+61.2.1234.5678",
            # other test/example numbers
            "+12345678900",
            "+44.7700.900000",
            "+33612345678",
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_phone_numbers(self, text):
        findings = []
        try:
            for pattern in self.phone_patterns:
                for match in pattern.finditer(text):
                    phone = match.group()

                    # normalize the number for whitelist check
                    normalized_phone = re.sub(r"[\s\-\(\)\.]", "", phone)
                    if normalized_phone in self.phone_whitelist:
                        self.logger.debug(f"skipping whitelisted phone number: {phone}")
                        continue

                    context = self._get_context(text, match.start(), match.end())
                    if self._contains_keyword(context, self.phone_keywords):
                        findings.append(
                            {
                                "type": "PHONE_NUMBER",
                                "content": phone,
                                "context": context,
                            }
                        )
                        self.logger.debug(f"found potential phone number: {phone}")
        except Exception as e:
            self.logger.error(f"error scanning phone numbers: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_phone_numbers(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
