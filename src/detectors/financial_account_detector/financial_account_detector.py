import logging
import re


class Detector:
    description = "Financial Account Number Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-financial-account"
        self.logger = logging.getLogger(self.name)

        self.account_patterns = [
            # standard bank account number (8-17 digits)
            re.compile(r"\b\d{8,17}\b"),
            # account number with dashes
            re.compile(r"\b\d{2,4}[-]\d{3,4}[-]\d{3,10}\b"),
            # account number with spaces
            re.compile(r"\b\d{2,4}\s\d{3,4}\s\d{3,10}\b"),
        ]

        self.account_keywords = [
            "account number",
            "account #",
            "account no",
            "acct number",
            "acct #",
            "acct no",
            "bank account",
            "checking account",
            "savings account",
            "deposit account",
            "account balance",
            "routing number",
            "aba number",
            "wire transfer",
            "direct deposit",
            "bank transfer",
            "account details",
            "beneficiary account",
            "bank details",
            "account information",
            "financial account",
            "bank statement",
            "account statement",
            "electronic transfer",
            "ach transfer",
            "bank routing",
            "account holder",
            "joint account",
            "primary account",
            "secondary account",
            "money market account",
            "investment account",
            "brokerage account",
            "retirement account",
        ]

        # test and commonly used demo account numbers
        self.account_whitelist = {
            "000000000",
            "111111111",
            "123456789",
            "987654321",
            "999999999",
            "12345-678-90123",
            "1234 5678 9012",
            "0000-000-00000",
            "1111-111-11111",
            "9999-999-99999",
            "12340056789",
            "98765432100",
            "11112222333",
            "44445555666",
            "77778888999",
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_account_numbers(self, text):
        findings = []
        try:
            for pattern in self.account_patterns:
                for match in pattern.finditer(text):
                    account = match.group()

                    # remove any spaces or dashes for whitelist comparison
                    clean_account = re.sub(r"[\s-]", "", account)

                    if clean_account in self.account_whitelist:
                        self.logger.debug(
                            f"skipping whitelisted account number: {account}"
                        )
                        continue

                    context = self._get_context(text, match.start(), match.end())
                    if self._contains_keyword(context, self.account_keywords):
                        findings.append(
                            {
                                "type": "FINANCIAL_ACCOUNT_NUMBER",
                                "content": account,
                                "context": context,
                            }
                        )
                        self.logger.debug(f"found potential account number: {account}")
        except Exception as e:
            self.logger.error(f"error scanning account numbers: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_account_numbers(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
