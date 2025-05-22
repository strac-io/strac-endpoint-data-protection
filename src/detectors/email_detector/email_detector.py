import logging
import re


class Detector:
    description = "Email Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-email"
        self.logger = logging.getLogger(self.name)

        # email pattern based on rfc-5322
        self.email_pattern = re.compile(
            r"""(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])""",
            re.IGNORECASE,
        )

        self.email_keywords = [
            "email",
            "e-mail",
            "mail",
            "contact",
            "address",
            "send to",
            "reply to",
            "cc",
            "bcc",
            "from",
            "to",
            "recipient",
            "sender",
            "mailing list",
            "distribution list",
            "subscribe",
            "unsubscribe",
            "contact us",
            "reach out",
            "get in touch",
            "email address",
            "inbox",
            "outbox",
            "correspondence",
        ]

        # test and commonly used demo email addresses
        self.email_whitelist = {
            "test@example.com",
            "user@example.com",
            "admin@example.com",
            "info@example.com",
            "support@example.com",
            "noreply@example.com",
            "demo@example.com",
            "sample@example.com",
            "test@test.com",
            "user@localhost",
            "admin@localhost",
            # common dev domains
            "test@dev.local",
            "test@development.local",
            "test@staging.local",
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_email(self, text):
        findings = []
        try:
            for match in self.email_pattern.finditer(text):
                email = match.group()

                if email.lower() in self.email_whitelist:
                    self.logger.debug(f"skipping whitelisted email: {email}")
                    continue

                context = self._get_context(text, match.start(), match.end())
                if self._contains_keyword(context, self.email_keywords):
                    findings.append(
                        {"type": "EMAIL", "content": email, "context": context}
                    )
                    self.logger.debug(f"found potential email: {email}")
        except Exception as e:
            self.logger.error(f"error scanning emails: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_email(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
