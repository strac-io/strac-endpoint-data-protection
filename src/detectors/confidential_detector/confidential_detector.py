import logging
import re


class Detector:
    description = "Confidential Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-confidential"
        self.logger = logging.getLogger(self.name)

        # confidential phrases
        self.confidential_phrases = [
            # general confidentiality phrases
            r"Company Confidential",
            r"For Internal Use Only",
            r"Internal Use Only",
            r"Confidential Information – Do Not Distribute",
            r"Proprietary Information",
            r"Confidential & Proprietary",
            r"Strictly Confidential",
            r"Restricted Access",
            r"For [A-Za-z0-9\s]+ Employees Only",
            r"Not for External Distribution",
            r"Sensitive Material",
            # legal and restricted distribution phrases
            r"Attorney-Client Privileged Information",
            r"Privileged and Confidential",
            r"Confidential Information Subject to NDA",
            r"Protected by Confidentiality Agreement",
            r"Disclosure Restricted Under NDA",
            r"Information Covered by NDA",
            # specific use and handling instructions
            r"Do Not Share Externally",
            r"For Authorized Personnel Only",
            r"Not to be Shared Outside [A-Za-z0-9\s]+",
            r"Internal Distribution Only",
            r"Restricted Document",
            r"Do Not Forward",
            # variants for email and digital communications
            r"This Message Contains Confidential Information",
            r"Confidential Message – Do Not Disclose",
            r"Please Handle as Confidential",
            r"For Internal Recipients Only",
            r"For Private Distribution Only",
            # financial and intellectual property specific
            r"Financially Sensitive Information",
            r"Trade Secrets – Handle with Care",
            r"Intellectual Property of [A-Za-z0-9\s]+",
            r"Sensitive Financial Data – Internal Use Only",
            r"Confidential Research Data",
            r"Confidential Financial Projections",
        ]

        # contextual words that surround confidentiality phrases
        self.contextual_keywords = [
            r"Warning",
            r"Notice",
            r"Caution",
            r"Confidential",
            r"Restricted Distribution",
            r"Confidential & Proprietary",
            r"For Internal Use Only",
        ]

        # compile phrases into regex patterns
        self.phrase_patterns = [
            re.compile(phrase, re.IGNORECASE) for phrase in self.confidential_phrases
        ]

        # compile contextual keywords into regex patterns
        self.contextual_patterns = [
            re.compile(keyword, re.IGNORECASE) for keyword in self.contextual_keywords
        ]

    def _contains_contextual_keyword(self, text):
        return any(pattern.search(text) for pattern in self.contextual_patterns)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_confidential_phrases(self, text):
        findings = []
        try:
            for pattern in self.phrase_patterns:
                for match in pattern.finditer(text):
                    phrase = match.group()
                    context = self._get_context(text, match.start(), match.end())
                    # check for contextual keywords in the surrounding text
                    if self._contains_contextual_keyword(context):
                        findings.append(
                            {
                                "type": "CONFIDENTIAL_PHRASE",
                                "content": phrase,
                                "context": context,
                            }
                        )
                        self.logger.debug(f"found confidential phrase: {phrase}")
                    else:
                        # even if no contextual keyword is found, still record the phrase
                        findings.append(
                            {
                                "type": "CONFIDENTIAL_PHRASE",
                                "content": phrase,
                                "context": context,
                            }
                        )
                        self.logger.debug(
                            f"found confidential phrase without context: {phrase}"
                        )
        except Exception as e:
            self.logger.error(f"error scanning for confidential phrases: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_confidential_phrases(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
