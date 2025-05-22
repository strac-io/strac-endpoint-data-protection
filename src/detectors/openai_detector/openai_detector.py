import json
import logging
import os

import httpx


class Detector:
    description = "OpenAI PHI/PII Detector"
    version = "1.0"

    # prompt template used for openai api
    PROMPT_TEMPLATE = """You are a PHI (Protected Health Information) and PII (Personally Identifiable Information) detection system.
    
    Analyze the following text and identify any PHI or PII information. If found, extract and label each piece.
    Only respond in valid JSON format with two fields:
    - "has_sensitive_data": boolean
    - "findings": array of objects with "type" and "content" fields
    
    Do not include any explanations or additional text.
    
    Example response:
    {
        "has_sensitive_data": true,
        "findings": [
            {"type": "NAME", "content": "John Smith"},
            {"type": "DOB", "content": "01/15/1980"}
        ]
    }

    Text to analyze:
    ###
    {text}
    ###"""

    def __init__(self):
        self.name = "detector-openai-phi-pii"
        self.logger = logging.getLogger(self.name)

        # get api key from environment variable
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            self.logger.error("openai api key not found in environment variables")
            raise ValueError("OPENAI_API_KEY environment variable is required")

        self.api_url = "https://api.openai.com/v1/chat/completions"
        self.model = "gpt-4"  # can be configured to use different models

        # create async client that will be reused
        self.client = httpx.AsyncClient()

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def _call_openai_api(self, text):
        # prepare the prompt
        prompt = self.PROMPT_TEMPLATE.format(text=text)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a PHI/PII detection system that only responds in JSON format.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,  # low temperature for more consistent results
        }

        try:
            response = await self.client.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=30.0,  # add reasonable timeout
            )

            if response.status_code != 200:
                self.logger.error(f"openai api error: {response.status_code}")
                return None

            result = response.json()
            return json.loads(result["choices"][0]["message"]["content"])

        except httpx.TimeoutException:
            self.logger.error("timeout calling openai api")
            return None
        except Exception as e:
            self.logger.error(f"error calling openai api: {e}")
            return None

    async def scan_text(self, text):
        findings = []
        try:
            api_response = await self._call_openai_api(text)

            if api_response and api_response.get("has_sensitive_data"):
                for finding in api_response.get("findings", []):
                    findings.append(
                        {
                            "type": "OPENAI_FOUND_TEXT",
                            "content": finding["content"],
                            "context": text,  # include full text as context
                            "subtype": finding[
                                "type"
                            ],  # include openai's classification
                        }
                    )
                    self.logger.debug(
                        f"found potential sensitive data: {finding['type']}"
                    )
        except Exception as e:
            self.logger.error(f"error scanning text: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_text(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
