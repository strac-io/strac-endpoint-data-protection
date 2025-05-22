import logging
import re


class Detector:
    description = "IP Address Detector"
    version = "1.0"

    def __init__(self):
        self.name = "detector-ip"
        self.logger = logging.getLogger(self.name)

        ipv4_pattern = r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

        ipv6_pattern = r"(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"

        self.ip_patterns = [
            re.compile(rf"\b{ipv4_pattern}\b"),
            re.compile(rf"\b{ipv6_pattern}\b"),
        ]

        self.ip_keywords = [
            "IP address",
            "IP addr",
            "IPv4",
            "IPv6",
            "host",
            "server",
            "gateway",
            "router",
            "subnet",
            "network address",
            "destination",
            "source IP",
            "dest IP",
            "localhost",
            "LAN address",
            "WAN address",
        ]

        self.ip_whitelist = {
            # localhost/loopback addresses
            "127.0.0.1",
            "::1",
            # private addresses
            "10.0.0.0",
            "172.16.0.0",
            "192.168.0.0",
            "192.168.1.1",
            # link-local addresses
            "169.254.0.0",
            # docs/example addresses
            "192.0.2.0",
            "198.51.100.0",
            "203.0.113.0",
            # ipv6 documentation addresses
            "2001:db8::",
            # multicast addresses
            "224.0.0.0",
            "ff00::",
        }

    def _contains_keyword(self, text, keywords):
        return any(keyword.lower() in text.lower() for keyword in keywords)

    def _get_context(self, text, start, end, context_window=100):
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]

    async def scan_ip(self, text):
        findings = []
        try:
            for pattern in self.ip_patterns:
                for match in pattern.finditer(text):
                    ip = match.group()

                    # Skip if IP is in whitelist
                    if any(
                        ip.startswith(whitelisted) for whitelisted in self.ip_whitelist
                    ):
                        self.logger.debug(f"skipping whitelisted IP: {ip}")
                        continue

                    context = self._get_context(text, match.start(), match.end())
                    if self._contains_keyword(context, self.ip_keywords):
                        ip_type = "IPV6" if ":" in ip else "IPV4"
                        findings.append(
                            {"type": ip_type, "content": ip, "context": context}
                        )
                        self.logger.debug(f"found potential {ip_type}: {ip}")
        except Exception as e:
            self.logger.error(f"error scanning ip addresses: {e}")
        return findings

    async def process_text(self, text):
        findings = []
        try:
            findings.extend(await self.scan_ip(text))
        except Exception as e:
            self.logger.error(f"error processing text: {e}")
        return findings
