import concurrent.futures
import logging
import logging.handlers
import os
import socket
import subprocess
from datetime import datetime

from rich.console import Console
from rich.table import Table

from config import (
    APP_NAME,
    PF_BLOCKED_SITES_PATH,
    PF_IGNORE_IPS,
    PF_IGNORED_SITES_PATH,
    PF_RULES_ORIGINAL_PATH,
    PF_RULES_PATH,
)
from storage.database import (
    ManagerHistory,
    ManagerStatus,
    NetworkFilterBlockedSite,
    NetworkFilterCurrentRules,
    NetworkFilterDomainIPTranslation,
    NetworkFilterOriginalDefaultRules,
    NetworkFilterRuleUpdateHistory,
    NetworkFilterWebsiteBlockHistory,
    NetworkInitialConfig,
)
from utils import is_valid_ip, remove_trailing_empty_lines, resolve_domain

console = Console()


class Filter:
    """Network filtering manager that handles packet filtering rules and website blocking.

    This class provides functionality to manage network filtering rules using OpenBSD's
    Packet Filter (PF). It can block/unblock domains or IPs, manage PF rules, and maintain
    a history of blocked sites.

    Example:
        >>> filter = Filter()
        >>> filter.start()  # Start the packet filter
        >>> filter.add_block_rule("example.com")  # Block a domain
        >>> filter.view_current_packet_filter_rules()  # View active rules
        >>> filter.stop()  # Stop the packet filter
    """

    def __init__(self):
        self.name = "manager-network"
        self.logger = logging.getLogger(self.name)

        _, _ = ManagerStatus.get_or_create(
            name=self.name,
            defaults={
                "should_run": False,
                "is_running": False,
                "last_updated": datetime.now(),
            },
        )

    def _log_action(self, action, success=True, message=None):
        """
        Log an action performed by the network filter manager.

        Args:
            action (str): The action performed (e.g., 'start', 'stop', 'add_block_rule').
            success (bool, optional): Whether the action was successful. Defaults to True.
            message (str, optional): Additional message or details about the action. Defaults to None.
        """
        ManagerHistory.create(
            name=self.name,
            action=action,
            timestamp=datetime.now(),
            success=success,
            message=message,
        )

    def _update_status(self, should_run=None, is_running=None):
        """
        Update the status of the network filter manager.

        Args:
            should_run (bool, optional): Desired 'should_run' status. Defaults to None.
            is_running (bool, optional): Desired 'is_running' status. Defaults to None.
        """
        status = ManagerStatus.get(ManagerStatus.name == self.name)
        if should_run is not None:
            status.should_run = should_run
        if is_running is not None:
            status.is_running = is_running
        status.last_updated = datetime.now()
        status.save()

    def get_ip(self, url):
        url = url.strip()
        if "://" in url:
            url = url.split("://", 1)[1]
        if "/" in url:
            url = url.split("/", 1)[0]
        if url.startswith("."):
            url = url[1:]

        try:
            hostname, aliases, ip_addresses = socket.gethostbyname_ex(url)
            return url, ip_addresses, True  # success flag
        except socket.gaierror:
            return url, "could not resolve", False
        except Exception as e:
            return url, f"error: {e}", False

    def process_urls(self, urls, output_file=PF_BLOCKED_SITES_PATH):
        try:
            # uses threadpoolexecutor for parallel processing
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                results = list(executor.map(self.get_ip, urls))

            successful_count = 0
            failed_count = 0
            # open file to store resolved URLs
            with open(output_file, "w") as f_out:
                # process results
                for url, ip_result, success in results:
                    if success:
                        # write successfully resolved URLs to the output file as one IP per line
                        for ip in ip_result:
                            if (
                                output_file == PF_BLOCKED_SITES_PATH
                                and ip in PF_IGNORE_IPS
                            ):
                                self.logger.debug(f"ignoring ip: {ip}")
                                continue
                            f_out.write(f"{ip}\n")
                        successful_count += 1
                    else:
                        failed_count += 1
                        self.logger.warning(
                            f"Failed to resolve URL: {url} - {ip_result}"
                        )

            self.logger.debug(
                f"URL processing complete: {successful_count} successful, {failed_count} failed"
            )

            if successful_count == 0 and len(urls) > 0:
                self.logger.error(
                    "No URLs were successfully resolved despite having input URLs"
                )

            return successful_count, failed_count

        except Exception as e:
            self.logger.error(f"Error processing urls to ips: {e}")
            return 0, len(urls)

    def trigger(self):
        """Check if service should be running and print status"""
        status = ManagerStatus.get(ManagerStatus.name == self.name)
        if status.should_run and not status.is_running:
            return "[yellow]'{self.name}' should be running but is not[/yellow]"
        elif not status.should_run and status.is_running:
            return "[yellow]'{self.service_name}' should be stopped but is running[/yellow]"
        elif status.should_run and status.is_running:
            return "[blue]'{self.name}' is running as it should be[/blue]"
        else:
            return "[yellow]'{self.name}' is stopped as it should be[/yellow]"

    def start(self, domains_to_block=None, domains_to_ignore=None):
        """Start the packet filter if it's not already running.

        This method enables PF and loads the rules from the configured rules file.

        Example:
            >>> filter = Filter()
            >>> filter.start()
            Auditor has been started.
        """
        if not domains_to_block or len(domains_to_block) == 0:
            domains_to_block = ["digg.com"]
            self.logger.warning(
                f"No domains specified, using default: {domains_to_block}"
            )

        # process blocked urls to ips
        blocked_successful, blocked_failed = self.process_urls(
            domains_to_block, PF_BLOCKED_SITES_PATH
        )

        if not domains_to_ignore or len(domains_to_ignore) == 0:
            domains_to_ignore = PF_IGNORE_IPS
            self.logger.warning(
                f"No ignored domains specified, using default: {domains_to_ignore}"
            )

        # process ignored urls to ips
        ignored_successful, ignored_failed = self.process_urls(
            domains_to_ignore, PF_IGNORED_SITES_PATH
        )

        if blocked_successful == 0 and len(domains_to_block) > 0:
            self.logger.warning("Could not resolve any of the provided domains to IPs.")
            return "[yellow]Failed to start the network manager: Could not resolve any domains to IP addresses[/yellow]"

        status = ManagerStatus.get(ManagerStatus.name == self.name)
        if self.is_packet_filter_running() and status.is_running:
            self._log_action("start", success=False, message="Already running")
            return "[yellow]The network manager is already running.[/yellow]"

        # check if initial config exists
        initial_config = NetworkInitialConfig.select().first()
        if not initial_config or initial_config.content == "latest update":
            self.logger.warning(
                "no initial network config found - writing default config"
            )

            with open(PF_RULES_PATH, "w") as pf_conf:
                # store the lists of vpn interfaces
                pf_conf.write(
                    '\nvpn_interfaces = "{ utun0 utun1 utun2 utun3 utun4 utun5 ipsec0 ppp0 }"\n'
                )
                # store the lists of local interfaces
                pf_conf.write(
                    '\nlocal_interfaces = "{ en0 en1 en2 lo0 bridge0 awdl0 llw0 }"\n'
                )
                # store the lists of blocked ips
                pf_conf.write(
                    f'\ntable <blocked_ips> persist file "{PF_BLOCKED_SITES_PATH}"\n'
                )
                # store the lists of ignored ips
                pf_conf.write(
                    f'\ntable <ignored_ips> persist file "{PF_IGNORED_SITES_PATH}"\n'
                )
                # don't nat vpn traffic that might already be encapsulated
                pf_conf.write("\nno nat on $vpn_interfaces from any to any\n")
                # ignore the ips
                pf_conf.write(
                    "\npass in quick from <ignored_ips> to any\npass out quick from any to <ignored_ips>\n"
                )
                # block the ips
                pf_conf.write(
                    "\nblock in quick from <blocked_ips> to any\nblock out quick from any to <blocked_ips>\n"
                )
                # allow traffic on all vpn interfaces
                pf_conf.write("\npass on $vpn_interfaces all\n")
                # allow traffic on all local interfaces
                pf_conf.write("\npass quick on $local_interfaces all\n")
                # ipsec rules to allow all
                pf_conf.write(
                    "\npass in proto esp\npass in proto ah\npass in proto udp from any to any port 500\npass in proto udp from any to any port 4500\n"
                )
                # openvpn rules to allow all
                pf_conf.write(
                    "\npass in proto udp from any to any port 1194\npass in proto tcp from any to any port 1194\n"
                )
                # wireguard rules to allow all
                pf_conf.write("\npass in proto udp from any to any port 51820\n")
                # pptp rules to allow all
                pf_conf.write(
                    "\npass in proto gre\npass in proto tcp from any to any port 1723\n"
                )
                # l2tp rules to allow all
                pf_conf.write("\npass in proto udp from any to any port 1701\n")
                # cisco anyconnect rules to allow all
                pf_conf.write(
                    "\npass in proto udp from any to any port 8443\npass in proto tcp from any to any port 8443\npass in proto tcp from any to any port 443\n"
                )
                # allow traffic from https and other web ports
                pf_conf.write(
                    "\npass in proto udp from any to any port 8443\npass in proto tcp from any to any port 8443\npass in proto tcp from any to any port 443\npass in proto tcp from any to any port 80\npass out proto tcp to any port 80\npass out proto tcp to any port 443\n"
                )
                # allow outbound dns requests
                pf_conf.write(
                    "\npass out proto udp from any to any port 53\npass out proto tcp from any to any port 53\n"
                )
                # allow traffic on all tun/tap interfaces
                pf_conf.write("\npass on tun0 all\npass on tap0 all\n")
            NetworkInitialConfig.create(content="rules updated")

        # now do the actual work of turning it on
        try:
            subprocess.run(
                [
                    "sudo",
                    "pfctl",
                    "-e",
                    "-f",
                    f"{PF_RULES_PATH}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            self.logger.debug("network manager started")
            self._update_status(should_run=True, is_running=True)
            self._log_action(
                "start",
                message=f"{self.name} started successfully with {blocked_successful} blocked domains and {ignored_successful} ignored domains",
            )
            return f"[blue]The network manager has been [green]started[/green] with [green]{blocked_successful}[/green] blocked domains and [green]{ignored_successful}[/green] ignored domains.[/blue]"
        except subprocess.CalledProcessError as e:
            self.logger.error(f"failed to start: {e}")
            self._log_action("start", success=False, message=str(e))
            return f"[yellow]Failed to start the network manager: [blue]{e}[/blue].[/yellow]"

    def stop(self):
        """Stop the packet filter if it's currently running.

        Example:
            >>> filter = Filter()
            >>> filter.stop()
            Auditor has been stopped.
        """
        status = ManagerStatus.get(ManagerStatus.name == self.name)
        if not self.is_packet_filter_running() and not status.is_running:
            self._log_action("stop", success=False, message="Not running")
            return "[yellow]The network manager is not running.[/yellow]"
        else:
            try:
                subprocess.run(
                    [
                        "sudo",
                        "pfctl",
                        "-d",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                self.logger.debug("pf stopped")
                self._update_status(should_run=False, is_running=False)
                self._log_action("stop", message=f"{self.name} stopped successfully")
                return "[blue]The network manager has been [red]stopped[/red].[/blue]"
            except subprocess.CalledProcessError as e:
                self.logger.error(f"failed to stop: {e}")
                self._log_action("stop", success=False, message=str(e))
                return f"[yellow]Failed to stop the network manager: [blue]{e}[/blue].[/yellow]"

    def status(self):
        """Print the status of the network filter"""
        status = ManagerStatus.get(ManagerStatus.name == self.name)
        # state = "running" if status.is_running else "stopped"
        # should_state = "should be running" if status.should_run else "should be stopped"
        # last_updated = status.last_updated.strftime("%Y-%m-%d %H:%M:%S")
        if status.is_running and self.is_packet_filter_running():
            return (
                True,
                f"[blue]{APP_NAME}.network[/blue] [green]is running as it should be[/green].",
            )
        elif not status.is_running and self.is_packet_filter_running():
            return (
                False,
                f"[blue]{APP_NAME}.network[/blue] [yellow]is running but it shouldn't be[/yellow].",
            )
        elif status.is_running and not self.is_packet_filter_running():
            return (
                False,
                f"[blue]{APP_NAME}.network[/blue] [yellow]is stopped but it should be running[/yellow].",
            )
        else:
            return (
                False,
                f"[blue]{APP_NAME}.network[/blue] [red]is not running[/red].",
            )

    def is_packet_filter_running(self):
        """Check if the packet filter is currently running.

        Returns:
            bool: True if the packet filter is running, False otherwise.

        Example:
            >>> filter = Filter()
            >>> if filter.is_packet_filter_running():
            ...     print("Packet filter is active")
        """
        try:
            # un pfctl command and capture output
            result = subprocess.run(
                ["sudo", "pfctl", "-s", "info"], capture_output=True, text=True
            )
            running = "Status: Enabled" in result.stdout
            self.logger.debug(f"pf running: {str(running)}")
            return running
        except Exception as e:
            self.logger.error(f"error checking pf status: {str(e)}")
            return False

    def view_current_packet_filter_rules(self):
        """Display the current active packet filter rules.

        Prints the rules to the console using rich formatting.

        Example:
            >>> filter = Filter()
            >>> filter.view_current_packet_filter_rules()
        """
        try:
            result = subprocess.run(
                ["sudo", "pfctl", "-s", "rules"], capture_output=True, text=True
            )
            self.logger.debug("current packet filter rules fetched.")
            console.print(result.stdout)
        except Exception as e:
            self.logger.error(
                "failed to fetch current packet filter rules: {}".format(e)
            )

    def reset_packet_filter_rules_to_default(self):
        """Reset packet filter rules to their original default state.

        This method will:
        1. Copy the original rules back to the active rules file
        2. Reload the packet filter
        3. Log the reset action

        Example:
            >>> filter = Filter()
            >>> filter.reset_packet_filter_rules_to_default()
        """
        try:
            if not os.path.exists(PF_RULES_ORIGINAL_PATH):
                self.logger.error("no original packet filter rules file to revert to.")
                return
            subprocess.run(
                ["sudo", "cp", PF_RULES_ORIGINAL_PATH, PF_RULES_PATH], check=True
            )
            subprocess.run(
                ["sudo", "pfctl", "-f", PF_RULES_PATH],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            # log the reset action
            NetworkFilterRuleUpdateHistory.create(changes="reset to default rules")
            self.logger.debug("packet filter rules reset to default.")
        except Exception as e:
            self.logger.error(f"failed to reset packet filter rules: {str(e)}")

    def view_packet_filter_block_history(self):
        """Display the history of blocked websites in a formatted table.

        Shows domain names and timestamps of when they were blocked.

        Example:
            >>> filter = Filter()
            >>> filter.view_packet_filter_block_history()
        """
        try:
            history = NetworkFilterWebsiteBlockHistory.select().order_by(
                NetworkFilterWebsiteBlockHistory.blocked_at.desc()
            )
            table = Table(title="Packet Filter Block History")
            table.add_column("Domain", style="cyan")
            table.add_column("Blocked At", style="magenta")
            for record in history:
                table.add_row(
                    record.domain, record.blocked_at.strftime("%Y-%m-%d %H:%M:%S")
                )
            console.print(table)
            self.logger.debug("block history displayed.")
        except Exception as e:
            self.logger.error("failed to fetch block history: {}".format(e))

    def store_original_default_rules(self):
        """Store the current rules as the original default rules.

        This method saves the current rules both to a file and the database.
        It will only store the rules if they haven't been stored before.

        Returns:
            bool: True if successful, False otherwise.

        Example:
            >>> filter = Filter()
            >>> success = filter.store_original_default_rules()
        """
        try:
            # check if OriginalDefaultRules already has a record
            existing_record = NetworkFilterOriginalDefaultRules.select().first()
            if existing_record:
                self.logger.debug(
                    "original default rules already stored in the database."
                )
                return True

            # read the current packet filter rules
            with open(PF_RULES_PATH, "r") as pf_conf:
                content = pf_conf.read()

            # write the current packet filter rules to the original rules file
            with open(PF_RULES_ORIGINAL_PATH, "w") as pf_conf_original:
                pf_conf_original.write(content)

            # store the rules in the database
            NetworkFilterOriginalDefaultRules.create(content=content)
            self.logger.debug(
                "original default rules have been stored in the database."
            )
            return True

        except Exception as e:
            self.logger.error(f"failed to store original default rules: {e}")
            return False

    def add_block_rule(self, domain_or_ip):
        """Add a blocking rule for a domain or IP address.

        Args:
            domain_or_ip (str): The domain name or IP address to block.

        This method will:
        1. Check if the rule already exists
        2. Resolve domain to IP if necessary
        3. Add the block rule to PF configuration
        4. Update the database with the new rule
        5. Log the change in history

        Example:
            >>> filter = Filter()
            >>> filter.add_block_rule("example.com")  # Block a domain
            >>> filter.add_block_rule("192.168.1.1")  # Block an IP address
        """
        # check if the block rule already exists
        existing_site = (
            NetworkFilterBlockedSite.select()
            .where(
                (NetworkFilterBlockedSite.domain == domain_or_ip)
                | (NetworkFilterBlockedSite.ip_addresses.contains(domain_or_ip))
            )
            .first()
        )
        if existing_site:
            self.logger.debug(f"Block rule for {domain_or_ip} already exists.")
            return f"[yellow]Block rule for [blue]{domain_or_ip}[/blue] already exists.[/yellow]"

        try:
            ip_addresses = [domain_or_ip]
            if not is_valid_ip(domain_or_ip):
                resolved_ips = resolve_domain(domain_or_ip)
                if not resolved_ips:
                    self.logger.error(
                        f"Could not resolve domain {domain_or_ip} to any IP addresses"
                    )
                    return f"[yellow]Could not resolve domain [blue]{domain_or_ip}[/blue] to any IP addresses.[/yellow]"

                ip_addresses = [ip["ip"] for ip in resolved_ips]
                for record in resolved_ips:
                    NetworkFilterDomainIPTranslation.create(
                        domain=domain_or_ip,
                        ip_address=record["ip"],
                        dns_server=record["dns_server"],
                    )

            for ip_address in ip_addresses:
                block_rule = f"\nblock drop from any to {ip_address}\n"
                with open(PF_RULES_PATH, "a") as pf_conf:
                    pf_conf.write(block_rule)

            # log the change
            NetworkFilterBlockedSite.create(
                domain=domain_or_ip, ip_addresses=ip_addresses
            )
            NetworkFilterRuleUpdateHistory.create(
                changes=f"Added block rule for {domain_or_ip}"
            )
            NetworkFilterWebsiteBlockHistory.create(domain=domain_or_ip)
            self.logger.debug(f"Block rule added for {domain_or_ip}")

            # updates the active pf rules
            subprocess.run(
                ["sudo", "pfctl", "-f", PF_RULES_PATH],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )

            # update the current rules in the database
            with open(PF_RULES_PATH, "r") as pf_conf:
                content = pf_conf.read()
            NetworkFilterCurrentRules.create(content=content)

            # check if packet filter is running
            if self.is_packet_filter_running():
                self.logger.debug(
                    "The network manager is running. The new rule has taken effect."
                )
                return f"[green]The network manager is running. The new ([blue]BLOCK - {domain_or_ip}[/blue]) rule has taken effect.[/green]"
            else:
                self.logger.warning(
                    "The network manager is not running. Start the packet filter for the rule to take effect."
                )
                return f"[yellow]The network manager is not running. Start the packet filter for the new ([blue]BLOCK - {domain_or_ip}[/blue]) rule to take effect.[/yellow]"
            # send notification if enabled
            # TODO: implement notifications
        except FileNotFoundError:
            self.logger.error(f"could not find file {PF_RULES_PATH}")
            return f"[yellow]Could not find file [blue]{PF_RULES_PATH}[/blue].[/yellow]"
        except PermissionError:
            self.logger.error(f"no permission to modify {PF_RULES_PATH}")
            return f"[yellow]No permission to modify [blue]{PF_RULES_PATH}[/blue].[/yellow]"
        except Exception as e:
            self.logger.error(f"failed to add block rule: {e}")
            return f"[yellow]Failed to add block rule: [blue]{e}[/blue].[/yellow]"

    def remove_block_rule(self, domain_or_ip):
        """Remove a blocking rule for a domain or IP address.

        Args:
            domain_or_ip (str): The domain name or IP address to unblock.

        This method will:
        1. Check if the rule exists
        2. Remove the rule from PF configuration
        3. Update the database
        4. Log the change in history

        Example:
            >>> filter = Filter()
            >>> filter.remove_block_rule("example.com")
        """
        try:
            # check if the block rule exists
            blocked_site = (
                NetworkFilterBlockedSite.select()
                .where(
                    (NetworkFilterBlockedSite.domain == domain_or_ip)
                    | (NetworkFilterBlockedSite.ip_addresses.contains(domain_or_ip))
                )
                .first()
            )
            if not blocked_site:
                self.logger.debug(f"No block rule exists for {domain_or_ip}.")
                return f"[yellow]No [blue]BLOCK[/blue] rule exists for [blue]{domain_or_ip}[/blue].[/yellow]"

            # remove the rule from PF_RULES_PATH
            with open(PF_RULES_PATH, "r") as pf_conf:
                lines = pf_conf.readlines()

            kept_lines = []
            removed_count = 0

            for line in lines:
                line = line.strip()
                should_keep = True

                for ip in blocked_site.ip_addresses:
                    if f"block drop from any to {ip}" in line:
                        should_keep = False
                        removed_count += 1
                        break

                if should_keep:
                    kept_lines.append(line + "\n")

            kept_lines = remove_trailing_empty_lines(kept_lines)

            with open(PF_RULES_PATH, "w") as pf_conf:
                pf_conf.writelines(kept_lines)

            subprocess.run(
                ["sudo", "pfctl", "-f", PF_RULES_PATH],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )

            # remove from the database
            blocked_site.delete_instance()
            self.logger.debug(f"Block rule for {domain_or_ip} removed.")

            # log the change
            NetworkFilterRuleUpdateHistory.create(
                changes=f"Removed block rule for {domain_or_ip}"
            )

            # update current rules in the database
            with open(PF_RULES_PATH, "r") as pf_conf:
                content = pf_conf.read()
            NetworkFilterCurrentRules.create(content=content)

            # check if packet filter is running
            if self.is_packet_filter_running():
                self.logger.debug(
                    "The network manager is running. The rule has been removed."
                )
                return f"[green]The network manager is running. The ([blue]BLOCK - {domain_or_ip}[/blue]) rule has been removed.[/green]"
            else:
                self.logger.warning(
                    "The network manager is not running. Start the packet filter for changes to take effect."
                )
                return f"[yellow]The ([blue]BLOCK - {domain_or_ip}[/blue]) rule has been removed. Start the packet filter for changes to take effect.[/yellow]"
        except FileNotFoundError:
            self.logger.error(f"could not find file {PF_RULES_PATH}")
            return f"[yellow]Could not find file [blue]{PF_RULES_PATH}[/blue].[/yellow]"
        except PermissionError:
            self.logger.error(f"no permission to modify {PF_RULES_PATH}")
            return f"[yellow]No permission to modify [blue]{PF_RULES_PATH}[/blue].[/yellow]"
        except Exception as e:
            self.logger.error(f"failed to remove block rule: {e}")
            return f"[yellow]Failed to remove ([blue]BLOCK - {domain_or_ip}[/blue]) rule: [blue]{e}[/blue].[/yellow]"
