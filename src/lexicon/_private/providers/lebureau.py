"""LeBureau.coop hosted DNS, using TSIG-authenticated RFC 2136."""

from argparse import ArgumentParser

import dns.exception
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.resolver
import dns.tokenizer
import dns.tsig
import dns.update
import dns.zone

from .ddns import Provider as DdnsProvider


class Provider(DdnsProvider):
    @staticmethod
    def get_nameservers() -> list[str]:
        return ["ns1.lebureau.coop.", "ns2.lebureau.coop."]

    @staticmethod
    def configure_parser(parser: ArgumentParser):
        parser.add_argument(
            "--auth-token", help="TSIG key as algorithm:key_name:base64_secret"
        )
        parser.add_argument(
            "--ddns-server",
            default="ns.lebureau.coop",
            help="DDNS server hostname or IP (default: ns.lebureau.coop)",
        )
        parser.add_argument(
            "--timeout",
            default=10,
            type=int,
            help="DNS operation timeout in seconds (default: 10)",
        )

    def __init__(self, config):
        super().__init__(config)

        self.endpoints = list(self._resolve_ips(self._get_provider_option("ddns_server")))

    def _resolve_ips(self, hostname):
        resolved = dns.resolver.resolve_name(hostname)
        for response in resolved.values():
            for answer in response.rrset:
                yield answer.address

    def _run_query(self, message):
        for endpoint in self.endpoints:
            try:
                return dns.query.tcp(message, endpoint, timeout=10)
            except (dns.exception.DNSException, OSError):
                pass
        return None
