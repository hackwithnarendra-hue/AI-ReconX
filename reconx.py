import re
import sys
import socket
import ipaddress

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from modules.domain_info import (
    get_domain_info,
    display_domain_info
)

from modules.whois_lookup import display_whois_info
from modules.dns_enum import display_dns_records
from modules.ip_lookup import display_ip_info
from modules.subdomain_enum import display_subdomains
from modules.ssl_info import display_ssl_info
from modules.security_headers import display_security_headers
from modules.directory_file_discovery import directory_file_discovery
console = Console()


def show_banner():

    banner = Text()
    banner.append("AI ", style="bold cyan")
    banner.append("ReconX", style="bold white")

    banner.append(
        "\nAll-in-One OSINT Reconnaissance Framework",
        style="bright_blue"
    )

    console.print(
        Panel(
            banner,
            border_style="cyan",
            padding=(1, 3)
        )
    )


def validate_domain(domain):

    domain = domain.strip().lower()

    if domain.startswith(("http://", "https://")):
        return False

    if "/" in domain or " " in domain:
        return False

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}$"
    )

    return bool(re.fullmatch(pattern, domain))


def get_public_ips(domain):

    ips = set()

    try:
        results = socket.getaddrinfo(domain, None)

        for result in results:

            ip = result[4][0]

            address = ipaddress.ip_address(ip)

            if address.is_global:
                ips.add(ip)

    except socket.gaierror:
        console.print(
            "[red]Unable to resolve domain IP addresses.[/red]"
        )

    return sorted(ips)


def main():

    show_banner()

    console.print(
        "[bold green][+] AI ReconX Started[/bold green]"
    )

    console.print(
        "[yellow]Only scan domains you own or are authorized to assess.[/yellow]\n"
    )

    domain = console.input(
        "[bold cyan]Enter Target Domain: [/bold cyan]"
    )

    domain = domain.strip().lower()

    if not validate_domain(domain):

        console.print(
            "[bold red]Invalid domain format![/bold red]"
        )

        sys.exit(1)

    console.print(
        f"\n[green][+] Target accepted: {domain}[/green]"
    )

    console.print(
        "[cyan][+] Domain validation successful.[/cyan]"
    )

    # DOMAIN INFORMATION

    console.print(
        "\n[bold yellow][*] Starting Domain Information Module...[/bold yellow]"
    )

    domain_results = get_domain_info(domain)

    display_domain_info(domain_results)

    console.print(
        "[bold green][+] Domain Information Module Completed.[/bold green]"
    )

    # WHOIS / RDAP

    console.print(
        "\n[bold yellow][*] Starting WHOIS / RDAP Module...[/bold yellow]"
    )

    display_whois_info(domain)

    console.print(
        "[bold green][+] WHOIS / RDAP Module Completed.[/bold green]"
    )

    # DNS ENUMERATION

    console.print(
        "\n[bold yellow][*] Starting DNS Enumeration Module...[/bold yellow]"
    )

    display_dns_records(domain)

    console.print(
        "[bold green][+] DNS Enumeration Module Completed.[/bold green]"
    )

    # IP LOOKUP

    console.print(
        "\n[bold yellow][*] Starting IP Lookup & ASN Module...[/bold yellow]"
    )

    public_ips = get_public_ips(domain)

    if public_ips:

        for ip in public_ips:

            console.print(
                f"\n[cyan][+] Resolved Public IP: {ip}[/cyan]"
            )

            display_ip_info(ip)

    else:

        console.print(
            "[yellow]No public IP addresses found.[/yellow]"
        )

    console.print(
        "[bold green][+] IP Lookup & ASN Module Completed.[/bold green]"
    )
# SUBDOMAIN ENUMERATION

    console.print(
        "\n[bold yellow][*] Starting Subdomain Enumeration Module...[/bold yellow]"
    )

    display_subdomains(domain)

    console.print(
        "[bold green][+] Subdomain Enumeration Module Completed.[/bold green]"
    )
# SSL CERTIFICATE ANALYSIS

    console.print(
        "\n[bold yellow][*] Starting SSL Certificate Analysis Module...[/bold yellow]"
    )

    display_ssl_info(domain)

    console.print(
        "[bold green][+] SSL Certificate Analysis Module Completed.[/bold green]"
    )
# HTTP SECURITY HEADERS ANALYSIS

    console.print(
        "\n[bold yellow][*] Starting HTTP Security Headers Analysis Module...[/bold yellow]"
    )

    display_security_headers(domain)

    console.print(
        "[bold green][+] HTTP Security Headers Analysis Module Completed.[/bold green]"
    )
# DIRECTORY & FILE DISCOVERY

    console.print(
        "\n[bold yellow][*] Starting Directory & File Discovery Module...[/bold yellow]"
    )

    directory_file_discovery(domain)

    console.print(
        "[bold green][+] Directory & File Discovery Module Completed.[/bold green]"
    )
if __name__ == "__main__":
    main()
