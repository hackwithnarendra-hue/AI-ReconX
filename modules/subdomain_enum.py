import os
import requests
import socket

from urllib.parse import quote, urlparse


HEADERS = {
    "User-Agent": "AI-ReconX/2.0",
    "Accept": "application/json"
}

TIMEOUT = 25


def normalize_subdomain(name, domain):

    name = name.strip().lower().rstrip(".")
    name = name.removeprefix("*.")

    if name == domain or name.endswith("." + domain):
        return name

    return None


def discover_from_crtsh(domain):

    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    response = requests.get(
        url, headers=HEADERS, timeout=TIMEOUT
    )
    response.raise_for_status()

    records = response.json()
    results = set()

    for record in records:

        for name in record.get("name_value", "").splitlines():

            clean = normalize_subdomain(name, domain)

            if clean:
                results.add(clean)

    return results


def discover_from_hackertarget(domain):

    url = "https://api.hackertarget.com/hostsearch/"

    response = requests.get(
        url,
        params={"q": domain},
        headers=HEADERS,
        timeout=TIMEOUT
    )
    response.raise_for_status()

    results = set()

    for line in response.text.splitlines():

        parts = line.split(",")

        if parts:
            clean = normalize_subdomain(parts[0], domain)

            if clean:
                results.add(clean)

    if "error" in response.text.lower() and not results:
        raise Exception(response.text[:200])

    return results


def discover_from_certspotter(domain):

    url = "https://api.certspotter.com/v1/issuances"

    params = {
        "domain": domain,
        "include_subdomains": "true",
        "expand": ["dns_names"]
    }

    response = requests.get(
        url,
        params=params,
        headers=HEADERS,
        timeout=TIMEOUT
    )
    response.raise_for_status()

    records = response.json()
    results = set()

    for record in records:

        for name in record.get("dns_names", []):

            clean = normalize_subdomain(name, domain)

            if clean:
                results.add(clean)

    return results


def discover_from_virustotal(domain):

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        raise Exception("VT_API_KEY not configured")

    url = (
        f"https://www.virustotal.com/api/v3/"
        f"domains/{domain}/subdomains"
    )

    headers = {
        **HEADERS,
        "x-apikey": api_key
    }

    results = set()

    for page in range(10):

        response = requests.get(
            url,
            headers=headers,
            timeout=TIMEOUT
        )
        response.raise_for_status()

        data = response.json()

        for item in data.get("data", []):

            clean = normalize_subdomain(
                item.get("id", ""), domain
            )

            if clean:
                results.add(clean)

        next_url = data.get("links", {}).get("next")

        if not next_url:
            break

        if urlparse(next_url).hostname != "www.virustotal.com":
            break

        url = next_url

    return results


def discover_from_securitytrails(domain):

    api_key = os.getenv("SECURITYTRAILS_API_KEY")

    if not api_key:
        raise Exception("SECURITYTRAILS_API_KEY not configured")

    url = (
        f"https://api.securitytrails.com/v1/"
        f"domain/{domain}/subdomains"
    )

    headers = {
        **HEADERS,
        "APIKEY": api_key
    }

    response = requests.get(
        url,
        headers=headers,
        params={"children_only": "true"},
        timeout=TIMEOUT
    )
    response.raise_for_status()

    data = response.json()
    results = set()

    for name in data.get("subdomains", []):

        clean = normalize_subdomain(
            f"{name}.{domain}", domain
        )

        if clean:
            results.add(clean)

    return results


def discover_from_rapiddns(domain):

    api_key = os.getenv("RAPIDDNS_API_KEY")

    if not api_key:
        raise Exception("RAPIDDNS_API_KEY not configured")

    url = (
        f"https://rapiddns.io/api/search/{quote(domain, safe='')}"
    )

    headers = {
        **HEADERS,
        "X-API-KEY": api_key
    }

    response = requests.get(
        url,
        headers=headers,
        params={"search_type": "subdomain"},
        timeout=TIMEOUT
    )
    response.raise_for_status()

    data = response.json()

    message = data.get("message", {})

    if isinstance(message, dict):
        if message.get("status") == "error":
            raise Exception(message.get("error", "RapidDNS search failed"))

        records = message.get("data", [])
    else:
        records = []

    results = set()

    for record in records:

        name = record.get("subdomain", "")

        clean = normalize_subdomain(name, domain)

        if clean:
            results.add(clean)

    return results


def discover_subdomains(domain):

    domain = domain.lower().strip().rstrip(".")

    sources = {
        "crt.sh": discover_from_crtsh,
        "HackerTarget": discover_from_hackertarget,
        "CertSpotter": discover_from_certspotter,
        "VirusTotal": discover_from_virustotal,
        "SecurityTrails": discover_from_securitytrails,
        "RapidDNS": discover_from_rapiddns
    }

    all_subdomains = set()
    source_status = {}

    for source, function in sources.items():

        try:

            results = function(domain)

            all_subdomains.update(results)

            source_status[source] = (
                f"SUCCESS ({len(results)} found)"
            )

        except requests.exceptions.HTTPError as e:

            code = (
                e.response.status_code
                if e.response is not None
                else "Unknown"
            )

            source_status[source] = f"HTTP ERROR ({code})"

        except Exception as e:

            source_status[source] = f"FAILED ({str(e)[:100]})"

    return sorted(all_subdomains), source_status


def resolve_subdomain(subdomain):

    try:

        results = socket.getaddrinfo(
            subdomain, None
        )

        ips = sorted({
            result[4][0]
            for result in results
        })

        return ips

    except socket.gaierror:
        return []


def display_subdomains(domain):

    print("\n========== SUBDOMAIN ENUMERATION ==========\n")

    print(f"Target Domain: {domain}")

    subdomains, source_status = discover_subdomains(domain)

    print("\n========== SOURCE STATUS ==========\n")

    for source, status in source_status.items():

        print(f"{source:<20}: {status}")

    print("\n========== DISCOVERED SUBDOMAINS ==========\n")

    if not subdomains:

        print("No subdomains found.")
        return

    print(f"Total Unique Subdomains: {len(subdomains)}\n")

    resolved_count = 0

    for subdomain in subdomains:

        ips = resolve_subdomain(subdomain)

        if ips:
            status = "RESOLVED"
            resolved_count += 1
        else:
            status = "NOT RESOLVED"

        print(f"Subdomain : {subdomain}")
        print(f"Status    : {status}")

        for ip in ips:
            print(f"IP Address: {ip}")

        print("-" * 45)

    print("\n========== SUMMARY ==========")

    print(f"Total Found  : {len(subdomains)}")
    print(f"Resolved     : {resolved_count}")
    print(f"Not Resolved : {len(subdomains) - resolved_count}")

    print("========================================\n")
