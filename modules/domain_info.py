import socket
import ipaddress


def get_domain_info(domain):

    results = {
        "domain": domain,
        "ipv4": [],
        "ipv6": [],
        "status": "Failed",
        "errors": []
    }

    try:
        addresses = socket.getaddrinfo(
            domain,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        for item in addresses:
            ip = item[4][0]

            if ":" in ip:
                if ip not in results["ipv6"]:
                    results["ipv6"].append(ip)
            else:
                if ip not in results["ipv4"]:
                    results["ipv4"].append(ip)

        if results["ipv4"] or results["ipv6"]:
            results["status"] = "Resolved"

    except socket.gaierror as error:
        results["errors"].append(str(error))

    return results


def display_domain_info(results):

    print("\n========== DOMAIN INFORMATION ==========")

    print("Domain:", results["domain"])
    print("Status:", results["status"])

    print("\nIPv4 Addresses:")

    if results["ipv4"]:
        for ip in results["ipv4"]:
            address = ipaddress.ip_address(ip)
            print(f" - {ip} | IPv{address.version}")
    else:
        print(" - Not Found")

    print("\nIPv6 Addresses:")

    if results["ipv6"]:
        for ip in results["ipv6"]:
            print(" -", ip)
    else:
        print(" - Not Found")

    for error in results["errors"]:
        print("\nDNS Error:", error)

    print("========================================\n")
