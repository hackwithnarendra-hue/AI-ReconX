import socket
import ssl
from datetime import datetime, timezone


def get_ssl_info(domain):

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (domain, 443), timeout=15
        ) as sock:

            with context.wrap_socket(
                sock, server_hostname=domain
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                cipher = secure_socket.cipher()
                tls_version = secure_socket.version()

                return {
                    "certificate": certificate,
                    "cipher": cipher,
                    "tls_version": tls_version
                }

    except Exception as e:

        return {"Error": str(e)}


def display_ssl_info(domain):

    print("\n========== SSL CERTIFICATE ANALYSIS ==========\n")

    print(f"Target Domain: {domain}")

    data = get_ssl_info(domain)

    if "Error" in data:

        print(f"SSL Lookup Failed: {data['Error']}")
        return

    cert = data["certificate"]

    print("\n========== CERTIFICATE DETAILS ==========\n")

    print("Issuer:")

    for item in cert.get("issuer", []):

        for key, value in item:
            print(f"{key}: {value}")

    print("\nSubject:")

    for item in cert.get("subject", []):

        for key, value in item:
            print(f"{key}: {value}")

    print("\nValidity:")

    not_before = datetime.strptime(
        cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=timezone.utc)

    not_after = datetime.strptime(
        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    days_remaining = (not_after - now).days

    print(f"Valid From       : {not_before}")
    print(f"Valid Until      : {not_after}")
    print(f"Days Remaining   : {days_remaining}")

    if now < not_before:
        print("Status           : NOT YET VALID")
    elif now > not_after:
        print("Status           : EXPIRED")
    else:
        print("Status           : VALID")

    print("\n========== CERTIFICATE INFORMATION ==========\n")

    print(f"Serial Number : {cert.get('serialNumber')}")
    print(f"Version       : {cert.get('version')}")

    print("\nSubject Alternative Names (SAN):")

    sans = cert.get("subjectAltName", [])

    if sans:

        for san_type, san_value in sans:
            print(f"{san_type}: {san_value}")

    else:
        print("No SAN information available.")

    print("\n========== TLS CONNECTION ==========\n")

    print(f"TLS Version : {data['tls_version']}")
    print(f"Cipher      : {data['cipher']}")

    print("\n========== SSL ANALYSIS COMPLETED ==========\n")
