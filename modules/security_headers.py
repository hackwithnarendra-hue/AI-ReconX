import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": "Protection against unauthorized content and scripts",
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Controls browser features"
}


def get_security_headers(domain):

    if not domain.startswith(("http://", "https://")):
        url = "https://" + domain
    else:
        url = domain

    try:

        response = requests.get(
            url,
            timeout=20,
            allow_redirects=True,
            headers={
                "User-Agent": "AI-ReconX/2.0"
            }
        )

        return {
            "url": response.url,
            "status_code": response.status_code,
            "headers": response.headers
        }

    except requests.exceptions.RequestException as e:

        return {"Error": str(e)}


def display_security_headers(domain):

    print("\n========== HTTP SECURITY HEADERS ==========\n")

    print(f"Target Domain: {domain}")

    data = get_security_headers(domain)

    if "Error" in data:

        print(f"Request Failed: {data['Error']}")
        return

    headers = data["headers"]

    print(f"\nFinal URL    : {data['url']}")
    print(f"HTTP Status  : {data['status_code']}")

    print("\n========== HEADER ANALYSIS ==========\n")

    present_count = 0
    missing_count = 0

    for header, description in SECURITY_HEADERS.items():

        value = headers.get(header)

        if value:

            print(f"[+] {header}: PRESENT")
            print(f"    Value: {value}")
            present_count += 1

        else:

            print(f"[-] {header}: MISSING")
            missing_count += 1

        print(f"    Purpose: {description}")
        print("-" * 45)

    print("\n========== ADDITIONAL INFORMATION ==========\n")

    print(f"Server Header: {headers.get('Server', 'Not Disclosed')}")
    print(f"Content Type : {headers.get('Content-Type', 'Not Available')}")

    print("\n========== SECURITY SUMMARY ==========\n")

    print(f"Present Headers : {present_count}")
    print(f"Missing Headers : {missing_count}")

    print("\n========== ANALYSIS COMPLETED ==========\n")
