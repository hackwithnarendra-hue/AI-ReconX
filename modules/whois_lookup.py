import requests


def get_whois_info(domain):

    url = f"https://rdap.org/domain/{domain}"

    headers = {
        "User-Agent": "AI-ReconX/1.0",
        "Accept": "application/rdap+json"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=20
        )

        response.raise_for_status()
        data = response.json()

        result = {
            "Domain": data.get("ldhName", domain),
            "Registrar": "Not Available",
            "Creation Date": "Not Available",
            "Expiration Date": "Not Available",
            "Updated Date": "Not Available",
            "Name Servers": [],
            "Status": data.get("status", []),
            "Organization": "Not Available"
        }

        # Extract domain events
        for event in data.get("events", []):

            action = event.get("eventAction")
            date = event.get("eventDate", "Not Available")

            if action == "registration":
                result["Creation Date"] = date

            elif action == "expiration":
                result["Expiration Date"] = date

            elif action == "last changed":
                result["Updated Date"] = date

        # Extract registrar and organization
        for entity in data.get("entities", []):

            roles = entity.get("roles", [])

            if "registrar" in roles:

                result["Registrar"] = entity.get(
                    "handle", "Not Available"
                )

                vcard = entity.get("vcardArray", [])

                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] in ("fn", "org"):
                            result["Organization"] = str(item[3])
                            break

        # Extract name servers
        for ns in data.get("nameservers", []):
            name = ns.get("ldhName")

            if name:
                result["Name Servers"].append(name)

        return result

    except requests.exceptions.Timeout:
        return {"Error": "RDAP request timed out"}

    except requests.exceptions.RequestException as e:
        return {"Error": f"RDAP request failed: {e}"}

    except ValueError:
        return {"Error": "Invalid RDAP response"}

    except Exception as e:
        return {"Error": str(e)}


def display_whois_info(domain):

    info = get_whois_info(domain)

    print("\n========== WHOIS / RDAP INFORMATION ==========\n")

    if "Error" in info:
        print(info["Error"])
        return

    for key, value in info.items():

        if isinstance(value, list):
            print(f"{key}:")
            if value:
                for item in value:
                    print(f"  - {item}")
            else:
                print("  Not Available")
        else:
            print(f"{key}: {value}")

    print("\n==============================================\n")
