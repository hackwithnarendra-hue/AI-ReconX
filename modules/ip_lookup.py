import requests
import ipaddress


def get_ip_info(ip):

    try:
        # Validate IP address
        ipaddress.ip_address(ip)

        url = f"https://ipwho.is/{ip}"

        response = requests.get(
            url,
            timeout=15
        )

        response.raise_for_status()
        data = response.json()

        if not data.get("success", False):
            return {"Error": data.get("message", "IP lookup failed")}

        connection = data.get("connection", {})

        result = {
            "IP Address": data.get("ip", ip),
            "Country": data.get("country", "Not Available"),
            "Region": data.get("region", "Not Available"),
            "City": data.get("city", "Not Available"),
            "Postal Code": data.get("postal", "Not Available"),
            "ISP": connection.get("isp", "Not Available"),
            "Organization": connection.get("org", "Not Available"),
            "ASN": connection.get("asn", "Not Available"),
            "Timezone": data.get("timezone", {}).get("id", "Not Available")
        }

        return result

    except ValueError:
        return {"Error": "Invalid IP address"}

    except requests.exceptions.RequestException as e:
        return {"Error": f"IP lookup request failed: {e}"}

    except Exception as e:
        return {"Error": str(e)}


def display_ip_info(ip):

    info = get_ip_info(ip)

    print("\n========== IP & ASN INFORMATION ==========\n")

    if "Error" in info:
        print(info["Error"])
        return

    for key, value in info.items():
        print(f"{key}: {value}")

    print("\n==========================================\n")
