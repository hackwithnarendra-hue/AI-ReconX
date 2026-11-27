import dns.resolver


def get_dns_records(domain):

    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME"
    ]

    results = {}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for record_type in record_types:

        results[record_type] = []

        try:
            answers = resolver.resolve(
                domain,
                record_type
            )

            for answer in answers:
                results[record_type].append(str(answer))

        except dns.resolver.NoAnswer:
            results[record_type] = []

        except dns.resolver.NXDOMAIN:
            results["Error"] = "Domain does not exist"
            return results

        except dns.resolver.NoNameservers:
            results[record_type] = ["Nameserver unavailable"]

        except dns.resolver.LifetimeTimeout:
            results[record_type] = ["DNS query timed out"]

        except Exception as e:
            results[record_type] = [f"Error: {e}"]

    return results


def display_dns_records(domain):

    results = get_dns_records(domain)

    print("\n========== DNS ENUMERATION ==========\n")

    if "Error" in results:
        print(results["Error"])
        return

    for record_type, records in results.items():

        print(f"\n{record_type} Records:")

        if records:
            for record in records:
                print(f"  - {record}")
        else:
            print("  Not Available")

    print("\n=====================================\n")
