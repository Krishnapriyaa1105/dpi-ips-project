import os

# Load blocklist domains from blocklist.txt
def load_blocklist():
    blocklist = set()
    try:
        with open("blocklist.txt", "r") as f:
            for line in f:
                domain = line.strip().lower()
                if domain:
                    blocklist.add(domain)
    except FileNotFoundError:
        print("[WARNING] blocklist.txt not found. No domains will be blocked.")
    return blocklist


BLOCKLIST = load_blocklist()


def classify(parsed):
    
    blocked_domains = [
        "malware.com",
        "phishing.com",
        "badsite.com"
    ]

    if parsed["type"] == "dns_query":

        domain = parsed["domain"]

        for bad in blocked_domains:
            if bad in domain:
                return "BLOCKED"

    if parsed["type"] == "tls":

        domain = parsed.get("domain", "")

        for bad in blocked_domains:
            if bad in domain:
                return "BLOCKED"

    return "SAFE"