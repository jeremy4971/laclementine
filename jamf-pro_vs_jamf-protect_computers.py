#!/usr/bin/env python3
"""
https://medium.com/@laclementine/

Compares computers (by serial number) between Jamf Pro and Jamf Protect.

Outputs:
  - Computers that exist in Jamf Protect but NOT in Jamf Pro ("extra"),
    with the last time they connected to Jamf Protect.
  - Computers that exist in Jamf Pro but NOT in Jamf Protect ("missing"),
    with their last check-in time in Jamf Pro.

Requirements:
  - Python 3 (ships with macOS / Xcode Command Line Tools)
  - No third-party dependencies (stdlib only)

Authentication:
  Jamf Pro     -> API Client (client id + client secret)
  Jamf Protect -> API Client (client id + password)

Either update lines 53–59 with your URLs and credentials,
or create a .env file containing the lines below and run "source yourFile.env":

  export JAMF_PRO_URL="https://yourcompany.jamfcloud.com"
  export JAMF_PRO_CLIENT_ID="your-api-client-id"
  export JAMF_PRO_CLIENT_SECRET="your-api-client-secret"

  export JAMF_PROTECT_URL="https://yourcompany.protect.jamfcloud.com"
  export JAMF_PROTECT_CLIENT_ID="protect-api-client-id"
  export JAMF_PROTECT_PASSWORD="protect-api-client-password"

Usage:
  python3 jamf_compare.py
  python3 jamf_compare.py --json          # machine-readable output
  python3 jamf_compare.py --insecure      # skip TLS verification (not recommended)
"""

import argparse
import json
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# CONFIG (env vars take precedence; you may hardcode values here if you must)
# --------------------------------------------------------------------------
JAMF_PRO_URL = os.environ.get("JAMF_PRO_URL", "").rstrip("/")
JAMF_PRO_CLIENT_ID = os.environ.get("JAMF_PRO_CLIENT_ID", "")
JAMF_PRO_CLIENT_SECRET = os.environ.get("JAMF_PRO_CLIENT_SECRET", "")

JAMF_PROTECT_URL = os.environ.get("JAMF_PROTECT_URL", "").rstrip("/")
JAMF_PROTECT_CLIENT_ID = os.environ.get("JAMF_PROTECT_CLIENT_ID", "")
JAMF_PROTECT_PASSWORD = os.environ.get("JAMF_PROTECT_PASSWORD", "")

TIMEOUT = 60  # seconds per HTTP request
PAGE_SIZE = 200


# --------------------------------------------------------------------------
# SSL / HTTP helpers (stdlib only)
# --------------------------------------------------------------------------
def create_ssl_context(insecure=False):
    """Create an SSL context; fall back to macOS Keychain root certs if needed."""
    ctx = ssl.create_default_context()

    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # If Python found no CA certs (common with python.org installs on macOS),
    # pull the trusted roots out of the macOS System Keychain.
    if not ctx.get_ca_certs():
        try:
            pem = subprocess.run(
                ["/usr/bin/security", "find-certificate", "-a", "-p",
                 "/System/Library/Keychains/SystemRootCertificates.keychain"],
                capture_output=True, text=True, check=True,
            ).stdout
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".pem", delete=False
            ) as f:
                f.write(pem)
                ca_file = f.name
            ctx = ssl.create_default_context(cafile=ca_file)
            print("Note: loaded CA certificates from macOS Keychain.", file=sys.stderr)
        except (subprocess.CalledProcessError, OSError) as e:
            sys.exit(
                f"No CA certificates available and Keychain fallback failed: {e}\n"
                "Run 'Install Certificates.command' from your Python installation, "
                "or use --insecure (not recommended)."
            )
    return ctx


def http_request(url, method="GET", headers=None, data=None, ctx=None):
    """Perform an HTTP request and return the parsed JSON response."""
    if isinstance(data, dict):
        data = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        sys.exit(f"HTTP {e.code} error calling {url}\n{detail}")
    except urllib.error.URLError as e:
        sys.exit(f"Connection error calling {url}: {e.reason}")


def normalize(serial):
    """Normalize serial numbers for comparison."""
    return (serial or "").strip().upper()


def format_timestamp(ts):
    """Format an ISO timestamp as local time with age in days, e.g. '2025-06-01 14:32 (12d ago)'."""
    if not ts:
        return "never / unknown"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - dt).days
        local = dt.astimezone()
        return f"{local.strftime('%Y-%m-%d %H:%M')} ({age_days}d ago)"
    except ValueError:
        return ts  # print raw value if parsing fails


# --------------------------------------------------------------------------
# Jamf Pro
# --------------------------------------------------------------------------
def jamf_pro_get_token(base_url, ctx):
    """Get a bearer token using an API Client (OAuth client credentials)."""
    if not (JAMF_PRO_CLIENT_ID and JAMF_PRO_CLIENT_SECRET):
        sys.exit("Set JAMF_PRO_CLIENT_ID and JAMF_PRO_CLIENT_SECRET.")

    payload = urllib.parse.urlencode({
        "client_id": JAMF_PRO_CLIENT_ID,
        "client_secret": JAMF_PRO_CLIENT_SECRET,
        "grant_type": "client_credentials",
    }).encode("utf-8")

    resp = http_request(
        f"{base_url}/api/oauth/token",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=payload,
        ctx=ctx,
    )
    return resp["access_token"]


def jamf_pro_get_computers(base_url, token, ctx):
    """Return {serial: {name, last_checkin, last_enrollment}} for all Jamf Pro computers."""
    computers = {}
    page = 0
    while True:
        params = urllib.parse.urlencode({
            "section": "GENERAL,HARDWARE",
            "page": page,
            "page-size": PAGE_SIZE,
            "sort": "id:asc",
        })
        resp = http_request(
            f"{base_url}/api/v1/computers-inventory?{params}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            ctx=ctx,
        )
        results = resp.get("results", [])
        for comp in results:
            general = comp.get("general") or {}
            serial = normalize((comp.get("hardware") or {}).get("serialNumber"))
            if serial:
                computers[serial] = {
                    "name": general.get("name", ""),
                    "last_checkin": general.get("lastContactTime", ""),
                    "last_enrollment": general.get("lastEnrolledDate", ""),
                }
        if (page + 1) * PAGE_SIZE >= resp.get("totalCount", 0) or not results:
            break
        page += 1
    return computers


# --------------------------------------------------------------------------
# Jamf Protect
# --------------------------------------------------------------------------
def jamf_protect_get_token(base_url, ctx):
    """Get a bearer token from Jamf Protect."""
    if not (JAMF_PROTECT_CLIENT_ID and JAMF_PROTECT_PASSWORD):
        sys.exit(
            "Jamf Protect credentials missing. "
            "Set JAMF_PROTECT_CLIENT_ID and JAMF_PROTECT_PASSWORD."
        )
    resp = http_request(
        f"{base_url}/token",
        method="POST",
        headers={"Content-Type": "application/json"},
        data={
            "client_id": JAMF_PROTECT_CLIENT_ID,
            "password": JAMF_PROTECT_PASSWORD,
        },
        ctx=ctx,
    )
    return resp["access_token"]


def jamf_protect_get_computers(base_url, token, ctx):
    """Return {serial: {name, last_checkin, first_connected}} for all Jamf Protect computers."""
    query = """
    query listComputers($page_size: Int, $next: String) {
        listComputers(input: { pageSize: $page_size, next: $next }) {
            items {
                serial
                hostName
                checkin
                created
            }
            pageInfo {
                next
                total
            }
        }
    }
    """
    computers = {}
    next_token = None
    while True:
        resp = http_request(
            f"{base_url}/graphql",
            method="POST",
            headers={
                "Authorization": token,
                "Content-Type": "application/json",
            },
            data={
                "query": query,
                "variables": {"page_size": PAGE_SIZE, "next": next_token},
            },
            ctx=ctx,
        )
        if resp.get("errors"):
            sys.exit(f"Jamf Protect GraphQL error:\n{json.dumps(resp['errors'], indent=2)}")
        data = resp["data"]["listComputers"]
        for comp in data.get("items", []):
            serial = normalize(comp.get("serial"))
            if serial:
                computers[serial] = {
                    "name": comp.get("hostName", ""),
                    "last_checkin": comp.get("checkin", ""),
                    "first_connected": comp.get("created", ""),
                }
        next_token = (data.get("pageInfo") or {}).get("next")
        if not next_token:
            break
    return computers


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Compare computers between Jamf Pro and Jamf Protect by serial number."
    )
    parser.add_argument("--json", action="store_true", help="output JSON instead of text")
    parser.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    args = parser.parse_args()

    if not JAMF_PRO_URL or not JAMF_PROTECT_URL:
        sys.exit("Set JAMF_PRO_URL and JAMF_PROTECT_URL environment variables.")

    pro_url = JAMF_PRO_URL.rstrip("/")
    protect_url = JAMF_PROTECT_URL.rstrip("/")

    ctx = create_ssl_context(insecure=args.insecure)

    print("Authenticating to Jamf Pro...", file=sys.stderr)
    pro_token = jamf_pro_get_token(pro_url, ctx)
    print("Fetching Jamf Pro computers...", file=sys.stderr)
    pro_computers = jamf_pro_get_computers(pro_url, pro_token, ctx)

    print("Authenticating to Jamf Protect...", file=sys.stderr)
    protect_token = jamf_protect_get_token(protect_url, ctx)
    print("Fetching Jamf Protect computers...", file=sys.stderr)
    protect_computers = jamf_protect_get_computers(protect_url, protect_token, ctx)

    pro_serials = set(pro_computers)
    protect_serials = set(protect_computers)

    extra_in_protect = sorted(protect_serials - pro_serials)     # in Protect, not in Pro
    missing_in_protect = sorted(pro_serials - protect_serials)   # in Pro, not in Protect

    if args.json:
        print(json.dumps({
            "jamf_pro_total": len(pro_serials),
            "jamf_protect_total": len(protect_serials),
            "extra_in_protect": [
                {
                    "serial": s,
                    "hostName": protect_computers[s]["name"],
                    "firstConnected": protect_computers[s]["first_connected"],
                    "notConnectedSince": protect_computers[s]["last_checkin"],
                }
                for s in extra_in_protect
            ],
            "missing_in_protect": [
                {
                    "serial": s,
                    "name": pro_computers[s]["name"],
                    "lastEnrollment": pro_computers[s]["last_enrollment"],
                    "lastCheckIn": pro_computers[s]["last_checkin"],
                }
                for s in missing_in_protect
            ],
        }, indent=2))
        return

    print()
    print("=" * 125)
    print(f"Jamf Pro computers:      {len(pro_serials)}")
    print(f"Jamf Protect computers:  {len(protect_serials)}")
    print("=" * 125)

    print(f"\nEXTRA in Jamf Protect (not found in Jamf Pro): {len(extra_in_protect)}")
    print("-" * 125)
    if extra_in_protect:
        print(f"  {'Serial':<16} {'Hostname':<30} {'First connected':<32} Not connected since")
        for serial in extra_in_protect:
            info = protect_computers[serial]
            print(f"  {serial:<16} {info['name']:<30} "
                  f"{format_timestamp(info['first_connected']):<32} "
                  f"{format_timestamp(info['last_checkin'])}")
    else:
        print("  (none)")

    print(f"\nMISSING in Jamf Protect (found in Jamf Pro only): {len(missing_in_protect)}")
    print("-" * 125)
    if missing_in_protect:
        print(f"  {'Serial':<16} {'Name':<30} {'Last enrollment':<32} Last check-in")
        for serial in missing_in_protect:
            info = pro_computers[serial]
            print(f"  {serial:<16} {info['name']:<30} "
                  f"{format_timestamp(info['last_enrollment']):<32} "
                  f"{format_timestamp(info['last_checkin'])}")
    else:
        print("  (none)")

    print()


if __name__ == "__main__":
    main()