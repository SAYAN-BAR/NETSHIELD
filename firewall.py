import argparse
import ctypes
import ipaddress
import json
import subprocess
import sys


def is_admin():
    """Check whether Python is running as Administrator."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def validate_ip(value):
    """Validate IPv4 or IPv6 addresses."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise ValueError(
            "Enter a valid IPv4 or IPv6 address."
        ) from exc


def run_powershell(command):
    """Execute a PowerShell command safely."""
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command
        ],
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=getattr(
            subprocess,
            "CREATE_NO_WINDOW",
            0
        )
    )

    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(
            message or "Windows PowerShell command failed."
        )

    return result.stdout.strip()


def add_block_rule(ip):
    """Create a NetShield outbound block rule."""

    if not is_admin():
        raise PermissionError(
            "Run NetShield as Administrator to manage firewall rules."
        )

    ip = validate_ip(ip)
    rule_name = f"NetShield Block {ip}"

    command = f"""
    $name = '{rule_name}'

    $existing = Get-NetFirewallRule `
        -DisplayName $name `
        -ErrorAction SilentlyContinue

    if ($existing) {{
        throw 'This NetShield block rule already exists.'
    }}

    New-NetFirewallRule `
        -DisplayName $name `
        -Direction Outbound `
        -Action Block `
        -RemoteAddress '{ip}' `
        -Profile Any `
        -Enabled True | Out-Null

    Write-Output 'Windows Defender Firewall block rule created.'
    """

    return run_powershell(command)


def remove_block_rule(ip):
    """Remove only the matching NetShield rule."""

    if not is_admin():
        raise PermissionError(
            "Run NetShield as Administrator to manage firewall rules."
        )

    ip = validate_ip(ip)
    rule_name = f"NetShield Block {ip}"

    command = f"""
    $rule = Get-NetFirewallRule `
        -DisplayName '{rule_name}' `
        -ErrorAction SilentlyContinue

    if ($null -eq $rule) {{
        throw 'NetShield rule not found.'
    }}

    $rule | Remove-NetFirewallRule

    Write-Output 'NetShield firewall rule removed.'
    """

    return run_powershell(command)


def get_rules():
    """Return firewall rules created by NetShield."""

    command = """
    $rules = @(Get-NetFirewallRule `
        -DisplayName 'NetShield Block *' `
        -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Enabled, Direction, Action, Profile)

    ConvertTo-Json -InputObject $rules -Compress
    """

    output = run_powershell(command)

    if not output:
        return []

    try:
        result = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Could not read Windows Firewall rule information."
        ) from exc

    return result if isinstance(result, list) else [result]


def show_rules():
    rules = get_rules()

    if not rules:
        print("No NetShield firewall rules found.")
        return

    print("\nNETSHIELD FIREWALL RULES")
    print("-" * 55)

    for rule in rules:
        print("Name:", rule.get("DisplayName"))
        print("Enabled:", rule.get("Enabled"))
        print("Direction:", rule.get("Direction"))
        print("Action:", rule.get("Action"))
        print("Profile:", rule.get("Profile"))
        print("-" * 55)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="NetShield Windows Firewall Manager"
    )

    parser.add_argument(
        "action",
        choices=["block", "remove", "status"]
    )

    parser.add_argument(
        "--ip",
        help="IPv4 or IPv6 address"
    )

    args = parser.parse_args()

    try:

        if args.action == "block":

            if not args.ip:
                parser.error("--ip is required for block.")

            print(add_block_rule(args.ip))

        elif args.action == "remove":

            if not args.ip:
                parser.error("--ip is required for remove.")

            print(remove_block_rule(args.ip))

        else:
            show_rules()

    except (
        ValueError,
        PermissionError,
        RuntimeError,
        subprocess.TimeoutExpired
    ) as error:

        print("ERROR:", error)
        sys.exit(1)