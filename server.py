"""
Domain Name Availability MCP Server

Checks domain availability using multiple verification methods:
1. WHOIS lookup (primary)
2. DNS resolution (secondary)
3. RDAP query (supplementary for supported TLDs)
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from enum import Enum

import dns.resolver
import httpx
import whois
from whois.exceptions import WhoisDomainNotFoundError, WhoisCommandFailedError, UnknownTldError
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr (NEVER stdout for STDIO transport)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

mcp = FastMCP("domain-availability-checker")

# Supported TLDs
SUPPORTED_TLDS = {".com", ".ai", ".net"}

# RDAP servers for supported TLDs
RDAP_SERVERS = {
    ".com": "https://rdap.verisign.com/com/v1/domain/",
    ".net": "https://rdap.verisign.com/net/v1/domain/",
    ".ai": None,  # .ai doesn't have a public RDAP server
}


class AvailabilityStatus(str, Enum):
    AVAILABLE = "available"
    TAKEN = "taken"
    UNKNOWN = "unknown"


@dataclass
class CheckResult:
    method: str
    status: AvailabilityStatus
    details: str | None = None


def validate_domain(domain: str) -> tuple[bool, str]:
    """Validate domain format and check if TLD is supported."""
    domain = domain.lower().strip()

    # Remove protocol if present
    domain = re.sub(r"^https?://", "", domain)
    # Remove trailing slash and path
    domain = domain.split("/")[0]
    # Remove www prefix
    domain = re.sub(r"^www\.", "", domain)

    # Basic domain format validation
    pattern = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$"
    if not re.match(pattern, domain):
        return False, f"Invalid domain format: {domain}"

    # Extract TLD
    tld = "." + domain.split(".")[-1]
    if tld not in SUPPORTED_TLDS:
        return False, f"TLD '{tld}' not supported. Supported TLDs: {', '.join(SUPPORTED_TLDS)}"

    return True, domain


async def check_whois(domain: str) -> CheckResult:
    """Check domain availability via WHOIS lookup."""
    try:
        # Run WHOIS in executor to avoid blocking
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)

        # Check if domain is registered
        # Different TLDs return different structures, so check multiple fields
        if w.domain_name is None:
            return CheckResult(
                method="whois",
                status=AvailabilityStatus.AVAILABLE,
                details="No WHOIS record found"
            )

        # Domain is registered
        return CheckResult(
            method="whois",
            status=AvailabilityStatus.TAKEN,
            details="WHOIS record exists"
        )
    except WhoisDomainNotFoundError:
        # No WHOIS record found - domain likely available
        return CheckResult(
            method="whois",
            status=AvailabilityStatus.AVAILABLE,
            details="No WHOIS record found"
        )
    except (WhoisCommandFailedError, UnknownTldError) as e:
        return CheckResult(
            method="whois",
            status=AvailabilityStatus.UNKNOWN,
            details=f"WHOIS lookup failed: {str(e)}"
        )
    except Exception as e:
        logger.warning(f"WHOIS check failed for {domain}: {e}")
        return CheckResult(
            method="whois",
            status=AvailabilityStatus.UNKNOWN,
            details=f"WHOIS lookup failed: {str(e)}"
        )


async def check_dns(domain: str) -> CheckResult:
    """Check if domain has DNS records (A, AAAA, or NS)."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    record_types = ["A", "AAAA", "NS"]

    for record_type in record_types:
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, resolver.resolve, domain, record_type)
            return CheckResult(
                method="dns",
                status=AvailabilityStatus.TAKEN,
                details=f"DNS {record_type} record found"
            )
        except dns.resolver.NXDOMAIN:
            # Domain definitely doesn't exist
            return CheckResult(
                method="dns",
                status=AvailabilityStatus.AVAILABLE,
                details="Domain does not exist (NXDOMAIN)"
            )
        except dns.resolver.NoAnswer:
            # No records of this type, try next
            continue
        except dns.resolver.NoNameservers:
            continue
        except Exception as e:
            logger.warning(f"DNS check failed for {domain} ({record_type}): {e}")
            continue

    # No DNS records found but not NXDOMAIN - inconclusive
    return CheckResult(
        method="dns",
        status=AvailabilityStatus.UNKNOWN,
        details="No DNS records found but domain may still be registered"
    )


async def check_rdap(domain: str) -> CheckResult:
    """Check domain via RDAP (Registration Data Access Protocol)."""
    tld = "." + domain.split(".")[-1]
    rdap_server = RDAP_SERVERS.get(tld)

    if not rdap_server:
        return CheckResult(
            method="rdap",
            status=AvailabilityStatus.UNKNOWN,
            details=f"No RDAP server available for {tld}"
        )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{rdap_server}{domain}")

            if response.status_code == 200:
                return CheckResult(
                    method="rdap",
                    status=AvailabilityStatus.TAKEN,
                    details="RDAP record found"
                )
            elif response.status_code == 404:
                return CheckResult(
                    method="rdap",
                    status=AvailabilityStatus.AVAILABLE,
                    details="No RDAP record found"
                )
            else:
                return CheckResult(
                    method="rdap",
                    status=AvailabilityStatus.UNKNOWN,
                    details=f"RDAP returned status {response.status_code}"
                )
    except Exception as e:
        logger.warning(f"RDAP check failed for {domain}: {e}")
        return CheckResult(
            method="rdap",
            status=AvailabilityStatus.UNKNOWN,
            details=f"RDAP lookup failed: {str(e)}"
        )


def determine_availability(results: list[CheckResult]) -> tuple[AvailabilityStatus, str]:
    """
    Determine final availability based on multiple check results.

    Priority:
    1. If any check says TAKEN, domain is taken
    2. If WHOIS or RDAP says AVAILABLE, domain is likely available
    3. DNS AVAILABLE alone is less reliable (could be registered but not configured)
    """
    taken_results = [r for r in results if r.status == AvailabilityStatus.TAKEN]
    available_results = [r for r in results if r.status == AvailabilityStatus.AVAILABLE]

    # If any method confirms taken, it's taken
    if taken_results:
        methods = ", ".join(r.method for r in taken_results)
        return AvailabilityStatus.TAKEN, f"Confirmed taken by: {methods}"

    # If WHOIS or RDAP says available, it's likely available
    authoritative_available = [r for r in available_results if r.method in ("whois", "rdap")]
    if authoritative_available:
        methods = ", ".join(r.method for r in authoritative_available)
        return AvailabilityStatus.AVAILABLE, f"Likely available (confirmed by: {methods})"

    # DNS-only available is less certain
    if available_results:
        return AvailabilityStatus.AVAILABLE, "Possibly available (DNS only - verify before purchasing)"

    # All checks inconclusive
    return AvailabilityStatus.UNKNOWN, "Unable to determine availability - all checks inconclusive"


@mcp.tool()
async def check_domain_availability(domain: str) -> str:
    """
    Check if a domain name is available for registration.

    Uses multiple verification methods (WHOIS, DNS, RDAP) to provide
    accurate availability status.

    Supported TLDs: .com, .ai, .net

    Args:
        domain: The domain name to check (e.g., "example.com")

    Returns:
        Availability status with confidence details
    """
    # Validate domain
    valid, result = validate_domain(domain)
    if not valid:
        return f"Error: {result}"

    domain = result  # Normalized domain
    logger.info(f"Checking availability for: {domain}")

    # Run all checks concurrently
    results = await asyncio.gather(
        check_whois(domain),
        check_dns(domain),
        check_rdap(domain),
    )

    # Determine final status
    status, explanation = determine_availability(list(results))

    # Build response
    response_lines = [
        f"Domain: {domain}",
        f"Status: {status.value.upper()}",
        f"Explanation: {explanation}",
        "",
        "Check Details:",
    ]

    for r in results:
        response_lines.append(f"  - {r.method.upper()}: {r.status.value} ({r.details})")

    return "\n".join(response_lines)


@mcp.tool()
async def check_multiple_domains(domains: list[str]) -> str:
    """
    Check availability for multiple domain names.

    Useful for checking variations of a domain across different TLDs
    or checking multiple candidate domain names at once.

    Supported TLDs: .com, .ai, .net

    Args:
        domains: List of domain names to check (e.g., ["example.com", "example.ai", "example.net"])

    Returns:
        Availability status for each domain
    """
    if not domains:
        return "Error: No domains provided"

    if len(domains) > 10:
        return "Error: Maximum 10 domains per request"

    results = []

    for domain in domains:
        valid, normalized = validate_domain(domain)
        if not valid:
            results.append(f"{domain}: ERROR - {normalized}")
            continue

        # Run checks for this domain
        check_results = await asyncio.gather(
            check_whois(normalized),
            check_dns(normalized),
            check_rdap(normalized),
        )

        status, _ = determine_availability(list(check_results))
        results.append(f"{normalized}: {status.value.upper()}")

    return "\n".join(results)


if __name__ == "__main__":
    mcp.run(transport="stdio")
