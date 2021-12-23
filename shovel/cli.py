from typer import Typer, Argument, Option

from .src.traceroute import trace


shovel = Typer()

@shovel.command(name="trace")
def trace_command(
    address: str,
    count: int = Option(default=1, help="Number of packets to send"),
    interval: float = Option(default=0.0, help="Interval between packets"),
    timeout: int = Option(default=25, help="Timeout for each packet"),
    ttl: int = Option(default=1, help="Time to live"),
    max_hops: int = Option(default=30, help="Maximum number of hops"),
    family: int = Option(default=None, help="Address family"),
    id: int = Option(default=None, help="Identifier (1-65536)"),
    source: str = Option(default=None, help="Source address"),
    detailed_asn: bool = Option(default=False, help="Detailed ASN information"),
) -> None:
    """Trace the route to a host"""
    trace(
        address,
        count,
        interval,
        timeout,
        ttl,
        max_hops,
        family,
        id,
        source,
        detailed_asn=detailed_asn,
    )

@shovel.command(name="version")
def version() -> None:
    print("1.0.0")

if __name__ == "__main__":
    shovel()
