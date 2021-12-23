from re import match
from socket import gethostbyaddr
from time import sleep
from typing import Iterable
from warnings import warn

from aslookup import get_as_data
from icmplib import Hop, ICMPRequest, ICMPv4Socket, ICMPv6Socket, TimeExceeded, resolve
from icmplib.exceptions import ICMPLibError
from icmplib.utils import unique_identifier
from rich.live import Live
from rich.table import Table
from rich.text import Text


def _trace(
    address: str,
    count: int = 1,
    interval: float = 0.0,
    timeout: int = 25,
    ttl: int = 1,
    max_hops: int = 30,
    family: int = None,
    id: int = None,
    source: str = None,
) -> Iterable[Hop | None]:
    if match(r"(?i)^([a-z0-9-]+|([a-z0-9_-]+[.])+[a-z]+)$", address):
        address = resolve(address, family)[0]

    if ":" in address:
        Socket = ICMPv6Socket
    else:
        Socket = ICMPv4Socket

    id = id or unique_identifier()
    reached = False

    with Socket(source) as sock:
        while not reached and ttl <= max_hops:
            reply = None
            sent = 0
            times = []

            for seq in range(count):
                request = ICMPRequest(address, id=id, sequence=seq, ttl=ttl)

                try:
                    sock.send(request)
                    sent += 1

                    reply = sock.receive(request, timeout)
                    rtt = reply.time - request.time
                    times.append(rtt)

                    reply.raise_for_status()
                    reached = True

                except TimeExceeded:
                    sleep(interval)

                except ICMPLibError:
                    break

            if reply:
                yield Hop(
                    address=reply.source, packets_sent=sent, rtts=times, distance=ttl
                )
            else:
                yield None
            ttl += 1


def _create_table(host: str, detailed: bool) -> Table:
    table = Table(title=f"Traceroute to {host} [Detailed: {detailed}]")

    for column in [
        "Hop",
        "Hostname",
        "Address",
        "Sent",
        "Loss (%)",
        "Avg. RTT (ms)",
        "Min. RTT (ms)",
        "Max. RTT (ms)",
        "ASN",
    ]:
        table.add_column(column, justify="left")

    return table

def trace(
    address: str,
    count: int = 1,
    interval: float = 0.0,
    timeout: int = 25,
    ttl: int = 1,
    max_hops: int = 30,
    family: int = None,
    id: int = None,
    source: str = None,
    upload: bool = False,
    detailed_asn: bool = False,
) -> None:
    table = _create_table(address, detailed_asn)

    if upload:
        warn("Uploading results is not currently implemented.")

    if family not in (4, 6, None):
        print("Family must be 4 or 6")
        return

    if detailed_asn and family == 6:
        warn("Detailed IPv6 ASN lookup is not currently implemented.")
        detailed_asn = False

    with Live(table):
        for hop in _trace(address, count, interval, timeout, ttl, max_hops, family, id, source):
            if not hop:
                table.add_row(
                    Text("no response", style="red bold"),
                    *[Text("*", style="red bold") for _ in range(8)],
                )
                continue

            try:
                hostname = gethostbyaddr(hop.address)[0]
            except Exception:
                hostname = hop.address

            try:
                asn = get_as_data(hop.address, service="cymru") or "n/a"
            except Exception:
                asn = "n/a"

            loss = round(hop.packet_loss * 100, 1)
            if loss > 0:
                loss = Text(str(loss), style="red bold")
            else:
                loss = str(loss)

            table.add_row(
                Text(str(hop.distance), style="green"),
                Text(str(hostname), style="blue"),
                str(hop.address),
                str(hop.packets_sent),
                loss,
                str(round(hop.avg_rtt * 1000)),
                str(round(hop.max_rtt * 1000)),
                str(round(hop.min_rtt * 1000)),
                (Text("n/a", style="red bold") if asn == "n/a" else f"{('(' + asn.as_name.split(' ')[0] + ('...' if asn.as_name.count(' ') >= 1 else '') + ') ') if detailed_asn else ''}https://bgp.tools/as/{asn.asn}"),
            )
