import argparse

from .core import PcapError, parse_pcap, summarize, to_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packetlens",
        description="Inspect classic Ethernet PCAP files without heavyweight dependencies.",
    )
    parser.add_argument("pcap", help="Path to a classic PCAP file")
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        dest="json_output",
        help="Print packet data and summary as JSON",
    )
    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=15,
        help="Maximum number of packet rows to display",
    )
    return parser


def _endpoint(address: str, port: int | None) -> str:
    return f"{address}:{port}" if port is not None else address


def main() -> None:
    args = build_parser().parse_args()
    if args.limit < 0:
        raise SystemExit("error: limit must be zero or greater")

    try:
        packets = parse_pcap(args.pcap)
    except (OSError, PcapError) as exc:
        raise SystemExit(f"error: {exc}") from exc

    if args.json_output:
        print(to_json(packets))
        return

    summary = summarize(packets)
    print(f"Packets: {summary['packets']}")
    print(f"Bytes:   {summary['bytes']}")

    print("Protocols:")
    if summary["protocols"]:
        for protocol, count in summary["protocols"].items():
            print(f"  {protocol:<10} {count}")
    else:
        print("  none")

    print("Packets:")
    if not packets or args.limit == 0:
        print("  none")
        return

    for packet in packets[: args.limit]:
        source = _endpoint(packet.src, packet.src_port)
        destination = _endpoint(packet.dst, packet.dst_port)
        print(
            f"  {source:<24} -> {destination:<24} "
            f"{packet.protocol:<8} {packet.length} B"
        )


if __name__ == "__main__":
    main()
