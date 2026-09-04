from __future__ import annotations

import ipaddress
import json
import struct
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


@dataclass(slots=True)
class Packet:
    timestamp: float
    src: str
    dst: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    length: int


class PcapError(ValueError):
    """Raised when a capture is malformed or unsupported."""


def _read_u16(data: bytes, offset: int) -> int:
    return struct.unpack("!H", data[offset : offset + 2])[0]


def _parse_ipv4(frame: bytes, position: int, timestamp: float) -> Packet | None:
    if len(frame) < position + 20:
        return None

    version = frame[position] >> 4
    ihl = (frame[position] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(frame) < position + ihl:
        return None

    protocol_number = frame[position + 9]
    source = str(ipaddress.ip_address(frame[position + 12 : position + 16]))
    destination = str(ipaddress.ip_address(frame[position + 16 : position + 20]))
    protocol = PROTOCOL_NAMES.get(protocol_number, f"IP/{protocol_number}")

    source_port = None
    destination_port = None
    transport_offset = position + ihl
    if protocol_number in (6, 17) and len(frame) >= transport_offset + 4:
        source_port = _read_u16(frame, transport_offset)
        destination_port = _read_u16(frame, transport_offset + 2)

    return Packet(
        timestamp=timestamp,
        src=source,
        dst=destination,
        protocol=protocol,
        src_port=source_port,
        dst_port=destination_port,
        length=len(frame),
    )


def parse_pcap(path: str | Path) -> list[Packet]:
    """Parse IPv4 packets from a classic Ethernet PCAP file."""
    raw = Path(path).read_bytes()
    if len(raw) < 24:
        raise PcapError("file is too small to be a PCAP")

    try:
        endian, timestamp_scale = PCAP_MAGICS[raw[:4]]
    except KeyError as exc:
        raise PcapError("unsupported PCAP magic") from exc

    network_type = struct.unpack(endian + "I", raw[20:24])[0]
    if network_type != 1:
        raise PcapError("only Ethernet PCAP files are supported")

    packets: list[Packet] = []
    offset = 24

    while offset < len(raw):
        if offset + 16 > len(raw):
            raise PcapError("truncated packet record header")

        seconds, fraction, captured_length, _ = struct.unpack(
            endian + "IIII",
            raw[offset : offset + 16],
        )
        offset += 16

        end = offset + captured_length
        if end > len(raw):
            raise PcapError("truncated packet data")

        frame = raw[offset:end]
        offset = end
        if len(frame) < 14:
            continue

        ether_type = _read_u16(frame, 12)
        payload_offset = 14

        if ether_type == 0x8100 and len(frame) >= 18:
            ether_type = _read_u16(frame, 16)
            payload_offset = 18

        if ether_type != 0x0800:
            continue

        timestamp = seconds + fraction / timestamp_scale
        packet = _parse_ipv4(frame, payload_offset, timestamp)
        if packet is not None:
            packets.append(packet)

    return packets


def summarize(packets: list[Packet]) -> dict:
    protocols = Counter(packet.protocol for packet in packets)
    hosts = Counter()

    for packet in packets:
        hosts[packet.src] += 1
        hosts[packet.dst] += 1

    return {
        "packets": len(packets),
        "bytes": sum(packet.length for packet in packets),
        "protocols": dict(protocols.most_common()),
        "top_hosts": hosts.most_common(10),
    }


def to_json(packets: list[Packet]) -> str:
    return json.dumps(
        {
            "summary": summarize(packets),
            "packets": [asdict(packet) for packet in packets],
        },
        indent=2,
    )
