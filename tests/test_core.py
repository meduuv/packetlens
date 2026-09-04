import struct
import tempfile
import unittest
from pathlib import Path

from packetlens.core import PcapError, parse_pcap, summarize


class PacketLensTests(unittest.TestCase):
    @staticmethod
    def _pcap_with_udp_packet() -> bytes:
        ethernet = b"\x00" * 12 + b"\x08\x00"
        ipv4 = (
            b"\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x11\x00\x00"
            b"\x01\x02\x03\x04\x05\x06\x07\x08"
        )
        udp = struct.pack("!HHHH", 53, 9999, 8, 0)
        frame = ethernet + ipv4 + udp
        global_header = b"\xd4\xc3\xb2\xa1" + struct.pack(
            "<HHIIII",
            2,
            4,
            0,
            0,
            65535,
            1,
        )
        packet_record = struct.pack(
            "<IIII",
            1,
            0,
            len(frame),
            len(frame),
        ) + frame
        return global_header + packet_record

    def test_parse_udp_packet(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.pcap"
            path.write_bytes(self._pcap_with_udp_packet())
            packets = parse_pcap(path)

        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].protocol, "UDP")
        self.assertEqual(packets[0].src, "1.2.3.4")
        self.assertEqual(packets[0].dst, "5.6.7.8")
        self.assertEqual(packets[0].src_port, 53)
        self.assertEqual(packets[0].dst_port, 9999)
        self.assertEqual(summarize(packets)["packets"], 1)

    def test_rejects_invalid_pcap(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.pcap"
            path.write_bytes(b"not-a-pcap")
            with self.assertRaises(PcapError):
                parse_pcap(path)

    def test_rejects_truncated_packet_record(self):
        payload = self._pcap_with_udp_packet()[:-1]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "truncated.pcap"
            path.write_bytes(payload)
            with self.assertRaises(PcapError):
                parse_pcap(path)


if __name__ == "__main__":
    unittest.main()
