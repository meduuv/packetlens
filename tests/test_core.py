import struct
tempfile = __import__('tempfile')
import unittest
from pathlib import Path

from packetlens.core import PcapError, parse_pcap, summarize


class PacketLensTests(unittest.TestCase):
    def test_parse_udp_packet(self):
        ethernet = b'\x00' * 12 + b'\x08\x00'
        ipv4 = (
            b'\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x11\x00\x00'
            b'\x01\x02\x03\x04\x05\x06\x07\x08'
        )
        udp = struct.pack('!HHHH', 53, 9999, 8, 0)
        frame = ethernet + ipv4 + udp
        header = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 1)
        record = struct.pack('<IIII', 1, 0, len(frame), len(frame)) + frame

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.pcap'
            path.write_bytes(header + record)
            packets = parse_pcap(path)

        self.assertEqual(packets[0].protocol, 'UDP')
        self.assertEqual(packets[0].src_port, 53)
        self.assertEqual(summarize(packets)['packets'], 1)

    def test_rejects_invalid_pcap(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.pcap'
            path.write_bytes(b'not-a-pcap')
            with self.assertRaises(PcapError):
                parse_pcap(path)


if __name__ == '__main__':
    unittest.main()
