# PacketLens

A compact PCAP inspector for quick traffic triage. PacketLens reads classic Ethernet PCAP files directly with Python's standard library, summarizes protocols and hosts, and can emit structured JSON for further analysis.

## Highlights

* Dependency-free PCAP parsing
* IPv4 TCP, UDP and ICMP recognition
* VLAN-aware Ethernet decoding
* Protocol and host summaries
* Human-readable terminal output
* JSON export for scripts and pipelines
* Tested on Python 3.10 through 3.13

## Install

```bash
git clone https://github.com/meduuv/packetlens.git
cd packetlens
pip install -e .
```

## Usage

```bash
packetlens capture.pcap
packetlens capture.pcap --json
packetlens capture.pcap --limit 30
```

PacketLens intentionally focuses on safe offline inspection of packet captures you are authorized to analyze. It does not capture live traffic or modify network data.

## Development

```bash
python -m unittest discover -s tests -v
```

## Credits

Built by [meduuv](https://guns.lol/meduu).

## License

MIT
