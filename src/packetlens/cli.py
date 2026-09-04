import argparse
from .core import parse_pcap, summarize, to_json, PcapError

def main():
    p=argparse.ArgumentParser(prog='packetlens',description='Inspect Ethernet PCAP files without heavyweight dependencies.')
    p.add_argument('pcap'); p.add_argument('-j','--json',action='store_true',dest='json_out'); p.add_argument('-n','--limit',type=int,default=15)
    a=p.parse_args()
    try: packets=parse_pcap(a.pcap)
    except (OSError,PcapError) as e: p.error(str(e))
    if a.json_out: print(to_json(packets)); return
    s=summarize(packets); print(f"Packets: {s['packets']}\nBytes:   {s['bytes']}")
    print('Protocols:'); [print(f'  {k:<10} {v}') for k,v in s['protocols'].items()]
    print('Recent packets:')
    for x in packets[:max(0,a.limit)]: print(f'  {x.src}:{x.src_port or ""} -> {x.dst}:{x.dst_port or ""}  {x.protocol:<6} {x.length} B')
if __name__=='__main__': main()
