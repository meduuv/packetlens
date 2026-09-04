from __future__ import annotations
import ipaddress, json, struct
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass(slots=True)
class Packet:
    ts: float; src: str; dst: str; protocol: str; src_port: int|None; dst_port: int|None; length: int

class PcapError(ValueError): pass

def _read_u16(data: bytes, off: int) -> int: return struct.unpack('!H', data[off:off+2])[0]

def parse_pcap(path: str|Path) -> list[Packet]:
    raw=Path(path).read_bytes()
    if len(raw)<24: raise PcapError('file is too small to be a PCAP')
    magic=raw[:4]
    fmts={b'\xd4\xc3\xb2\xa1':('<',1_000_000),b'\xa1\xb2\xc3\xd4':('>',1_000_000),b'\x4d\x3c\xb2\xa1':('<',1_000_000_000),b'\xa1\xb2\x3c\x4d':('>',1_000_000_000)}
    if magic not in fmts: raise PcapError('unsupported PCAP magic')
    endian,scale=fmts[magic]; network=struct.unpack(endian+'I',raw[20:24])[0]
    if network!=1: raise PcapError('only Ethernet PCAP files are supported')
    out=[]; off=24
    while off+16<=len(raw):
        sec,sub,incl,_=struct.unpack(endian+'IIII',raw[off:off+16]); off+=16
        frame=raw[off:off+incl]; off+=incl
        if len(frame)<14: continue
        eth_type=_read_u16(frame,12); pos=14
        if eth_type==0x8100 and len(frame)>=18: eth_type=_read_u16(frame,16); pos=18
        if eth_type!=0x0800 or len(frame)<pos+20: continue
        ihl=(frame[pos]&0x0F)*4
        if ihl<20 or len(frame)<pos+ihl: continue
        proto=frame[pos+9]; src=str(ipaddress.ip_address(frame[pos+12:pos+16])); dst=str(ipaddress.ip_address(frame[pos+16:pos+20]))
        sport=dport=None; name={6:'TCP',17:'UDP',1:'ICMP'}.get(proto,f'IP/{proto}')
        l4=pos+ihl
        if proto in (6,17) and len(frame)>=l4+4: sport,dport=_read_u16(frame,l4),_read_u16(frame,l4+2)
        out.append(Packet(sec+sub/scale,src,dst,name,sport,dport,len(frame)))
    return out

def summarize(packets: list[Packet]) -> dict:
    protocols=Counter(p.protocol for p in packets); hosts=Counter()
    for p in packets: hosts[p.src]+=1; hosts[p.dst]+=1
    return {'packets':len(packets),'bytes':sum(p.length for p in packets),'protocols':dict(protocols.most_common()),'top_hosts':hosts.most_common(10)}

def to_json(packets:list[Packet])->str:
    return json.dumps({'summary':summarize(packets),'packets':[asdict(p) for p in packets]},indent=2)
