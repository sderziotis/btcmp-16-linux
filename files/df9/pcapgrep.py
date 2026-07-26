#!/usr/bin/env python3
"""
pcapgrep.py - Module 9 fallback analyser. Python 3 standard library ONLY.
No install, no admin rights, no npcap, no Suricata.

Use it when the CR image has no IDS, or to sanity-check what an IDS
*should* have seen before you blame your rule.

    python3 pcapgrep.py capture.pcap                 # HTTP requests + DNS queries
    python3 pcapgrep.py capture.pcap --headers       # full request headers
    python3 pcapgrep.py capture.pcap --grep telemetry
    python3 pcapgrep.py capture.pcap --timing        # inter-request deltas per host
"""
import struct, sys, socket, collections

LINKTYPE_ETHERNET = 1


def read_pcap(path):
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            raise SystemExit("not a pcap file")
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, nano = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, nano = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, nano = "<", True
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, nano = ">", True
        else:
            raise SystemExit("unsupported capture format (pcapng? re-save as pcap)")
        link = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            ph = fh.read(16)
            if len(ph) < 16:
                return
            ts, tus, caplen, _ = struct.unpack(endian + "IIII", ph)
            data = fh.read(caplen)
            yield ts + (tus / 1e9 if nano else tus / 1e6), link, data


def parse(frame, link):
    """-> (proto, src, sport, dst, dport, payload) or None"""
    if link == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        etype = struct.unpack("!H", frame[12:14])[0]
        off = 14
        while etype in (0x8100, 0x88A8):          # VLAN tags
            etype = struct.unpack("!H", frame[off + 2:off + 4])[0]
            off += 4
        if etype != 0x0800:
            return None
        ip = frame[off:]
    else:
        ip = frame
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    total = struct.unpack("!H", ip[2:4])[0]
    seg = ip[ihl:total] if total else ip[ihl:]
    if proto == 6 and len(seg) >= 20:
        sport, dport = struct.unpack("!HH", seg[0:4])
        doff = (seg[12] >> 4) * 4
        return "tcp", src, sport, dst, dport, seg[doff:]
    if proto == 17 and len(seg) >= 8:
        sport, dport = struct.unpack("!HH", seg[0:4])
        return "udp", src, sport, dst, dport, seg[8:]
    return None


METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")


def dns_qname(payload):
    try:
        if len(payload) < 12 or struct.unpack("!H", payload[6:8])[0] > 0:
            pass
        i, labels = 12, []
        while payload[i]:
            n = payload[i]
            labels.append(payload[i + 1:i + 1 + n].decode("ascii", "replace"))
            i += n + 1
        return ".".join(labels)
    except Exception:
        return None


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    path = sys.argv[1]
    show_headers = "--headers" in sys.argv
    timing = "--timing" in sys.argv
    needle = None
    if "--grep" in sys.argv:
        needle = sys.argv[sys.argv.index("--grep") + 1].lower()

    t0 = None
    seen = collections.Counter()
    by_target = collections.defaultdict(list)

    for ts, link, frame in read_pcap(path):
        r = parse(frame, link)
        if not r:
            continue
        proto, src, sport, dst, dport, payload = r
        if not payload:
            continue
        t0 = ts if t0 is None else t0
        rel = ts - t0

        if proto == "udp" and dport == 53:
            q = dns_qname(payload)
            if q and (not needle or needle in q.lower()):
                print(f"[{rel:8.2f}s] DNS   {src:>15} -> {q}")
                seen["dns"] += 1
            continue

        if proto != "tcp" or not payload.startswith(METHODS):
            continue
        text = payload.decode("latin-1")
        head, _, body = text.partition("\r\n\r\n")
        lines = head.split("\r\n")
        reqline = lines[0]
        hdrs = dict(
            (h.split(":", 1)[0].strip().lower(), h.split(":", 1)[1].strip())
            for h in lines[1:] if ":" in h
        )
        blob = (head + body).lower()
        if needle and needle not in blob:
            continue
        host = hdrs.get("host", dst)
        key = f"{host} ({dst}:{dport})"
        by_target[key].append(rel)
        seen["http"] += 1
        print(f"[{rel:8.2f}s] HTTP  {src}:{sport} -> {dst}:{dport}  {reqline}")
        print(f"{'':11}Host: {host}   UA: {hdrs.get('user-agent','-')}")
        if show_headers:
            for h in lines[1:]:
                print(f"{'':13}{h}")
            if body.strip():
                print(f"{'':13}body[{len(body)}]: {body[:120]}")
        seen[f"ua:{hdrs.get('user-agent','-')}"] += 1

    print(f"\n== {seen['http']} HTTP requests, {seen['dns']} DNS queries ==")
    print("\nrequests per destination:")
    for k, v in sorted(by_target.items(), key=lambda x: -len(x[1])):
        print(f"  {len(v):>3}  {k}")
    print("\nrequests per User-Agent:")
    for k, v in seen.items():
        if k.startswith("ua:"):
            print(f"  {v:>3}  {k[3:]}")

    if timing:
        print("\ninter-request deltas (seconds):")
        for k, v in sorted(by_target.items(), key=lambda x: -len(x[1])):
            if len(v) < 3:
                continue
            d = [round(v[i + 1] - v[i], 1) for i in range(len(v) - 1)]
            jitter = (max(d) - min(d)) / (sum(d) / len(d)) * 100
            print(f"  {k}\n     deltas={d}\n     mean={sum(d)/len(d):.1f}s  "
                  f"spread={jitter:.1f}% of mean")


if __name__ == "__main__":
    main()
