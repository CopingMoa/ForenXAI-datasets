"""
pcap_flow_enricher.py
=====================

Adds packet-level features from a PCAP/PCAPng file to the CICFlowMeter v4 CSV
made from that same capture. One output row per CICFlowMeter flow; the new
columns are inserted just before "Label", so the original 84 columns keep their
order and values.

    python pcap_flow_enricher.py <capture.pcap|.pcapng> <capture.pcap_Flow.csv> <out.csv>
    python pcap_flow_enricher.py --selftest

Pipeline
--------
1. Read the CSV. Each flow gets a key (protocol + both endpoints, direction-free)
   and a time span [Timestamp, Timestamp + Flow Duration].
2. Detect the clock offset. CICFlowMeter writes Timestamp as local wall time with
   1-second precision; PCAP times are UTC epoch. The script tries offsets from
   -14 h to +14 h (30-min steps) on the first 5,000 packets and keeps the one that
   places the most packets inside a matching flow's span.
3. Stream the capture once (Scapy). For each IP packet, find its flow by key and
   time (1 s slack for the truncated timestamp) and update that flow's
   accumulators. ARP packets never belong to a flow; they are stored per IP and
   joined to flows by endpoint IP and time window (step 5).
4. Compute window aggregates from the CSV itself (flows from the same Src IP in
   the previous 2 s / 60 s).
5. Write the CSV with the new columns.

New columns (45)
----------------
IP header      pcap_ttl_min/max/mean/distinct, pcap_ecn_ce_count, pcap_df_ratio,
               pcap_frag_count, pcap_ip_options_count
TCP            pcap_win_min/max/mean, pcap_zero_win_count, pcap_mss, pcap_wscale,
               pcap_retrans_count, pcap_urgptr_nonzero
ICMP           pcap_icmp_echo_req, pcap_icmp_echo_rep, pcap_icmp_unreach
DNS            dns_query_count, dns_resp_count, dns_nxdomain_count,
               dns_qname_len_mean, dns_qname_entropy_mean
Payload        payload_entropy, payload_printable_ratio, payload_nop_count,
               payload_longest_run
Packet order   pcap_first10_size_1..10  (IP packet length, + forward / - backward,
               0 = flow has fewer packets)
ARP            arp_reply_count, arp_gratuitous_count, arp_mac_distinct
               (ARP packets claiming either endpoint IP, from 60 s before the
               flow start to the flow end)
Window         win2s_src_flows, win60s_src_flows, win60s_src_dstports
Check          pcap_matched_pkts (packets assigned to the flow)

Missing values: counts are 0; statistics with no data (e.g. TTL of a flow that
matched no packet, MSS of a non-TCP flow) are -1.

Sources for the feature choice: NetFlow v2 standard set (TTL, DNS, ICMP type,
retransmissions; Sarhan et al., arXiv 2101.11315), Kitsune / KDD Cup 99 window
counts, payload entropy (Kenyon et al., arXiv 2404.19121), first-N packet sizes
and payload byte patterns (Thesis 2 - RESEARCH.pdf, Q3).
"""
import argparse
import bisect
import csv
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime
from itertools import groupby

from scapy.all import PcapReader, conf
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

conf.verb = 0
SLACK = 1.0                 # seconds; CICFlowMeter Timestamp is truncated to the second
ARP_WINDOW = 60.0           # seconds before flow start that count for ARP features
PAYLOAD_CAP = 65536         # ponytail: payload bytes analysed per flow; raise for exact stats on bulk flows
FIRST_N = 10
EPOCH = datetime(1970, 1, 1)

NEW_COLS = (["pcap_ttl_min", "pcap_ttl_max", "pcap_ttl_mean", "pcap_ttl_distinct",
             "pcap_ecn_ce_count", "pcap_df_ratio", "pcap_frag_count", "pcap_ip_options_count",
             "pcap_win_min", "pcap_win_max", "pcap_win_mean", "pcap_zero_win_count",
             "pcap_mss", "pcap_wscale", "pcap_retrans_count", "pcap_urgptr_nonzero",
             "pcap_icmp_echo_req", "pcap_icmp_echo_rep", "pcap_icmp_unreach",
             "dns_query_count", "dns_resp_count", "dns_nxdomain_count",
             "dns_qname_len_mean", "dns_qname_entropy_mean",
             "payload_entropy", "payload_printable_ratio", "payload_nop_count", "payload_longest_run"]
            + [f"pcap_first10_size_{i}" for i in range(1, FIRST_N + 1)]
            + ["arp_reply_count", "arp_gratuitous_count", "arp_mac_distinct",
               "win2s_src_flows", "win60s_src_flows", "win60s_src_dstports",
               "pcap_matched_pkts"])


# ---------------------------------------------------------------- helpers
def entropy(hist):
    """Shannon entropy in bits of a Counter/histogram of symbols."""
    n = sum(hist.values())
    return -sum(c / n * math.log2(c / n) for c in hist.values() if c) if n else -1


def parse_ts(s):
    for fmt in ("%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S"):   # v4, v3
        try:
            return (datetime.strptime(s.strip(), fmt) - EPOCH).total_seconds()
        except ValueError:
            pass
    raise ValueError(f"unknown Timestamp format: {s!r}")


def flow_key(proto, a_ip, a_port, b_ip, b_port):
    a, b = (a_ip, a_port), (b_ip, b_port)
    return (proto,) + ((a, b) if a <= b else (b, a))


class Acc:
    __slots__ = ("ttls", "n_ip", "ecn", "df", "frag", "ipopt", "wins", "zero_win", "mss", "wscale",
                 "seqs", "retrans", "urg", "icmp_req", "icmp_rep", "icmp_unr", "dns_q", "dns_r",
                 "dns_nx", "qlens", "qents", "hist", "longest", "run_byte", "run_len", "first", "pkts")

    def __init__(self):
        self.ttls, self.wins, self.qlens, self.qents, self.first = [], [], [], [], []
        self.n_ip = self.ecn = self.df = self.frag = self.ipopt = self.zero_win = 0
        self.retrans = self.urg = self.icmp_req = self.icmp_rep = self.icmp_unr = 0
        self.dns_q = self.dns_r = self.dns_nx = self.longest = self.run_len = self.pkts = 0
        self.mss = self.wscale = self.run_byte = -1
        self.seqs = set()
        self.hist = Counter()

    def add_payload(self, raw):
        room = PAYLOAD_CAP - sum(self.hist.values())
        raw = raw[:room]
        if not raw:
            return
        self.hist.update(raw)
        for byte, grp in groupby(raw):
            n = sum(1 for _ in grp)
            self.run_len = self.run_len + n if byte == self.run_byte else n
            self.run_byte = byte
            self.longest = max(self.longest, self.run_len)

    def row(self):
        mean = lambda v: round(sum(v) / len(v), 4) if v else -1
        n_hist = sum(self.hist.values())
        printable = sum(c for b, c in self.hist.items() if 0x20 <= b <= 0x7E)
        first = self.first + [0] * (FIRST_N - len(self.first))
        return ([min(self.ttls, default=-1), max(self.ttls, default=-1), mean(self.ttls), len(set(self.ttls)),
                 self.ecn, round(self.df / self.n_ip, 4) if self.n_ip else -1, self.frag, self.ipopt,
                 min(self.wins, default=-1), max(self.wins, default=-1), mean(self.wins), self.zero_win,
                 self.mss, self.wscale, self.retrans, self.urg,
                 self.icmp_req, self.icmp_rep, self.icmp_unr,
                 self.dns_q, self.dns_r, self.dns_nx, mean(self.qlens), mean(self.qents),
                 round(entropy(self.hist), 4) if n_hist else -1,
                 round(printable / n_hist, 4) if n_hist else -1, self.hist.get(0x90, 0), self.longest]
                + first)


# ---------------------------------------------------------------- main steps
def load_csv(path):
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        r = csv.reader(f)
        header = [h.strip() for h in next(r)]
        rows = [row for row in r if len(row) == len(header)]
    col = {name: header.index(name) for name in
           ("Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp", "Flow Duration", "Label")}
    flows = []          # (key, start, end, src_ip, src_port, dst_ip, dst_port)
    index = defaultdict(list)
    for i, row in enumerate(rows):
        s_ip, d_ip = row[col["Src IP"]], row[col["Dst IP"]]
        s_pt, d_pt, proto = int(row[col["Src Port"]]), int(row[col["Dst Port"]]), int(row[col["Protocol"]])
        start = parse_ts(row[col["Timestamp"]])
        end = start + float(row[col["Flow Duration"]]) / 1e6
        key = flow_key(proto, s_ip, s_pt, d_ip, d_pt)
        flows.append((key, start, end, s_ip, s_pt, d_ip, d_pt))
        index[key].append((start, end, i))
    index = {k: ([s for s, _, _ in sorted(v)], sorted(v)) for k, v in index.items()}
    return header, rows, col, flows, index


def find_flow(index, key, t, used=None, cap=None):
    """Flow (row index) with this key whose span covers t. When several flows with the same
    key cover t (1-s timestamps, quick port reuse), take the earliest one that still has
    packets left according to CICFlowMeter's own packet count; otherwise the latest."""
    hit = index.get(key)
    if not hit:
        return None
    starts, spans = hit
    i = bisect.bisect_right(starts, t + SLACK) - 1
    cands = [spans[j][2] for j in range(i, max(i - 20, -1), -1) if t <= spans[j][1] + SLACK]
    if not cands:
        return None
    if used is not None:
        # Never exceed CICFlowMeter's own packet count: e.g. v4 does not count the final ACK
        # after FIN, so that packet is left out here too.
        return next((r for r in reversed(cands) if used[r] < cap[r]), None)   # earliest with room
    return cands[0]


def packet_keys(pkt):
    """Return (ip_layer, l4_name, keys_to_try, src, sport) or None for non-IP."""
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:
        return None
    if TCP in pkt:
        l4, proto = pkt[TCP], 6
    elif UDP in pkt:
        l4, proto = pkt[UDP], 17
    else:
        l4, proto = None, (ip.proto if isinstance(ip, IP) else ip.nh)
    sport, dport = (l4.sport, l4.dport) if l4 is not None else (0, 0)
    keys = [flow_key(proto, ip.src, sport, ip.dst, dport)]
    if l4 is None:
        keys.append(flow_key(0, ip.src, 0, ip.dst, 0))  # CICFlowMeter may write non-TCP/UDP as protocol 0
    return ip, l4, keys, ip.src, sport


def detect_offset(capture, index, sample=5000):
    samples = []
    with PcapReader(capture) as rd:
        for pkt in rd:
            pk = packet_keys(pkt)
            if pk and any(k in index for k in pk[2]):
                samples.append((float(pkt.time), pk[2]))
                if len(samples) >= sample:
                    break
    best, best_score = 0, (-1, 0)
    for off in range(-14 * 3600, 14 * 3600 + 1, 1800):
        hits, dist = 0, 0.0
        for t, keys in samples:
            for k in keys:
                r = find_flow(index, k, t + off)
                if r is not None:
                    hits += 1
                    dist += abs(t + off - starts_of[r])
                    break
        score = (hits, -dist)                       # most packets matched; ties -> closest to flow starts
        if score > best_score:
            best, best_score = off, score
    return best, best_score[0], len(samples)


def enrich(capture, csv_in, csv_out):
    global starts_of
    header, rows, col, flows, index = load_csv(csv_in)
    starts_of = [f[1] for f in flows]
    # columns 9-10 = Total Fwd/Bwd packets in both v3 and v4 naming
    cap = [int(float(row[8])) + int(float(row[9])) for row in rows]
    used = [0] * len(rows)
    offset, hits, n = detect_offset(capture, index)
    print(f"[offset] {offset / 3600:+.1f} h ({hits}/{n} sample packets matched)", file=sys.stderr)

    accs = defaultdict(Acc)
    arp = defaultdict(list)      # claimed IP -> [(time, op, hwsrc, gratuitous)]
    total = ip_pkts = matched = 0
    with PcapReader(capture) as rd:
        for pkt in rd:
            total += 1
            t = float(pkt.time) + offset
            if ARP in pkt:
                a = pkt[ARP]
                arp[a.psrc].append((t, a.op, a.hwsrc, a.psrc == a.pdst))
                continue
            pk = packet_keys(pkt)
            if pk is None:
                continue
            ip_pkts += 1
            ip, l4, keys, src, sport = pk
            r = next((x for x in (find_flow(index, k, t, used, cap) for k in keys) if x is not None), None)
            if r is None:
                continue
            used[r] += 1
            matched += 1
            a = accs[r]
            a.pkts += 1
            fwd = (src, sport) == (flows[r][3], flows[r][4])

            # IP header
            if isinstance(ip, IP):
                a.ttls.append(ip.ttl)
                a.ecn += (ip.tos & 3) == 3
                a.df += bool(ip.flags.DF)
                a.frag += bool(ip.flags.MF) or ip.frag > 0
                a.ipopt += ip.ihl > 5
                ip_len, hdr = ip.len, ip.ihl * 4
            else:
                a.ttls.append(ip.hlim)
                a.ecn += (ip.tc & 3) == 3
                ip_len, hdr = ip.plen + 40, 40
            a.n_ip += 1
            if len(a.first) < FIRST_N:
                a.first.append(ip_len if fwd else -ip_len)

            # TCP / UDP payload
            raw = b""
            if isinstance(l4, TCP):
                a.wins.append(l4.window)
                a.zero_win += l4.window == 0 and not (l4.flags & 0x04)
                a.urg += l4.urgptr != 0
                plen = max(ip_len - hdr - l4.dataofs * 4, 0)
                if l4.flags & 0x02:                      # SYN: read options once
                    for name, val in l4.options:
                        if name == "MSS" and a.mss < 0:
                            a.mss = val
                        elif name == "WScale" and a.wscale < 0:
                            a.wscale = val
                if plen:
                    seq = (fwd, l4.seq)
                    if seq in a.seqs:
                        a.retrans += 1
                    else:
                        a.seqs.add(seq)
                    raw = bytes(l4.payload)[:plen]
            elif isinstance(l4, UDP):
                raw = bytes(l4.payload)[:max(l4.len - 8, 0)]
            a.add_payload(raw)

            # ICMP
            if ICMP in pkt:
                ty = pkt[ICMP].type
                a.icmp_req += ty == 8
                a.icmp_rep += ty == 0
                a.icmp_unr += ty == 3

            # DNS
            if DNS in pkt:
                d = pkt[DNS]
                if d.qr:
                    a.dns_r += 1
                    a.dns_nx += d.rcode == 3
                else:
                    a.dns_q += 1
                try:
                    name = d.qd[0].qname.rstrip(b".")   # qd is a list in Scapy >= 2.6; may be empty
                except (IndexError, TypeError, AttributeError):
                    name = b""
                if name:
                    a.qlens.append(len(name))
                    a.qents.append(entropy(Counter(name)))

    # ARP join + window aggregates
    for v in arp.values():
        v.sort()
    arp_times = {ip: [e[0] for e in v] for ip, v in arp.items()}
    by_src = defaultdict(list)
    for i, f in enumerate(flows):
        by_src[f[3]].append((f[1], f[6], i))
    win = {}
    for src, lst in by_src.items():
        lst.sort()
        lo2 = lo60 = 0
        ports = Counter()
        for hi, (s, dport, i) in enumerate(lst):
            ports[dport] += 1
            while lst[lo2][0] < s - 2:
                lo2 += 1
            while lst[lo60][0] < s - 60:
                p = lst[lo60][1]
                ports[p] -= 1
                if not ports[p]:
                    del ports[p]
                lo60 += 1
            win[i] = (hi - lo2 + 1, hi - lo60 + 1, len(ports))

    with open(csv_out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        li = col["Label"]
        w.writerow(header[:li] + NEW_COLS + header[li:])
        empty = Acc().row()
        for i, row in enumerate(rows):
            _, start, end, s_ip, _, d_ip, _ = flows[i]
            replies = grat = 0
            macs = set()
            for ipaddr in (s_ip, d_ip):
                ts = arp_times.get(ipaddr)
                if not ts:
                    continue
                for t, op, hw, g in arp[ipaddr][bisect.bisect_left(ts, start - ARP_WINDOW):bisect.bisect_right(ts, end + SLACK)]:
                    replies += op == 2
                    grat += g
                    macs.add((ipaddr, hw))
            mac_distinct = max((sum(1 for ip_, _ in macs if ip_ == x) for x in (s_ip, d_ip)), default=0)
            feats = accs[i].row() if i in accs else empty
            w.writerow(row[:li] + feats + [replies, grat, mac_distinct, *win[i],
                                           accs[i].pkts if i in accs else 0] + row[li:])

    flows_hit = len(accs)
    print(f"[packets] total {total:,} | IP {ip_pkts:,} | matched to a flow {matched:,} "
          f"({matched / ip_pkts:.1%} of IP)" if ip_pkts else "[packets] no IP packets", file=sys.stderr)
    print(f"[flows] {len(rows):,} flows | with >=1 matched packet {flows_hit:,} ({flows_hit / len(rows):.1%}) "
          f"| ARP packets {sum(len(v) for v in arp.values()):,}", file=sys.stderr)
    print(f"[out] {csv_out}: {len(header) + len(NEW_COLS)} columns", file=sys.stderr)


def selftest():
    assert entropy(Counter(range(256))) == 8.0
    assert entropy(Counter(b"aaaa")) == 0
    assert flow_key(6, "10.0.0.2", 80, "10.0.0.1", 5000) == flow_key(6, "10.0.0.1", 5000, "10.0.0.2", 80)
    assert parse_ts("22/11/2023 11:40:38 AM") == parse_ts("22/11/2023 11:40:38")
    a = Acc()
    a.add_payload(b"\x90\x90\x90AB")
    a.add_payload(b"\x90")
    r = a.row()
    assert r[NEW_COLS.index("payload_nop_count")] == 4 and r[NEW_COLS.index("payload_longest_run")] == 3
    assert r[NEW_COLS.index("payload_printable_ratio")] == round(2 / 6, 4)
    assert len(r) + 7 == len(NEW_COLS)
    print("selftest ok")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Attach PCAP packet features to a CICFlowMeter v4 CSV.")
    ap.add_argument("capture", nargs="?", help=".pcap or .pcapng file")
    ap.add_argument("csv_in", nargs="?", help="CICFlowMeter v4 CSV generated from that capture")
    ap.add_argument("csv_out", nargs="?", help="output CSV")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
    elif a.capture and a.csv_in and a.csv_out:
        enrich(a.capture, a.csv_in, a.csv_out)
    else:
        ap.error("give capture, csv_in and csv_out (or --selftest)")
