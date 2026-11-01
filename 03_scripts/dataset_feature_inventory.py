"""
dataset_feature_inventory.py
============================

Lists the CSV features and the PCAP/PCAPng features of every dataset under the
DATASETS/01_raw_datasets folder (ASEADOS-SDN-IoT, CyberFlowIoT-GICAP, TII-SSRC-23).


1. Folder layout expected
-------------------------
Each top-level sub-folder of the root is treated as one dataset:

    DATASETS/01_raw_datasets/
        ASEADOS-SDN-IoT/      csv/*.csv, pcap/**/*.pcap  (+ .7z copies, skipped)
        CyberFlowIoT-GICAP/   01_Raw/**/*.pcapng, 02_Pcap/**/*.pcap,
                              03_Flows/**/*.csv, 04_Manifests/*.csv,
                              05_Labeled_Flows/**/*.csv, 06_Datasets/*.csv|*.parquet
        TII-SSRC-23/          csv/**/*.csv, pcap/**/*.pcap and *.pcap.zip

Files directly in the root are ignored.


2. How the CSV features are extracted
-------------------------------------
Step 2.1  Walk every folder under the root with os.walk().
Step 2.2  For every file ending in .csv, open it as UTF-8 (bad bytes are
          replaced, so a stray character never stops the scan) and read ONLY
          the first row with csv.reader. That first row is the header, i.e.
          the list of feature/column names. Data rows are never loaded, so even
          multi-GB CSVs are read in milliseconds.
Step 2.3  Strip spaces around each column name (CICFlowMeter writes headers
          like " Dst Port").
Step 2.4  Group files by their exact header. Files with identical headers form
          one "schema". Example: the 164 files in CyberFlowIoT-GICAP/03_Flows
          all share one 86-column schema, so it is printed once with a count.
Step 2.5  For .parquet files, read only the schema (column names) with
          pyarrow.parquet.read_schema(); no rows are loaded.
Step 2.6  Print each schema as a numbered list, in the column order of the
          file: 1. Flow ID, 2. Src IP, ...

Note: CSVs that hold metadata rather than traffic features (CyberFlow
04_Manifests, Summary_by_AttackTraffic_type.csv) are listed too, as separate
schemas; tell them apart by path.


3. How the PCAP/PCAPng features are extracted
---------------------------------------------
A capture file does not have "columns". It stores raw packets, and each packet
is a stack of protocol headers (Ethernet -> IP -> TCP -> payload). The PCAP
features are the header fields of each protocol layer found in the capture.

Step 3.1  Find every capture:
            *.pcap      opened with scapy PcapReader
            *.pcapng    opened with scapy PcapNgReader
            *.pcap.zip  each .pcap/.pcapng inside the zip is streamed straight
                        out of the archive (zipfile.open), never extracted
                        to disk
            *.7z        skipped (Python has no built-in 7z reader); ASEADOS
                        already has extracted copies next to the .7z files.
Step 3.2  Read packets one at a time (streaming, so a 5 GB capture never has to
          fit in memory) and stop after the first N packets (default 3000,
          --packets to change).
Step 3.3  For each packet, walk the layer chain: start at the outer layer
          (pkt), record it, then move to pkt.payload, and repeat until scapy's
          end marker NoPayload is reached.
              Ether -> IP -> TCP -> Raw -> NoPayload (stop)
Step 3.4  For each layer reached, record:
            - the layer name (scapy class name, e.g. "TCP")
            - every field scapy defines for that header (layer.fields_desc),
              kept in wire order (sport, dport, seq, ack, ...)
            - how many packets contained that layer (used as evidence below)
          Results are merged per dataset, so a layer seen in any capture of
          the dataset is listed once.
Step 3.5  Sort the layers into protocol-stack groups (link, network,
          transport, control, application, ICMP-quoted, payload) using the
          LAYER_GROUP table below.
Step 3.6  Flag layers in SUSPECT_LAYERS with "*". Scapy names some
          application layers by port number only, so flood/scan packets aimed
          at random ports get labelled as HSRP, RIP, VXLAN, etc. The packet
          count printed next to each layer helps judge whether a layer is real
          traffic or a port-number guess.
Step 3.7  Append the frame metadata every capture stores with each packet
          (time, caplen, wirelen). pcapng also stores an interface ID per packet.
Step 3.8  Print the numbered list: layers numbered 1, 2, 3 ...; fields
          numbered layer.field, e.g. 7.3 = third field of layer 7.

Layers named *error (IPerror, TCPerror, UDPerror, ICMPerror) are copies of the
original packet's headers quoted inside an ICMP error message.


4. Caveats
----------
* Only the first N packets of each capture are decoded. A protocol that first
  appears later in a capture is missed. Raise --packets for full coverage,
  at the cost of run time.
* CyberFlowIoT-GICAP stores each capture twice (01_Raw .pcapng and 02_Pcap
  .pcap), so its capture count is doubled; the features are the same.


5. Requirements and usage
-------------------------
    Python 3.9+, scapy, pyarrow (only if a .parquet file is present)
    pip install scapy pyarrow

    python dataset_feature_inventory.py                       # scans ../01_raw_datasets
    python dataset_feature_inventory.py "<datasets folder>" --packets 3000 > inventory.txt

Unreadable files are reported on stderr and skipped. Thesis inventory run
(2026-11-01): --packets 3000, no read errors on any file.
"""
import argparse
import collections
import csv
import io
import os
import sys
import zipfile

from scapy.all import PcapNgReader, PcapReader, conf

conf.verb = 0

# Step 3.5: protocol-stack group of each scapy layer. Unlisted layers go to "Other".
GROUPS = ["Link layer", "Network layer", "Transport layer", "Control / diagnostic",
          "Application layer", "Headers quoted inside ICMP errors", "Payload", "Other"]
LAYER_GROUP = {
    "Ether": 0, "CookedLinux": 0, "CookedLinuxV2": 0, "ARP": 0, "PPP": 0, "Dot1Q": 0,
    "IP": 1, "IPv6": 1, "GRE": 1,
    "TCP": 2, "UDP": 2,
    "ICMP": 3, "ICMPv6ND_RS": 3, "ICMPv6NDOptSrcLLAddr": 3,
    "IPerror": 5, "TCPerror": 5, "UDPerror": 5, "ICMPerror": 5,
    "Raw": 6, "Padding": 6,
}
APPLICATION = {
    "DNS", "BOOTP", "DHCP", "NTPHeader", "NBTDatagram", "SMB_Header", "SMBMailslot_Write",
    "ESP", "HSRP", "HSRPmd5", "L2TP", "LDAP", "KerberosTCPHeader", "MobileIP",
    "MobileIPTunnelData", "NBTSession", "_SMBGeneric", "NetflowHeader", "PPTP", "RIP",
    "RIPEntry", "Radius", "Skinny", "VXLAN",
}
LAYER_GROUP.update({name: 4 for name in APPLICATION})

# Step 3.6: layers that scapy picks from the port number alone. In these datasets
# they come from floods/scans to random ports, not real use of the protocol.
SUSPECT_LAYERS = {
    "ESP", "HSRP", "HSRPmd5", "L2TP", "LDAP", "KerberosTCPHeader", "MobileIP",
    "MobileIPTunnelData", "NBTSession", "_SMBGeneric", "NetflowHeader", "PPTP", "RIP",
    "RIPEntry", "Radius", "Skinny", "VXLAN",
}

# Step 3.7: metadata stored with every packet record.
FRAME_METADATA = [("time", "capture timestamp"),
                  ("caplen", "captured length (bytes saved)"),
                  ("wirelen", "original length on the wire")]


def main():
    ap = argparse.ArgumentParser(description="List the CSV and PCAP/PCAPng features of each dataset.")
    ap.add_argument("root", nargs="?",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "01_raw_datasets"),
                    help="datasets folder; each sub-folder is one dataset (default: ../01_raw_datasets)")
    ap.add_argument("--packets", type=int, default=3000, help="packets decoded per capture (default 3000)")
    args = ap.parse_args()
    root, n_packets = args.root, args.packets

    # dataset -> header tuple -> list of files using that header   (Step 2.4)
    csv_heads = collections.defaultdict(lambda: collections.defaultdict(list))
    # dataset -> layer name -> {field name: None}; dict keeps wire order (Step 3.4)
    pcap_fields = collections.defaultdict(lambda: collections.defaultdict(dict))
    # dataset -> layer name -> number of packets containing the layer (Step 3.4)
    layer_packets = collections.defaultdict(collections.Counter)
    # dataset -> capture counts by format
    captures = collections.defaultdict(collections.Counter)

    def scan_pcap(ds, f, name):
        """Steps 3.2-3.4 for one capture (f is an open binary file object)."""
        try:
            is_ng = name.endswith(".pcapng")
            reader = PcapNgReader(f) if is_ng else PcapReader(f)
            for i, pkt in enumerate(reader):          # Step 3.2: stream packets
                if i >= n_packets:
                    break
                layer = pkt
                while layer and layer.__class__.__name__ != "NoPayload":   # Step 3.3
                    lname = layer.__class__.__name__
                    fields = pcap_fields[ds][lname]
                    for fd in layer.fields_desc:                          # Step 3.4
                        fields.setdefault(fd.name)
                    layer_packets[ds][lname] += 1
                    layer = layer.payload
            captures[ds]["pcapng" if is_ng else "pcap"] += 1
        except Exception as e:
            print("pcap fail", name, e, file=sys.stderr)

    # Steps 2.1 / 3.1: walk the tree and dispatch each file by extension
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, root)
            if os.sep not in rel:
                continue                                   # file in root itself, not a dataset
            ds = rel.split(os.sep)[0]
            low = fname.lower()
            try:
                if low.endswith(".csv"):                   # Steps 2.2-2.4
                    with open(path, newline="", encoding="utf-8", errors="replace") as f:
                        header = tuple(c.strip() for c in next(csv.reader(f), []))
                    csv_heads[ds][header].append(rel)
                elif low.endswith(".parquet"):             # Step 2.5
                    import pyarrow.parquet as pq
                    csv_heads[ds][tuple(pq.read_schema(path).names)].append(rel + " [parquet]")
                elif low.endswith((".pcap", ".pcapng")):  # Step 3.1
                    with open(path, "rb") as f:
                        scan_pcap(ds, f, low)
                elif low.endswith(".pcap.zip"):            # Step 3.1, streamed from zip
                    with zipfile.ZipFile(path) as z:
                        for member in z.namelist():
                            if member.lower().endswith((".pcap", ".pcapng")):
                                with z.open(member) as f:
                                    scan_pcap(ds, io.BufferedReader(f), member.lower())
            except Exception as e:
                print("read fail", rel, e, file=sys.stderr)

    # Output
    for ds in sorted(set(csv_heads) | set(pcap_fields)):
        print("=" * 80)
        print("DATASET:", ds)
        print("=" * 80)

        # Step 2.6: numbered CSV schemas
        for si, (header, files) in enumerate(csv_heads[ds].items(), 1):
            print(f"\nCSV schema {si}: {len(header)} columns, used by {len(files)} file(s)")
            print(f"  example: {files[0]}")
            for i, col in enumerate(header, 1):
                print(f"  {i}. {col}")

        if ds not in pcap_fields:
            print()
            continue

        # Step 3.8: numbered PCAP layers and fields, grouped by protocol stack
        layers = pcap_fields[ds]
        fmt = ", ".join(f"{n} .{k}" for k, n in sorted(captures[ds].items()))
        n_fields = sum(len(v) for v in layers.values())
        print(f"\nPCAP/PCAPng features: {fmt} (first {n_packets} packets each)")
        print(f"  {len(layers)} protocol layers, {n_fields} packet fields + {len(FRAME_METADATA)} frame metadata fields")

        ordered = sorted(layers, key=lambda n: LAYER_GROUP.get(n, 7))
        li = 0
        for g, group in enumerate(GROUPS):
            members = [n for n in ordered if LAYER_GROUP.get(n, 7) == g]
            if not members:
                continue
            print(f"\n  [{group}]")
            for name in members:
                li += 1
                flag = " *" if name in SUSPECT_LAYERS else ""
                print(f"  {li}. {name}{flag} ({len(layers[name])} fields, seen in {layer_packets[ds][name]} packets)")
                for fi, field in enumerate(layers[name], 1):
                    print(f"     {li}.{fi} {field}")

        li += 1
        print("\n  [Frame metadata]")
        print(f"  {li}. Frame record ({len(FRAME_METADATA)} fields)")
        for fi, (field, desc) in enumerate(FRAME_METADATA, 1):
            print(f"     {li}.{fi} {field} - {desc}")
        if captures[ds]["pcapng"]:
            print("     (pcapng files also store an interface ID per packet)")
        if any(n in SUSPECT_LAYERS for n in layers):
            print("\n  * likely a port-number guess by scapy, not real use of the protocol")
        print()


if __name__ == "__main__":
    main()
