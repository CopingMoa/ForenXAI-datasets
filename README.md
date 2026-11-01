# ForenXAI – Datasets & CICFlowMeter Feature Preparation

Dataset preparation for the ForenXAI thesis: inventory of three IoT intrusion datasets,
CICFlowMeter v3 / v4 flow-feature extraction, and evidence of which CICFlowMeter version each
published dataset used.

> **Raw datasets are not included** (~94 GB of third-party data, above GitHub's limits).
> Obtain them from each dataset's official release and place them in `01_raw_datasets/`.

## Layout

```
DATASETS/
├─ 01_raw_datasets/           (local only, git-ignored)
│  ├─ ASEADOS-SDN-IoT/        csv/ASEADOS_SDN_IoT.csv, pcap/attack, pcap/benign
│  ├─ CyberFlowIoT-GICAP/     01_Raw (.pcapng), 02_Pcap (.pcap), 03_Flows, 04_Manifests,
│  │                          05_Labeled_Flows, 06_Datasets, ATK_Metadata
│  └─ TII-SSRC-23/            csv/data.csv, pcap/benign, pcap/malicious
├─ 02_cicflowmeter_samples/   one sample PCAP per dataset processed by each version
│  ├─ v3/<dataset>/generated_csv/*.pcap_ISCX.csv
│  └─ v4/<dataset>/generated_csv/*.pcap_Flow.csv
├─ 03_scripts/
│  ├─ dataset_feature_inventory.py   lists CSV columns and PCAP/PCAPng header fields per dataset
│  └─ pcap_flow_enricher.py          attaches PCAP-derived columns to a CICFlowMeter v4 CSV
├─ 04_reference/
│  ├─ CICFlowMeter_Feature_Tables.xlsx   feature categories, all features, v3 vs v4 comparison, verdict
│  ├─ PCAP_Feature_Guide.html            research guide: which PCAP features to add, evidence, selection plan
│  └─ papers/                            (local only, git-ignored)
├─ 05_tools/                  CICFlowMeter v3 / v4 (local), launchers tracked – see 05_tools/README.md
└─ 06_machine_learning/       (reserved for model training)
```

PCAP files (`*.pcap`, `*.pcapng`) are git-ignored everywhere, including the sample folders.

## Datasets

| Dataset | Published CSV | Columns | CICFlowMeter version used |
|---|---|---|---|
| ASEADOS-SDN-IoT (2026) | `ASEADOS_SDN_IoT.csv` | 84 | **v3** |
| CyberFlowIoT-GICAP | NFStream flows (`03_Flows`, `05_Labeled_Flows`, `06_Datasets/*.parquet`) | 86–98 | not CICFlowMeter |
| TII-SSRC-23 (2023) | `data.csv` | 86 | **v4** |

### Evidence for the version used

| Check | ASEADOS vs v3 | ASEADOS vs v4 | TII vs v3 | TII vs v4 |
|---|---|---|---|---|
| Header names (84) | **84/84** | 36/84 | 36/84 | **84/84** |
| Same flows (Flow ID + duration + total packets/bytes) | **20/20** | 10/20 | 22,179/22,179 | **22,179/22,179** |
| All 76 feature values identical | 0/20 | 0/20 | 0/22,179 | **22,179/22,179** |

Test PCAPs: `dos-rbp1-hulk.pcap` (ASEADOS) and `bruteforce_dns.pcap` (TII).

- **ASEADOS-SDN-IoT – v3:** all 84 column names match the v3 output exactly, including v3's misspelled
  `CWE Flag Count` (v4 writes `CWR`), and all 20 flows have v3's flow boundaries (v4 matched only 10);
  feature values were not identical, which points to a slightly different v3 build.
- **TII-SSRC-23 – v4:** the first 84 columns match v4 name for name, including the corrected
  `CWR Flag Count`, and all 22,179 flows match v4's output on every one of the 76 feature values;
  none match v3. Columns 85–86 (`Traffic Type`, `Traffic Subtype`) were added by the authors.

### CICFlowMeter v3 vs v4 output on the samples

| Dataset | Sample PCAP | v3 flows | v4 flows |
|---|---|---|---|
| ASEADOS-SDN-IoT | `dos-rbp1-hulk.pcap` | 20 | 20 |
| CyberFlowIoT-GICAP | `28.NMAP_RECATK__00001_20251217232207.pcap` | 1,971 | 1,624 |
| TII-SSRC-23 | `bruteforce_dns.pcap` | 22,179 | 22,179 |

Both versions output the same 84 columns in the same order (76 statistical features); 48 names differ.
Full tables: `04_reference/CICFlowMeter_Feature_Tables.xlsx`.

## PCAP feature enrichment

Study design: raw PCAP/PCAPng of the three datasets → CICFlowMeter v4 CSV → extra columns computed
directly from the packets with Scapy (`03_scripts/pcap_flow_enricher.py`). No NetFlow/NFStream tool
and no published CSV is used as input.

- Packets are matched to v4 flows by protocol + both endpoints and the flow's time span; the clock
  offset between PCAP and CSV is detected automatically; a flow never receives more packets than
  CICFlowMeter counted for it.
- 45 columns are inserted before `Label` (84 → 129 columns); the original 84 values are unchanged.

| Group | Columns |
|---|---|
| IP header | `pcap_ttl_min/max/mean/distinct`, `pcap_ecn_ce_count`, `pcap_df_ratio`, `pcap_frag_count`, `pcap_ip_options_count` |
| TCP | `pcap_win_min/max/mean`, `pcap_zero_win_count`, `pcap_mss`, `pcap_wscale`, `pcap_retrans_count`, `pcap_urgptr_nonzero` |
| ICMP | `pcap_icmp_echo_req`, `pcap_icmp_echo_rep`, `pcap_icmp_unreach` |
| DNS | `dns_query_count`, `dns_resp_count`, `dns_nxdomain_count`, `dns_qname_len_mean`, `dns_qname_entropy_mean` |
| Payload | `payload_entropy`, `payload_printable_ratio`, `payload_nop_count`, `payload_longest_run` |
| Packet order | `pcap_first10_size_1…10` (+ forward / − backward) |
| ARP | `arp_reply_count`, `arp_gratuitous_count`, `arp_mac_distinct` |
| Time window | `win2s_src_flows`, `win60s_src_flows`, `win60s_src_dstports` (from the v4 CSV) |
| Check | `pcap_matched_pkts` |

Validation on the samples (`02_cicflowmeter_samples/v4/<dataset>/enriched_csv/`):

| Dataset | Rows kept | Original 84 values unchanged | Packets per flow = CICFlowMeter count |
|---|---|---|---|
| ASEADOS-SDN-IoT | 20/20 | 20/20 | 18/20 (2 empty flows created by CICFlowMeter) |
| CyberFlowIoT-GICAP | 1,624/1,624 | 1,624/1,624 | 1,623/1,624 |
| TII-SSRC-23 | 22,179/22,179 | 22,179/22,179 | 22,179/22,179 |

Feature selection plan, evidence from the reference papers and risks: `04_reference/PCAP_Feature_Guide.html`.

## Usage

```bash
pip install scapy pyarrow
python 03_scripts/dataset_feature_inventory.py --packets 3000 > inventory.txt
python 03_scripts/pcap_flow_enricher.py --selftest
python 03_scripts/pcap_flow_enricher.py capture.pcap capture.pcap_Flow.csv capture_Flow_enriched.csv
```

CICFlowMeter build and run instructions: [`05_tools/README.md`](05_tools/README.md).

## Licenses
- Scripts and documentation in this repository: written for the ForenXAI thesis.
- CICFlowMeter: © Canadian Institute for Cybersecurity, MIT-style license (not redistributed here).
- Datasets: property of their respective authors; not redistributed here. Sample CSVs in
  `02_cicflowmeter_samples` are CICFlowMeter output derived from one PCAP per dataset.
