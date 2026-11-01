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
│  └─ dataset_feature_inventory.py   lists CSV columns and PCAP/PCAPng header fields per dataset
├─ 04_reference/
│  ├─ CICFlowMeter_Feature_Tables.xlsx   feature categories, all features, v3 vs v4 comparison, verdict
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

## Usage

```bash
pip install scapy pyarrow
python 03_scripts/dataset_feature_inventory.py --packets 3000 > inventory.txt
```

CICFlowMeter build and run instructions: [`05_tools/README.md`](05_tools/README.md).

## Licenses
- Scripts and documentation in this repository: written for the ForenXAI thesis.
- CICFlowMeter: © Canadian Institute for Cybersecurity, MIT-style license (not redistributed here).
- Datasets: property of their respective authors; not redistributed here. Sample CSVs in
  `02_cicflowmeter_samples` are CICFlowMeter output derived from one PCAP per dataset.
