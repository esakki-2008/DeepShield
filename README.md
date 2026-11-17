# DeepShield

### Intelligent Network Intrusion Detection and Threat Analytics Platform

DeepShield is an educational cybersecurity and machine-learning project that analyzes network traffic to identify potentially malicious activity. It combines a **live network-monitoring workflow** with **historical CSV traffic analysis**, using supervised machine learning, anomaly scoring, and a Streamlit-based SOC-style dashboard.

The project is built around the CIC-IDS2017 network-flow dataset and includes an experimental packet-to-flow pipeline for monitoring authorized local network traffic.

<p align="center">
  <strong>Live Network Monitoring · ML-Based Intrusion Detection · Threat Analytics · Explainability</strong>
</p>

---

## Table of contents

- [Project overview](#project-overview)
- [Key capabilities](#key-capabilities)
- [System architecture](#system-architecture)
- [Machine-learning models](#machine-learning-models)
- [Dataset](#dataset)
- [Evaluation results](#evaluation-results)
- [Technology stack](#technology-stack)
- [Repository structure](#repository-structure)
- [Getting started](#getting-started)
- [Running DeepShield](#running-deepshield)
- [Testing](#testing)
- [Screenshots](#screenshots)
- [Limitations and responsible use](#limitations-and-responsible-use)
- [Roadmap](#roadmap)
- [Author](#author)

---

## Project overview

Traditional network monitoring tools can produce large volumes of traffic data that are difficult to inspect manually. DeepShield explores how machine learning can help analyze network-flow behaviour, highlight suspicious activity, and present useful context for security triage.

DeepShield provides two workflows:

| Workflow | Description |
|---|---|
| **Live SOC Monitoring** | Captures authorized local IPv4 TCP/UDP traffic, aggregates packets into bidirectional flows, extracts model features, and produces live prediction events and potential-threat alerts. |
| **CSV Traffic Analysis** | Accepts historical network-flow CSV files and provides binary classification, attack-family predictions, anomaly signals, visual summaries, and downloadable reports. |

The live workflow is experimental. Its packet-derived features are approximations of the CIC-IDS2017 training features and have not been proven equivalent to CICFlowMeter output.

## Key capabilities

### Live network monitoring

- Packet capture through **Scapy** and Npcap on Windows.
- Bidirectional IPv4 TCP/UDP flow aggregation.
- Idle-timeout and maximum-lifetime flow handling.
- Provisional predictions for active flows and final predictions for eligible expired flows.
- JSON Lines event storage for dashboard consumption.
- Potential-threat alerts with severity labels and supporting connection details.
- Live traffic and prediction summaries in the dashboard.

### Historical CSV analysis

- Upload compatible network-flow CSV files containing the model's 78 numeric input features.
- Binary classification: `BENIGN` or `ATTACK`.
- Multiclass attack-family prediction for records classified as attacks.
- Isolation Forest anomaly scoring as a separate signal.
- Traffic distribution and attack-family visualizations.
- CSV export and PDF analysis reports.

### Model analysis and explainability

- XGBoost feature-based intrusion classification.
- SHAP-based explanation workflow.
- Random-split and held-out-capture evaluation.
- Feature-ablation experiments.
- Anomaly-threshold calibration experiments.

---

## System architecture

### Live monitoring pipeline

```text
 Authorized local network interface
                |
         Scapy packet capture
                |
       IPv4 TCP/UDP processing
                |
     Bidirectional flow generator
                |
       78-feature extraction
                |
       Binary XGBoost model
                |
       +--------+---------+
       |                  |
  Alert manager       Event store
       |                  |
       +--------+---------+
                |
        Streamlit SOC dashboard
```

### Historical CSV pipeline

```text
Network-flow CSV
       |
Streamlit upload
       |
FastAPI prediction endpoint
       |
Feature validation and ordering
       |
+------+--------------------+
|                           |
Binary XGBoost         Isolation Forest
|                           |
Attack-family model     Anomaly signal
|                           |
+-------------+-------------+
              |
     Results, charts and reports
```

---

## Machine-learning models

| Component | Algorithm | Role |
|---|---|---|
| Binary intrusion detector | XGBoost Classifier | Classifies traffic as `BENIGN` or `ATTACK`. |
| Attack-family classifier | XGBoost Classifier | Predicts a label from the attack classes represented during training. |
| Anomaly detector | Isolation Forest | Provides an independent anomaly signal. |
| Explainability | SHAP | Helps inspect feature contributions to selected model outputs. |

The binary XGBoost classifier is the primary supervised detector. Isolation Forest is a separate anomaly signal; an anomaly flag does not establish that traffic is malicious. The dashboard's severity/risk labels are preliminary triage heuristics, not calibrated incident-severity measurements.

---

## Dataset

DeepShield was developed using the **CIC-IDS2017** dataset.

- Official dataset page: [Canadian Institute for Cybersecurity — CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- Approximately **2.83 million flow records** across eight CSV files.
- **78 numeric flow features** and a traffic label.
- Includes benign traffic and multiple attack families.

The raw and processed datasets are excluded from this repository. Download the dataset from the official source and prepare it locally when running the preprocessing or model-training workflows. A fresh clone may also require locally generated model artifacts, depending on which artifacts are available in the repository.

---

## Evaluation results

The metrics below come from different experimental setups. They must not be combined into one overall accuracy claim.

### Binary model — random stratified test split

| Metric | Result |
|---|---:|
| Accuracy | **99.88%** |
| ROC-AUC | **99.99%** |

### Binary model — held-out Friday DDoS capture

| Metric | Result |
|---|---:|
| Accuracy | **78.72%** |
| Precision | **99.75%** |
| Recall | **63.08%** |
| F1 score | **77.28%** |
| ROC-AUC | **91.70%** |
| False-positive rate | **0.21%** |

### Multiclass model — random stratified validation

| Metric | Result |
|---|---:|
| Accuracy | **99.30%** |
| Macro F1 | **94.71%** |
| Weighted F1 | **99.30%** |

### How to interpret these results

- Random-split metrics are substantially more optimistic than the held-out-capture result.
- CIC-IDS2017 attack families are unevenly distributed across capture files. A closed-set classifier cannot reliably name an attack family that was absent from its training data.
- Some classes have very small validation support, so their individual scores are not reliable estimates of generalization.
- On the held-out Friday DDoS capture, the binary model achieved high precision but missed a meaningful share of attacks.
- A successful live capture-to-dashboard demonstration confirms that the software pipeline runs; it does **not** prove real-world detection accuracy.
- Live flow features are currently approximations. Exact CICFlowMeter parity has not been established.

---

## Technology stack

| Area | Technologies |
|---|---|
| Language | Python |
| Machine learning | XGBoost, scikit-learn |
| Data processing | Pandas, NumPy, PyArrow |
| Explainable AI | SHAP |
| Packet capture | Scapy, Npcap (Windows) |
| API | FastAPI, Uvicorn |
| Dashboard | Streamlit |
| Visualization | Plotly |
| PDF reporting | ReportLab |
| Testing | Pytest, HTTPX / Requests |

---

## Repository structure

```text
DeepShield/
├── api/
│   └── main.py
├── capture/
│   ├── packet_capture.py
│   ├── flow_generator.py
│   ├── feature_extractor.py
│   ├── live_predictor.py
│   ├── live_detection_engine.py
│   ├── alert_manager.py
│   └── event_store.py
├── dashboard/
│   ├── app.py
│   └── live_data.py
├── data/
│   ├── raw/                 # downloaded locally; not committed
│   └── processed/           # generated locally; not committed
├── models/                  # trained model artifacts
├── notebooks/
├── reports/                 # generated reports and runtime data
├── src/                     # preprocessing, training and evaluation
├── tests/
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Getting started

### Prerequisites

- Windows 10/11 or a compatible Python environment.
- Python version compatible with the pinned dependencies in `requirements.txt`.
- Git.
- Npcap for Windows live packet capture.
- Administrator privileges may be required for packet capture.
- Trained model artifacts in the `models/` directory for prediction workflows.

### 1. Clone the repository

```powershell
git clone https://github.com/esakki-2008/DeepShield.git
cd DeepShield
```

### 2. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script activation, use an approved execution policy for your environment or activate the virtual environment using another Python shell.

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Install Npcap for live monitoring on Windows

Install Npcap from [npcap.com](https://npcap.com/). Follow its official installation instructions. Packet capture may require starting the terminal with Administrator privileges.

### 5. Configure the network interface

The live engine currently uses the interface index configured in:

```text
capture/live_detection_engine.py
```

Find the correct interface index on your computer with:

```powershell
python -c "from scapy.all import conf; conf.ifaces.show()"
```

Update `INTERFACE_INDEX` in the live detection engine before starting capture. Interface indexes can differ between computers.

### 6. Prepare datasets and models when needed

The raw and processed CIC-IDS2017 files are not included in the repository.

1. Download CIC-IDS2017 from the [official dataset page](https://www.unb.ca/cic/datasets/ids-2017.html).
2. Extract the relevant CSV files into `data/raw/`.
3. Run the appropriate preprocessing and training scripts in `src/`.
4. Confirm the model files required by the API and live predictor are present in `models/`.

Do not download datasets or model binaries from untrusted sources.

---

## Running DeepShield

Open separate terminals from the project root. Activate `.venv` in each terminal.

### A. Start the Streamlit dashboard

```powershell
streamlit run dashboard/app.py
```

Open: [http://localhost:8501](http://localhost:8501)

### B. Start the FastAPI backend for CSV analysis

```powershell
uvicorn api.main:app --reload
```

- API root: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- Health check: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- Interactive API documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

The CSV prediction endpoint accepts compatible flow-feature CSV files. The current API limit is **50,000 rows per request**.

### C. Start live network monitoring

Run this in a separate terminal with the required capture permissions:

```powershell
python capture/live_detection_engine.py
```

Stop monitoring with `Ctrl + C`.

The live engine captures IPv4 TCP/UDP traffic on the configured interface. The current flow generator does not provide full protocol coverage or deep packet inspection. Some extracted features are approximations, so treat live predictions as experimental signals that require investigation.

### D. Run CSV traffic analysis

1. Start the FastAPI backend.
2. Open the Streamlit dashboard.
3. Select the CSV traffic-analysis workflow.
4. Upload a compatible network-flow CSV containing the required 78 numeric feature columns.
5. Review predictions, anomaly signals, charts, and available exports.

---

## Testing

### API integration tests

Start the FastAPI server in one terminal, then run:

```powershell
python -m pytest tests/test_api.py -v
```

The API prediction test expects the local sample file:

```text
data/processed/api_test_ddos_5000.csv
```

Generate or prepare this sample locally if it is not present.

### Flow and feature checks

```powershell
python capture/test_flows.py
python capture/test_feature_extractor.py
```

These scripts exercise flow aggregation and basic feature-extraction checks. They do not establish exact CICFlowMeter compatibility or real-world model accuracy.

---

## Screenshots

The following screenshots show the DeepShield interface and project workflows.

### Dashboard and traffic analytics

![DeepShield dashboard](docs/screenshots/Screenshot%202026-11-13%20170243.png)

![Traffic analytics](docs/screenshots/Screenshot%202026-11-13%20170251.png)

![Dashboard view](docs/screenshots/Screenshot%202026-11-13%20170303.png)

### Detection and reporting views

![Detection view](docs/screenshots/Screenshot%202026-11-13%20180427.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214523.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214547.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214608.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214638.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214705.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214725.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214738.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214751.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214804.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214850.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214908.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214921.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214941.png)

![DeepShield interface](docs/screenshots/Screenshot%202026-11-13%20214954.png)

---

## Limitations and responsible use

- **Authorized monitoring only:** capture traffic only on devices and networks you own or are explicitly permitted to monitor.
- **Research and portfolio use:** DeepShield is not a production-certified IDS and is not a replacement for an enterprise IDS, firewall, SIEM, or incident-response process.
- **Dataset limitations:** models were trained using CIC-IDS2017. Real network environments and attack distributions may differ substantially.
- **Live feature approximation:** the packet-derived feature extractor has not been validated for exact CICFlowMeter parity.
- **Prediction uncertainty:** a `BENIGN` result does not guarantee traffic is safe. An `ATTACK` result is a model prediction, not a confirmed incident.
- **Anomaly and severity signals:** anomaly flags and heuristic severity labels are intended to support triage, not make final security decisions.
- **Event-based dashboard counts:** live metrics are derived from prediction events. Provisional and final predictions can refer to the same flow, so event counts should not be interpreted as unique-flow counts or network throughput.

---

## Roadmap

- [ ] Validate live feature calculations against CICFlowMeter reference output.
- [ ] Expand protocol and IPv6 handling.
- [ ] Improve generalization across unseen captures and attack families.
- [ ] Add stronger automated tests for flow lifecycle, alert deduplication, and event consistency.
- [ ] Improve interface discovery and capture configuration.
- [ ] Add authentication, access control, and deployment hardening.
- [ ] Improve operational metrics and long-running capture resource management.

---

## Author

**Esakki Raja Salaikumar**  
B.Sc. Information Technology | AI/ML & Cybersecurity

- GitHub: [@esakki-2008](https://github.com/esakki-2008)
- Project repository: [DeepShield](https://github.com/esakki-2008/DeepShield)

---

<p align="center">
  <strong>DeepShield</strong><br>
  Turning network traffic into actionable security intelligence.
</p>
