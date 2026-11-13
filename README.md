# 🛡️ DeepShield

### AI-Powered Network Intrusion Detection & Threat Analytics Platform

DeepShield is a machine-learning-based network intrusion detection and threat analytics project. It analyzes network-flow records, classifies traffic, surfaces anomaly signals, explains selected model predictions, and presents monitoring results through a Security Operations Center (SOC) dashboard.

The platform supports **two analysis modes**:

- **Live SOC Monitoring:** captures authorized IPv4 TCP/UDP traffic from a selected local network interface, builds bidirectional flows, generates provisional and final predictions, and streams events to the dashboard.
- **CSV Traffic Analysis:** uploads historical network-flow CSV data for batch prediction, visualization, and report export.

> **Research/portfolio project:** DeepShield is not a production-certified IDS. Its models were developed with CIC-IDS2017, and live feature extraction is an approximation of the training dataset's flow features. Validate carefully before using it for security decisions.

---

## ✨ Features

### Live SOC Monitoring
- Local packet capture using Scapy.
- Bidirectional TCP/UDP flow aggregation.
- Configurable flow timeouts and maximum flow lifetime.
- Provisional predictions while flows are active.
- Final predictions when eligible flows expire.
- JSONL event persistence for dashboard updates.
- Potential-threat alerts with triage severity labels.
- Live dashboard refresh with traffic and prediction summaries.

### CSV Traffic Analysis
- Upload network-flow CSV files with the expected 78 numeric model features.
- Binary classification: `BENIGN` or `ATTACK`.
- Multiclass attack-family classification for records classified as attacks.
- Isolation Forest anomaly signal.
- Traffic summaries, charts, and downloadable CSV/PDF reports.

### Explainability and evaluation
- SHAP-based feature explanations.
- Binary and multiclass model evaluation.
- Held-out capture experiments to examine generalization.
- False-negative, feature-ablation, and anomaly-calibration analysis.

---

## 🧠 Models

| Component | Method | Purpose |
|---|---|---|
| Binary IDS | XGBoost Classifier | BENIGN vs ATTACK |
| Attack-family classifier | XGBoost Classifier | Predicts one of the trained traffic labels |
| Anomaly signal | Isolation Forest | Flags unusual feature patterns |
| Explainability | SHAP | Explains selected model outputs |

The supervised XGBoost binary classifier is the primary attack detector. Isolation Forest is presented as a separate anomaly signal; an anomaly flag is not proof of an attack. Threat severity is a preliminary triage heuristic, not a calibrated incident-severity measurement.

---

## 📊 Dataset

DeepShield was developed using the **CIC-IDS2017** dataset.

- Official dataset: https://www.unb.ca/cic/datasets/ids-2017.html
- Approximately 2.83 million flow records across eight CSV files.
- 78 numerical input features and a traffic label.
- Includes benign traffic and multiple attack families.

The raw and processed datasets are not included in this repository. Download the dataset from the official source and prepare it locally before training or running workflows that require the original data.

---

## 📈 Model evaluation

The following results come from different evaluation setups. They should not be interpreted as a single real-world accuracy estimate.

### Binary model — random stratified test split

| Metric | Result |
|---|---:|
| Accuracy | 99.88% |
| ROC-AUC | 99.99% |

### Binary model — held-out Friday DDoS capture

| Metric | Result |
|---|---:|
| Accuracy | 78.72% |
| Precision | 99.75% |
| Recall | 63.08% |
| F1 score | 77.28% |
| ROC-AUC | 91.70% |
| False-positive rate | 0.21% |

### Multiclass model — random stratified validation

| Metric | Result |
|---|---:|
| Accuracy | 99.30% |
| Macro F1 | 94.71% |
| Weighted F1 | 99.30% |

**Evaluation caveats**
- Random-split results are optimistic compared with tests on an unseen capture.
- Attack families are unevenly distributed across CIC-IDS2017 capture files. A family absent from training cannot be reliably identified by a closed-set classifier.
- Some attack classes have very small validation support; their individual scores are not reliable estimates.
- The held-out DDoS results show that the binary model misses a substantial share of attacks despite high precision.
- Live monitoring events demonstrate that the capture-to-dashboard pipeline runs; they do not establish real-world detection accuracy. Observed local traffic during the recorded demo was classified as benign.
- Live flow features are approximated from captured packets. They have not been validated for exact CICFlowMeter parity.

---

## 🏗️ Architecture

```text
                    ┌─────────────────────────┐
                    │  Local authorized NIC   │
                    └────────────┬────────────┘
                                 │
                         Scapy packet capture
                                 │
                         Bidirectional flows
                                 │
                         Feature extraction
                                 │
                         XGBoost prediction
                                 │
                    ┌────────────┴────────────┐
                    │                         │
              Alert manager             Event store
                    │                         │
                    └────────────┬────────────┘
                                 │
                         Streamlit SOC UI


Historical CSV ──> FastAPI /predict ──> ML models ──> Dashboard & reports
```

---

## 🧰 Technology stack

- **Language:** Python
- **Machine learning:** XGBoost, scikit-learn
- **Data processing:** Pandas, NumPy, PyArrow
- **Explainable AI:** SHAP
- **Packet capture:** Scapy (Windows capture typically requires Npcap)
- **Backend:** FastAPI, Uvicorn
- **Dashboard:** Streamlit
- **Visualization:** Plotly
- **Reporting:** ReportLab
- **Testing:** Pytest

---

## 📁 Project structure

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
├── reports/                 # generated locally; runtime logs ignored
├── src/                     # preprocessing, training, evaluation
├── tests/
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ⚙️ Installation

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

If PowerShell blocks activation, use a terminal with an allowed script policy or activate the environment using your preferred Python shell.

### 3. Install Python dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Install packet-capture support (Windows, live mode)

Install **Npcap** from https://npcap.com/ if it is not already installed. Packet capture may require running PowerShell as Administrator.

The live engine currently selects a network interface using `INTERFACE_INDEX` in `capture/live_detection_engine.py`. Check and change that value to match the interface on your computer before starting capture.

### 5. Prepare data and model artifacts

1. Download CIC-IDS2017 from the official dataset page.
2. Extract the CSV files into `data/raw/`.
3. Run the relevant preprocessing and training scripts in `src/`.
4. Ensure the model artifacts expected by the API and live predictor exist in `models/`.

Model binaries and datasets may not be present in a fresh clone. They must be generated locally or obtained from a trusted project release.

---

## ▶️ Run DeepShield

### Start the FastAPI backend

From the project root:

```powershell
uvicorn api.main:app --reload
```

- API health: http://127.0.0.1:8000/health
- Interactive API documentation: http://127.0.0.1:8000/docs

### Start the Streamlit dashboard

Open a second terminal, activate the same virtual environment, then run:

```powershell
streamlit run dashboard/app.py
```

Dashboard: http://localhost:8501

### Start live network monitoring

Use a third terminal. Only capture traffic on a device and network you own or are explicitly authorized to monitor.

```powershell
python capture/live_detection_engine.py
```

Stop monitoring with `Ctrl + C`.

The live engine currently captures IPv4 traffic and builds TCP/UDP flows. It is not a full packet inspection system; IPv6 and other protocols are not handled by the current flow generator. The live feature extractor uses approximations for some flow statistics, so live predictions should be treated as experimental.

### Analyze a CSV file

Select **CSV Traffic Analysis** in the dashboard and upload a compatible network-flow CSV containing the expected 78 numeric feature columns. The API enforces an upload limit; consult `api/main.py` for the current configured limit.

---

## 🧪 Tests

Run the API integration tests:

```powershell
python -m pytest tests/test_api.py -v
```

Run the capture and feature validation scripts when available:

```powershell
python capture/test_flows.py
python capture/test_feature_extractor.py
```

Some tests require the trained model artifacts and/or Scapy dependencies to be installed.

---

## 📸 DeepShield – Project Screenshots

Explore the DeepShield dashboard, network monitoring, threat detection, model evaluation, and reporting interface.

<details>
<summary><b>View all 18 screenshots</b></summary>

### Screenshot 1
![Screenshot 1](docs/screenshots/Screenshot%202026-11-13%20170243.png)

### Screenshot 2
![Screenshot 2](docs/screenshots/Screenshot%202026-11-13%20170251.png)

### Screenshot 3
![Screenshot 3](docs/screenshots/Screenshot%202026-11-13%20170303.png)

### Screenshot 4
![Screenshot 4](docs/screenshots/Screenshot%202026-11-13%20180427.png)

### Screenshot 5
![Screenshot 5](docs/screenshots/Screenshot%202026-11-13%20214523.png)

### Screenshot 6
![Screenshot 6](docs/screenshots/Screenshot%202026-11-13%20214547.png)

### Screenshot 7
![Screenshot 7](docs/screenshots/Screenshot%202026-11-13%20214608.png)

### Screenshot 8
![Screenshot 8](docs/screenshots/Screenshot%202026-11-13%20214638.png)

### Screenshot 9
![Screenshot 9](docs/screenshots/Screenshot%202026-11-13%20214705.png)

### Screenshot 10
![Screenshot 10](docs/screenshots/Screenshot%202026-11-13%20214725.png)

### Screenshot 11
![Screenshot 11](docs/screenshots/Screenshot%202026-11-13%20214738.png)

### Screenshot 12
![Screenshot 12](docs/screenshots/Screenshot%202026-11-13%20214751.png)

### Screenshot 13
![Screenshot 13](docs/screenshots/Screenshot%202026-11-13%20214804.png)

### Screenshot 14
![Screenshot 14](docs/screenshots/Screenshot%202026-11-13%20214850.png)

### Screenshot 15
![Screenshot 15](docs/screenshots/Screenshot%202026-11-13%20214908.png)

### Screenshot 16
![Screenshot 16](docs/screenshots/Screenshot%202026-11-13%20214921.png)

### Screenshot 17
![Screenshot 17](docs/screenshots/Screenshot%202026-11-13%20214941.png)

### Screenshot 18
![Screenshot 18](docs/screenshots/Screenshot%202026-11-13%20214954.png)

</details>

## 🔐 Responsible use and limitations

- Only capture traffic on networks and devices for which you have explicit authorization.
- DeepShield is an educational/research portfolio project, not a replacement for a production IDS, firewall, SIEM, or incident-response process.
- Models were trained on CIC-IDS2017. Network environments, traffic distributions, and attack techniques differ in practice.
- The live feature extractor is approximate and has not been proven equivalent to CICFlowMeter.
- A BENIGN prediction does not guarantee that traffic is safe. An ATTACK prediction is a model output that requires investigation.
- Anomaly flags, heuristic risk scores, and alert severity labels are supporting triage signals, not confirmed incidents.
- Do not use the dashboard's packet totals as network throughput: they aggregate packet counts attached to prediction events and can include repeated provisional snapshots of the same flow.

---

## 🔮 Future improvements

- Configurable interface discovery and capture settings.
- Validate live feature calculations against CICFlowMeter.
- Improve generalization across unseen capture files and attack families.
- Add stronger automated tests for live flow lifecycle and event consistency.
- Improve event deduplication and distinguish flow-level metrics from prediction-event metrics.
- Add authentication, access control, and deployment hardening.

---

## 👨‍💻 Author

**Esakki Raja Salaikumar**  
B.Sc. Information Technology | AI/ML & Cybersecurity

GitHub: https://github.com/esakki-2008

---

*DeepShield — Turning network traffic into actionable security intelligence.*
