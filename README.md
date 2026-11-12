# 🛡️ DeepShield
### Intelligent Network Intrusion Detection & Threat Analytics Platform

DeepShield is an AI-powered network intrusion detection and threat analytics platform that analyzes network-flow records, identifies suspicious traffic, classifies attack families, and provides anomaly detection and risk assessment.

It combines machine learning, explainable AI, a REST API, and an interactive security dashboard.

## 🚀 Key Features

- **Binary Intrusion Detection:** Classifies network traffic as BENIGN or ATTACK.
- **Multiclass Classification:** Identifies 15 traffic categories, including DDoS, PortScan, Bot, and DoS attacks.
- **Anomaly Detection:** Uses Isolation Forest to identify unusual traffic patterns.
- **Explainable AI:** Uses SHAP to investigate model predictions.
- **Threat Intelligence:** Provides preliminary risk scores and severity levels.
- **Interactive Dashboard:** Visualizes traffic distribution, attack families, anomalies, and threat alerts.
- **REST API:** Provides network-flow analysis through FastAPI.
- **Automated Reports:** Exports prediction results as PDF and CSV.
- **Automated Testing:** Includes API integration tests using pytest.

## 🧠 Machine Learning Models

| Component | Algorithm |
|---|---|
| Binary classification | XGBoost Classifier |
| Multiclass classification | XGBoost Classifier |
| Anomaly detection | Isolation Forest |
| Explainability | SHAP |

## 📊 Dataset

DeepShield uses the **CIC-IDS2017** dataset.

Dataset source: https://www.unb.ca/cic/datasets/ids-2017.html

The project processes approximately 2.83 million network-flow records across eight CSV files, with 78 numerical input features and a traffic label.

The dataset contains benign traffic and multiple attack categories.

## 🏗️ Technology Stack

- **Language:** Python
- **Machine Learning:** XGBoost, Scikit-learn
- **Data Processing:** Pandas, NumPy, PyArrow
- **Explainable AI:** SHAP
- **Backend:** FastAPI
- **Frontend:** Streamlit
- **Visualization:** Plotly
- **Reporting:** ReportLab
- **Testing:** Pytest

## 📁 Project Structure

```text
DeepShield/
│
├── api/
│   └── main.py
│
├── dashboard/
│   └── app.py
│
├── data/
│   ├── raw/
│   └── processed/
│
├── models/
│   ├── binary_xgboost.joblib
│   ├── multiclass_xgboost.joblib
│   └── calibrated_hybrid_detector.joblib
│
├── notebooks/
│
├── reports/
│   └── figures/
│
├── src/
│   ├── preprocessing.py
│   ├── train_binary.py
│   ├── train_multiclass.py
│   ├── explainability.py
│   ├── train_hybrid.py
│   └── calibrate_anomaly.py
│
├── tests/
│   └── test_api.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/DeepShield.git
cd DeepShield
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the environment

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Prepare the dataset and models

Download CIC-IDS2017 from the official source.

Follow the dataset preparation and model training scripts in `src/` to generate the processed data and model files.

Place the generated model files in `models/`.

## ▶️ Running DeepShield

### Start the FastAPI backend

```bash
uvicorn api.main:app --reload
```

API documentation:

http://127.0.0.1:8000/docs

### Start the Streamlit dashboard

Open another terminal:

```bash
streamlit run dashboard/app.py
```

Dashboard:

http://localhost:8501

Upload a supported CIC-IDS2017 network-flow CSV to analyze its traffic.

## 🧪 Testing

Run the API integration tests:

```bash
python -m pytest tests/test_api.py -v
```

The tests verify API availability, model health, and CSV prediction functionality.

## 📈 Model Evaluation

### Binary classification — random stratified test split

| Metric | Result |
|---|---:|
| Accuracy | 99.88% |
| ROC-AUC | 99.99% |

### Binary classification — held-out DDoS capture

| Metric | Result |
|---|---:|
| Accuracy | 78.72% |
| Precision | 99.75% |
| Recall | 63.08% |
| F1 Score | 77.28% |
| ROC-AUC | 91.70% |

### Multiclass classification — random stratified validation

| Metric | Result |
|---|---:|
| Accuracy | 99.30% |
| Macro F1 | 94.71% |
| Weighted F1 | 99.30% |

**Important:** Random-split performance is not representative of performance on unseen network environments. The held-out DDoS capture test provides a more challenging generalization assessment. Rare attack categories also have very limited examples.

## ⚠️ Limitations

- The current application analyzes uploaded network-flow CSV files; it does not capture live network packets.
- The models are trained and evaluated using CIC-IDS2017, so performance may differ on real-world network traffic.
- Some attack categories have very few training examples.
- Anomaly flags are not equivalent to confirmed attacks.
- Risk scores are preliminary heuristic indicators, not calibrated incident severity measurements.
- The API requires the expected 78 numerical features.

## 🔮 Future Improvements

- Live packet capture and network monitoring.
- Real-time intrusion detection.
- Improved generalization to unseen attacks.
- Advanced threat intelligence integration.
- User authentication and role-based access.
- Cloud deployment and scalable inference.
- Enhanced alerting and incident investigation.

## 👨‍💻 Author

**Esakki Raja Salaikumar**

B.Sc. Information Technology | AI/ML & Cybersecurity Enthusiast

GitHub: https://github.com/YOUR_USERNAME

---

*DeepShield — Turning network traffic into actionable security intelligence.*
