import streamlit as st
import pandas as pd
import plotly.express as px
import requests
import json
import os

from pathlib import Path
from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


# =====================================================
# PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="DeepShield | Security Analytics",
    page_icon="🛡️",
    layout="wide"
)

API_URL = "http://127.0.0.1:8000"

BASE_DIR = Path(__file__).resolve().parent
LIVE_EVENTS_FILE = (
    BASE_DIR.parent
    / "reports"
    / "live_events"
    / "predictions.jsonl"
)

LIVE_ALERTS_FILE = (
    BASE_DIR.parent
    / "reports"
    / "live_alerts"
    / "alerts.jsonl"
)


# =====================================================
# CUSTOM CSS
# =====================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
:root {--bg:#061326;--panel:#0a1b32;--line:#15518a;--cyan:#20c9f5;--blue:#159bff;--green:#00e99a;--red:#ff5263;--purple:#a45cff;--gold:#f2bd26;}
html,body,[class*="css"]{font-family:Inter,sans-serif;}
.stApp{background:radial-gradient(ellipse at 45% -10%,rgba(0,112,220,.22),transparent 48%),linear-gradient(135deg,#061326,#07152b 58%,#041020);color:#eaf4ff;}
[data-testid="stHeader"]{background:rgba(4,15,29,.88);}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#07162a,#050f1e);border-right:1px solid #153e67;}
[data-testid="stSidebar"] *{color:#eaf4ff;}
[data-testid="stMainBlockContainer"],.stMainBlockContainer,.block-container{width:100%!important;max-width:100%!important;padding:1rem 1.25rem 2rem!important;box-sizing:border-box!important;}
h1,h2,h3{color:#f3f8ff!important;letter-spacing:-.025em;font-weight:800!important;}
[data-testid="stMetric"]{background:#0a2039;border:1px solid #1765a2;border-radius:13px;padding:12px;min-height:105px;}
[data-testid="stMetricLabel"]{color:#aec7e2!important;}
[data-testid="stMetricValue"]{color:#fff!important;font-weight:800;}
div[data-testid="stPlotlyChart"]{background:linear-gradient(145deg,#091b32,#07162a);border:1px solid #15518a;border-radius:15px;padding:7px;}
div[data-testid="stDataFrame"]{border:1px solid #15518a;border-radius:12px;overflow:hidden;}
.stButton>button,.stDownloadButton>button{border-radius:10px;border:1px solid #168dd0;background:linear-gradient(90deg,#087cc5,#1555b8);color:white;font-weight:700;}
hr{border-color:#17436d!important;}
[data-testid="stCaptionContainer"]{color:#8faac8!important;}
.ds-app-title{display:flex;align-items:center;gap:12px;padding:3px 0 8px;}
.ds-app-mark{font-size:32px;color:#27c8ff;text-shadow:0 0 18px #008cff;}
.ds-app-title b{display:block;font-size:23px;color:#fff;}
.ds-app-title small{display:block;color:#9bb8d7;font-size:12px;margin-top:2px;}
.ds-topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:10px 14px;margin-bottom:12px;border:1px solid #164d7d;border-radius:14px;background:linear-gradient(100deg,#07172b,#0b2340);}
.ds-brand{display:flex;align-items:center;gap:10px;}
.ds-shield{font-size:30px;color:#24c8ff;text-shadow:0 0 16px #078bff;}
.ds-brand-name{font-size:22px;font-weight:800;color:#fff;}
.ds-brand-sub{font-size:11px;color:#a7c0dc;}
.ds-top-status,.ds-chip,.ds-status{padding:8px 13px;border-radius:11px;border:1px solid #27557e;background:#0b2038;color:#dcecff;font-size:12px;font-weight:700;}
.ds-top-status{border-color:#087c59;color:#6affbd;background:#052b27;}
.ds-live-dot{display:inline-block;width:9px;height:9px;background:#00ed9b;border-radius:50%;margin-right:7px;box-shadow:0 0 10px #00ed9b;}
.ds-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:9px 4px 16px;}
.ds-heading h1{font-size:clamp(23px,2.1vw,32px);margin:0;}
.ds-heading p{margin:3px 0 0;color:#a9c1dc;font-size:13px;}
.ds-statuses{display:flex;gap:8px;flex-wrap:wrap;}
.ds-green{border-color:#087d5b;color:#6dffc1;}.ds-blue{border-color:#326a9c;color:#a9d8ff;}.ds-purple{border-color:#6742a5;color:#d1b5ff;}
.ds-kpi{position:relative;min-height:112px;padding:13px 12px 11px 58px;border-radius:14px;border:1px solid #176aa8;background:linear-gradient(145deg,#092b4c,#071a30);box-shadow:inset 0 1px 0 rgba(255,255,255,.04);}
.ds-kpi-icon{position:absolute;left:14px;top:17px;font-size:27px;font-weight:800;color:#27baff;text-shadow:0 0 15px currentColor;}
.ds-kpi-label{font-size:11px;color:#c1d4e8;min-height:28px;line-height:1.3;}
.ds-kpi-value{font-size:clamp(19px,1.7vw,27px);font-weight:800;color:#fff;white-space:nowrap;}
.ds-kpi-foot{font-size:10px;color:#8daecc;margin-top:3px;}
.ds-kpi.green{border-color:#00895f;background:linear-gradient(145deg,#063a34,#071d2d);}.ds-kpi.green .ds-kpi-icon{color:#00e99a;}
.ds-kpi.red{border-color:#a52b43;background:linear-gradient(145deg,#3a1527,#1b172c);}.ds-kpi.red .ds-kpi-icon{color:#ff5263;}
.ds-kpi.purple{border-color:#6640a8;background:linear-gradient(145deg,#21183f,#111a35);}.ds-kpi.purple .ds-kpi-icon{color:#b276ff;}
.ds-kpi.gold{border-color:#8c7018;background:linear-gradient(145deg,#342b10,#1d1c20);}.ds-kpi.gold .ds-kpi-icon{color:#ffd32c;}
.ds-kpi.cyan{border-color:#087c9a;background:linear-gradient(145deg,#073447,#081d31);}.ds-kpi.cyan .ds-kpi-icon{color:#00d8ef;}
.ds-section-title{font-size:17px;font-weight:800;color:#f2f7ff;padding:10px 2px 5px;}
.ds-legend-row{display:flex;align-items:center;gap:9px;flex-wrap:wrap;color:#bcd1e8;font-size:11px;padding:0 12px 10px;}
.ds-legend-row b{margin-right:10px;color:#fff;}
.dot{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:5px;}.dot.tcp{background:#159bff;}.dot.udp{background:#9855f5;}
.ds-bar-label{display:flex;justify-content:space-between;gap:8px;color:#d7e5f5;font-size:12px;margin:10px 0 4px;}
.ds-bar-label b{color:#fff;}
.ds-bar-track{height:13px;background:#203a55;border-radius:5px;overflow:hidden;margin-bottom:13px;}
.ds-bar-track div{height:100%;border-radius:5px;box-shadow:0 0 10px rgba(30,170,255,.25);}
.ds-empty-alert{min-height:245px;border:1px solid #15518a;border-radius:14px;background:linear-gradient(145deg,#081d35,#07172a);display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:18px;}
.ds-check{font-size:36px;color:#00eb9b;border:3px solid #00d98e;border-radius:50%;width:52px;height:52px;line-height:45px;margin-bottom:14px;}
.ds-empty-alert b{font-size:16px;color:#f3f8ff;}
.ds-empty-alert p{font-size:12px;color:#a9bfd8;margin:8px 0 0;}
@media(max-width:900px){.ds-kpi{padding-left:48px;}.ds-kpi-icon{left:10px;font-size:22px;}.ds-statuses{gap:5px;}}

/* Reference layout refinements: wider navigation, stronger typography and roomier panels */
section[data-testid="stSidebar"]{width:238px!important;min-width:238px!important;}
section[data-testid="stSidebar"] [data-testid="stSidebarContent"]{padding-top:1rem!important;}
section[data-testid="stSidebar"] [role="radiogroup"] label{font-size:14px!important;padding:9px 7px!important;}
.ds-topbar{padding:15px 20px!important;min-height:76px!important;}
.ds-brand-name{font-size:27px!important;}
.ds-brand-sub{font-size:13px!important;}
.ds-top-status,.ds-chip,.ds-status{font-size:14px!important;padding:10px 16px!important;}
.ds-heading{padding:15px 5px 20px!important;}
.ds-heading h1{font-size:clamp(27px,2.3vw,36px)!important;}
.ds-heading p{font-size:15px!important;}
.ds-kpi{min-height:132px!important;padding:17px 14px 14px 66px!important;}
.ds-kpi-icon{font-size:32px!important;left:17px!important;top:21px!important;}
.ds-kpi-label{font-size:13px!important;min-height:32px!important;}
.ds-kpi-value{font-size:clamp(23px,1.9vw,31px)!important;}
.ds-kpi-foot{font-size:12px!important;}
.ds-section-title{font-size:19px!important;padding:14px 3px 8px!important;}
.ds-legend-row,.ds-bar-label{font-size:13px!important;}
.ds-bar-track{height:16px!important;}
.ds-empty-alert{min-height:285px!important;}
.ds-empty-alert b{font-size:18px!important;}
.ds-empty-alert p{font-size:14px!important;}
div[data-testid="stPlotlyChart"]{padding:10px!important;}
[data-testid="stDataFrame"]{font-size:13px!important;}
@media(max-width:900px){
 section[data-testid="stSidebar"]{width:205px!important;min-width:205px!important;}
 .ds-kpi{min-height:112px!important;padding-left:52px!important;}
 .ds-kpi-icon{left:12px!important;font-size:24px!important;}
}

</style>
""", unsafe_allow_html=True)


# =====================================================
# LIVE DATA FUNCTIONS
# =====================================================

def load_live_events():

    if not LIVE_EVENTS_FILE.exists():
        return pd.DataFrame()

    events = []

    try:
        with open(
            LIVE_EVENTS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    except OSError:
        return pd.DataFrame()

    if not events:
        return pd.DataFrame()

    df = pd.DataFrame(events)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            errors="coerce"
        )

    if "attack_probability" in df.columns:
        df["attack_probability"] = pd.to_numeric(
            df["attack_probability"],
            errors="coerce"
        ).fillna(0).clip(0, 1)

    if "total_packets" in df.columns:
        df["total_packets"] = pd.to_numeric(
            df["total_packets"],
            errors="coerce"
        ).fillna(0)

    if "classification" in df.columns:
        df["prediction"] = (
            df["classification"].astype(str).str.strip().str.upper()
        )
    elif "prediction" not in df.columns:
        df["prediction"] = "UNKNOWN"
    else:
        df["prediction"] = df["prediction"].astype(str).str.strip().str.upper()

    return df



def get_live_statistics(df):

    if df.empty:
        return {
            "total_events": 0,
            "benign_events": 0,
            "attack_events": 0,
            "attack_percentage": 0.0,
            "average_attack_probability": 0.0
        }

    total = len(df)

    # Read the correct classification column
    classification = (
        df["classification"]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    benign = int((classification == "BENIGN").sum())
    attacks = int((classification == "ATTACK").sum())

    attack_percentage = (
        attacks / total * 100 if total else 0
    )

    average_probability = (
        df["attack_probability"].mean()
        if "attack_probability" in df.columns
        else 0.0
    )

    return {
        "total_events": total,
        "benign_events": benign,
        "attack_events": attacks,
        "attack_percentage": attack_percentage,
        "average_attack_probability": average_probability
    }

# =====================================================
# PDF REPORT GENERATOR
# =====================================================

def generate_pdf_report(result, predictions_df):

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontSize=23,
            textColor=colors.HexColor("#12345A"),
            alignment=TA_CENTER,
            spaceAfter=8
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#155E9A"),
            spaceBefore=14,
            spaceAfter=8
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallText",
            parent=styles["Normal"],
            fontSize=8,
            leading=11
        )
    )

    story = []

    summary = result.get("summary", {})
    total = int(result.get("total_records", 0))

    benign = int(summary.get("benign_records", 0))
    attacks = int(summary.get("attack_records", 0))
    anomalies = int(summary.get("anomalous_records", 0))

    story.append(
        Paragraph("DEEPSHIELD", styles["ReportTitle"])
    )

    story.append(
        Paragraph(
            "Network Intrusion Detection & Threat Analytics Report",
            styles["Heading2"]
        )
    )

    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%d %B %Y, %I:%M %p')}",
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph("1. Executive Summary", styles["SectionHeading"])
    )

    executive_text = (
        f"DeepShield analyzed <b>{total:,}</b> network-flow records. "
        f"The system classified <b>{benign:,}</b> records as BENIGN "
        f"and <b>{attacks:,}</b> records as ATTACK. "
        f"The anomaly detector flagged <b>{anomalies:,}</b> records."
    )

    story.append(
        Paragraph(executive_text, styles["Normal"])
    )

    story.append(
        Paragraph("2. Traffic Analysis", styles["SectionHeading"])
    )

    traffic_data = [
        ["Metric", "Records", "Percentage"],
        ["Total Records", f"{total:,}", "100%"],
        [
            "Benign Traffic",
            f"{benign:,}",
            f"{benign / total * 100:.2f}%" if total else "0%"
        ],
        [
            "Detected Attacks",
            f"{attacks:,}",
            f"{attacks / total * 100:.2f}%" if total else "0%"
        ],
        [
            "Anomaly Flags",
            f"{anomalies:,}",
            f"{anomalies / total * 100:.2f}%" if total else "0%"
        ]
    ]

    traffic_table = Table(
        traffic_data,
        colWidths=[65 * mm, 45 * mm, 45 * mm]
    )

    traffic_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#173B63")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#EAF1F8")])
        ])
    )

    story.append(traffic_table)

    story.append(
        Paragraph("3. Attack Family Analysis", styles["SectionHeading"])
    )

    families = summary.get("attack_families", {})

    if families:

        family_data = [
            ["Attack Family", "Detected Records"]
        ]

        for family, count in sorted(
            families.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            family_data.append([
                str(family),
                f"{int(count):,}"
            ])

        family_table = Table(
            family_data,
            colWidths=[90 * mm, 65 * mm]
        )

        family_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0),
                 colors.HexColor("#173B63")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 7),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#EAF1F8")])
            ])
        )

        story.append(family_table)

    else:
        story.append(
            Paragraph("No attack families were reported.", styles["Normal"])
        )

    story.append(
        Paragraph("4. Threat Severity Assessment", styles["SectionHeading"])
    )

    severity_data = [
        ["Severity", "Records"]
    ]

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:

        count = int(
            (predictions_df["severity"] == severity).sum()
        )

        severity_data.append([
            severity,
            f"{count:,}"
        ])

    severity_table = Table(
        severity_data,
        colWidths=[90 * mm, 65 * mm]
    )

    severity_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0),
             colors.HexColor("#173B63")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 7),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#EAF1F8")])
        ])
    )

    story.append(severity_table)

    story.append(
        Paragraph("5. Highest-Risk Traffic Records", styles["SectionHeading"])
    )

    priority_df = predictions_df[
        predictions_df["severity"].isin(["CRITICAL", "HIGH"])
    ].sort_values(
        "risk_score",
        ascending=False
    ).head(15)

    if not priority_df.empty:

        threat_data = [[
            "Row",
            "Prediction",
            "Attack Family",
            "Risk Score",
            "Severity"
        ]]

        for _, row in priority_df.iterrows():

            threat_data.append([
                str(row.get("row_number", "")),
                str(row.get("prediction", "")),
                str(row.get("attack_family", "N/A")),
                f"{float(row.get('risk_score', 0)):.2f}",
                str(row.get("severity", ""))
            ])

        threat_table = Table(
            threat_data,
            colWidths=[
                18 * mm,
                30 * mm,
                48 * mm,
                28 * mm,
                35 * mm
            ],
            repeatRows=1
        )

        threat_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0),
                 colors.HexColor("#173B63")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#EAF1F8")])
            ])
        )

        story.append(threat_table)

    else:
        story.append(
            Paragraph(
                "No high or critical risk records were identified.",
                styles["Normal"]
            )
        )

    story.append(
        Paragraph("6. Methodology & Limitations", styles["SectionHeading"])
    )

    methodology = """
    <b>Detection:</b> The system uses a supervised XGBoost classifier
    for BENIGN / ATTACK classification and a multiclass model for
    attack-family identification.<br/><br/>

    <b>Anomaly detection:</b> Isolation Forest provides a separate
    anomaly signal. An anomaly flag does not automatically mean
    a confirmed attack.<br/><br/>

    <b>Risk scoring:</b> The dashboard calculates a preliminary
    heuristic score using attack probability and anomaly status.
    It is not a calibrated real-world incident severity score.<br/><br/>

    <b>Input:</b> This report summarizes uploaded network-flow CSV
    records. It does not represent live packet capture or continuous
    network monitoring.<br/><br/>

    <b>Evaluation:</b> Performance on a sampled dataset from a known
    capture should not be interpreted as proof of generalization
    to unseen networks or attack families.
    """

    story.append(
        Paragraph(methodology, styles["SmallText"])
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Generated by DeepShield AI Security Platform",
            styles["Normal"]
        )
    )

    def add_footer(canvas, document):

        canvas.saveState()

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)

        canvas.drawString(
            18 * mm,
            10 * mm,
            "DeepShield | Security Analytics"
        )

        canvas.drawRightString(
            A4[0] - 18 * mm,
            10 * mm,
            f"Page {document.page}"
        )

        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=add_footer,
        onLaterPages=add_footer
    )

    buffer.seek(0)

    return buffer.getvalue()

# =====================================================
# =====================================================
# HEADER
# =====================================================

# The Live SOC view renders its own single reference-style brand header.


# SIDEBAR
# =====================================================

st.sidebar.markdown("## 🛡️ DeepShield")
st.sidebar.caption("SECURITY CONTROL PANEL")

dashboard_mode = st.sidebar.radio(
    "NAVIGATION",
    [
        "Live SOC Monitoring",
        "Alerts & Incidents",
        "Event Logs",
        "Analytics",
        "Models & Performance",
        "Settings",
        "CSV Traffic Analysis"
    ],
    index=0
)

st.sidebar.divider()

st.sidebar.markdown("### API Connection")

try:

    health = requests.get(
        f"{API_URL}/health",
        timeout=3
    )

    if health.status_code == 200:
        st.sidebar.success("Detection API: Connected")
    else:
        st.sidebar.warning("Detection API: Unhealthy")

except requests.exceptions.RequestException:

    st.sidebar.error("Detection API: Disconnected")

st.sidebar.divider()

st.sidebar.caption(
    "DeepShield AI Security Platform"
)


# =====================================================
# =====================================================
# LIVE SOC MONITORING
# =====================================================

if dashboard_mode == "Live SOC Monitoring":

    @st.fragment(run_every="2s")
    def live_soc_dashboard():

        df = load_live_events()

        # Brand banner inspired by the approved DeepShield SOC reference.
        st.markdown(
            """
            <div class="ds-topbar">
              <div class="ds-brand">
                <div class="ds-shield">⬡</div>
                <div><div class="ds-brand-name">DeepShield</div>
                <div class="ds-brand-sub">AI-Powered Network Intrusion Detection</div></div>
              </div>
              <div class="ds-top-status"><span class="ds-live-dot"></span> Live Monitoring</div>
              <div class="ds-chip">◉ Wi-Fi · Local capture</div>
              <div class="ds-chip">XGBoost · Binary IDS</div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown(
            """
            <div class="ds-heading">
              <div><h1>Security Operations Center (SOC)</h1>
              <p>Real-time network traffic analysis, threat detection and intelligent alerts</p></div>
              <div class="ds-statuses">
                <span class="ds-status ds-green">⬡ IDS: Active</span>
                <span class="ds-status ds-blue">▦ Model: XGBoost</span>
                <span class="ds-status ds-purple">⚡ Response: Monitoring</span>
              </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        if df.empty:
            st.warning("No live prediction events found. Start the capture engine to populate the SOC.")
            st.code("python -m capture.live_detection_engine", language="powershell")
            return

        if "classification" not in df.columns:
            df["classification"] = df.get("prediction", "UNKNOWN")
        df["classification"] = df["classification"].astype(str).str.upper().str.strip()
        df["prediction"] = df["classification"]

        for column, default in [
            ("protocol", "UNKNOWN"),
            ("source_ip", "Unknown"),
            ("destination_ip", "Unknown"),
            ("destination_port", pd.NA),
            ("total_packets", 0),
            ("prediction_stage", "UNKNOWN"),
            ("attack_probability", 0.0)
        ]:
            if column not in df.columns:
                df[column] = default

        df["protocol"] = df["protocol"].fillna("UNKNOWN").astype(str).str.upper()
        df["destination_port"] = pd.to_numeric(df["destination_port"], errors="coerce")
        df["total_packets"] = pd.to_numeric(df["total_packets"], errors="coerce").fillna(0)
        df["attack_probability"] = pd.to_numeric(df["attack_probability"], errors="coerce").fillna(0).clip(0, 1)
        df["prediction_stage"] = df["prediction_stage"].fillna("UNKNOWN").astype(str).str.upper()

        stats = get_live_statistics(df)
        total = len(df)
        benign = stats["benign_events"]
        attacks = stats["attack_events"]
        avg_prob = stats["average_attack_probability"] * 100
        provisional = int((df["prediction_stage"] == "PROVISIONAL").sum())
        final_count = int((df["prediction_stage"] == "FINAL").sum())
        unique_destinations = int(df["destination_ip"].nunique())
        protocol_counts = df["protocol"].value_counts()
        tcp_count = int(protocol_counts.get("TCP", 0))
        udp_count = int(protocol_counts.get("UDP", 0))
        tcp_pct = tcp_count / total * 100 if total else 0
        udp_pct = udp_count / total * 100 if total else 0

        # Six KPI cards. Values are sourced from captured event records.
        kpis = st.columns(6)
        cards = [
            ("◈", "Total Events", f"{total:,}", "Recorded predictions", "blue"),
            ("⬡", "Benign Traffic", f"{benign:,}", f"{benign / total * 100:.2f}% of events" if total else "—", "green"),
            ("◎", "Attack Traffic", f"{attacks:,}", f"{attacks / total * 100:.2f}% of events" if total else "—", "red"),
            ("∿", "Attack Probability (Avg)", f"{avg_prob:.2f}%", "Mean model probability", "purple"),
            ("⌘", "Unique Destinations", f"{unique_destinations:,}", "Observed destination IPs", "gold"),
            ("▤", "Packets Observed", f"{int(df['total_packets'].sum()):,}", "Across prediction events", "cyan")
        ]
        for col, (symbol, label, value, foot, tone) in zip(kpis, cards):
            with col:
                st.markdown(
                    f'<div class="ds-kpi {tone}"><div class="ds-kpi-icon">{symbol}</div>'
                    f'<div class="ds-kpi-label">{label}</div><div class="ds-kpi-value">{value}</div>'
                    f'<div class="ds-kpi-foot">{foot}</div></div>',
                    unsafe_allow_html=True
                )

        st.markdown('<div class="ds-grid-two">', unsafe_allow_html=True)
        left, right = st.columns([0.9, 1.2], gap="medium")

        with left:
            st.markdown('<div class="ds-section-title">▤ &nbsp; Traffic Distribution</div>', unsafe_allow_html=True)
            protocol_df = pd.DataFrame({
                "Protocol": ["TCP", "UDP", "Other"],
                "Events": [tcp_count, udp_count, max(total - tcp_count - udp_count, 0)]
            })
            fig = px.pie(
                protocol_df, names="Protocol", values="Events", hole=0.66,
                color="Protocol",
                color_discrete_map={"TCP": "#159bff", "UDP": "#9855f5", "Other": "#19d6c2"}
            )
            fig.update_traces(textinfo="none", marker=dict(line=dict(color="#07172b", width=3)))
            fig.update_layout(
                height=285, margin=dict(l=10,r=10,t=10,b=10),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e7f2ff"), legend=dict(orientation="v", x=1.0, y=0.5),
                annotations=[dict(text=f"<b>{total:,}</b><br>Events", x=.42, y=.5, showarrow=False,
                                  font=dict(size=19, color="#f5f9ff"))]
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
            st.markdown(
                f'<div class="ds-legend-row"><span><i class="dot tcp"></i> TCP</span><b>{tcp_pct:.1f}% ({tcp_count:,})</b>'
                f'<span><i class="dot udp"></i> UDP</span><b>{udp_pct:.1f}% ({udp_count:,})</b></div>',
                unsafe_allow_html=True
            )

        with right:
            st.markdown('<div class="ds-section-title">⌁ &nbsp; Traffic Trends (Last 15 Minutes)</div>', unsafe_allow_html=True)
            trend_df = df.dropna(subset=["timestamp"]).copy() if "timestamp" in df.columns else pd.DataFrame()
            if not trend_df.empty:
                trend_df["minute"] = trend_df["timestamp"].dt.floor("min")
                trend = trend_df.groupby(["minute", "classification"], as_index=False).agg(
                    packets=("total_packets", "sum")
                )
                fig = px.line(
                    trend, x="minute", y="packets", color="classification",
                    color_discrete_map={"BENIGN": "#16e6a0", "ATTACK": "#ff4c63"},
                    markers=True
                )
                fig.update_layout(
                    height=285, margin=dict(l=12,r=12,t=15,b=10),
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#c8d9ef"), xaxis_title="", yaxis_title="Packets recorded",
                    legend=dict(orientation="h", y=1.12, x=0.55),
                    xaxis=dict(gridcolor="rgba(110,160,210,.15)"),
                    yaxis=dict(gridcolor="rgba(110,160,210,.15)")
                )
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
                st.caption("Trend aggregates packet counts attached to prediction events by minute; it is not a packet-rate sensor.")
            else:
                st.info("Waiting for timestamped events.")

        st.markdown('</div>', unsafe_allow_html=True)

        left, right = st.columns([1, 1], gap="medium")
        with left:
            st.markdown('<div class="ds-section-title">∿ &nbsp; Attack Probability Timeline</div>', unsafe_allow_html=True)
            timeline = df.dropna(subset=["timestamp"]).sort_values("timestamp").copy() if "timestamp" in df.columns else pd.DataFrame()
            if not timeline.empty:
                timeline["probability_pct"] = timeline["attack_probability"] * 100
                fig = px.line(
                    timeline, x="timestamp", y="probability_pct", color="prediction_stage",
                    color_discrete_map={"PROVISIONAL": "#a65bff", "FINAL": "#22c8ff", "UNKNOWN": "#7b91ad"}
                )
                fig.update_layout(
                    height=245, margin=dict(l=10,r=10,t=10,b=10),
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#c8d9ef"), xaxis_title="", yaxis_title="Probability (%)",
                    yaxis=dict(range=[0, max(1, float(timeline["probability_pct"].max()) * 1.25)],
                               gridcolor="rgba(110,160,210,.15)"),
                    xaxis=dict(gridcolor="rgba(110,160,210,.15)"),
                    legend=dict(orientation="h", y=1.12)
                )
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
            else:
                st.info("No timestamped probabilities available.")

        with right:
            st.markdown('<div class="ds-section-title">⬟ &nbsp; Protocol & Port Analysis</div>', unsafe_allow_html=True)
            proto_cols = st.columns(2)
            with proto_cols[0]:
                st.markdown("**Protocol Usage**")
                for protocol, count, color in [("TCP", tcp_count, "#159bff"), ("UDP", udp_count, "#9855f5")]:
                    pct = count / total * 100 if total else 0
                    st.markdown(
                        f'<div class="ds-bar-label"><span>{protocol}</span><b>{pct:.1f}%</b></div>'
                        f'<div class="ds-bar-track"><div style="width:{pct:.2f}%;background:{color}"></div></div>',
                        unsafe_allow_html=True
                    )
            with proto_cols[1]:
                st.markdown("**Top Destination Ports**")
                ports = df["destination_port"].dropna().astype(int).value_counts().head(5)
                if ports.empty:
                    st.caption("No port data available.")
                else:
                    for port, count in ports.items():
                        pct = count / total * 100 if total else 0
                        label = {443:"443 (HTTPS)",53:"53 (DNS)",80:"80 (HTTP)"}.get(int(port), str(port))
                        st.markdown(
                            f'<div class="ds-bar-label"><span>{label}</span><b>{pct:.1f}%</b></div>'
                            f'<div class="ds-bar-track"><div style="width:{pct:.2f}%;background:#25baf5"></div></div>',
                            unsafe_allow_html=True
                        )

        left, right = st.columns([1.55, 0.85], gap="medium")
        with left:
            st.markdown('<div class="ds-section-title">▣ &nbsp; Recent Network Predictions</div>', unsafe_allow_html=True)
            recent = df.sort_values("timestamp", ascending=False) if "timestamp" in df.columns else df.iloc[::-1]
            table = recent.head(12).copy()
            if "timestamp" in table.columns:
                table["Time"] = table["timestamp"].dt.strftime("%H:%M:%S")
            # Format probability before renaming source columns. This avoids
            # looking up "attack_probability" after it has become "Attack Prob.".
            if "attack_probability" in table.columns:
                table["Attack Prob."] = table["attack_probability"].map(
                    lambda value: f"{float(value):.4f}" if pd.notna(value) else "—"
                )
            table = table.rename(columns={
                "source_ip":"Source IP",
                "destination_ip":"Destination IP",
                "destination_port":"Port",
                "protocol":"Protocol",
                "total_packets":"Packets",
                "classification":"Prediction"
            })
            show_cols = [
                "Time", "Source IP", "Destination IP", "Port",
                "Protocol", "Packets", "Attack Prob.", "Prediction"
            ]
            show_cols = [column for column in show_cols if column in table.columns]
            st.dataframe(
                table[show_cols],
                use_container_width=True,
                hide_index=True,
                height=285
            )

        with right:
            st.markdown('<div class="ds-section-title">♟ &nbsp; Recent Alerts & Incidents</div>', unsafe_allow_html=True)
            incidents = df[df["classification"] == "ATTACK"].copy()
            if incidents.empty:
                st.markdown(
                    '<div class="ds-empty-alert"><div class="ds-check">✓</div>'
                    '<b>No attack events detected.</b><p>All displayed events are currently classified as BENIGN by the model.</p></div>',
                    unsafe_allow_html=True
                )
            else:
                cols = [x for x in ["timestamp","source_ip","destination_ip","destination_port","protocol","attack_probability"] if x in incidents.columns]
                st.dataframe(incidents[cols].sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True, height=245)
                st.error(f"{len(incidents):,} attack prediction events recorded. Investigate these model classifications.")

        st.caption(
            f"Live refresh: 2 seconds · {provisional:,} provisional and {final_count:,} final prediction events. "
            "Counts are prediction events, not unique flows. Throughput and active-flow counts are not available from the current event schema."
        )

    live_soc_dashboard()
    st.stop()

# ALERTS & INCIDENTS
# =====================================================

elif dashboard_mode == "Alerts & Incidents":

    st.title("🚨 Alerts & Incidents")
    st.caption(
        "Review security alerts written by DeepShield's live detection engine. "
        "Only saved ATTACK classifications appear here."
    )

    alert_records = []
    if LIVE_ALERTS_FILE.exists():
        try:
            with LIVE_ALERTS_FILE.open("r", encoding="utf-8") as alert_file:
                for line in alert_file:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if isinstance(record, dict):
                            alert_records.append(record)
                    except json.JSONDecodeError:
                        continue

        except OSError as error:
            st.error(f"Could not read alert history: {error}")

    alerts_df = pd.DataFrame(alert_records)

    if not alerts_df.empty:
        if "timestamp" in alerts_df.columns:
            alerts_df["timestamp"] = pd.to_datetime(
                alerts_df["timestamp"], errors="coerce"
            )
        if "attack_probability" in alerts_df.columns:
            alerts_df["attack_probability"] = pd.to_numeric(
                alerts_df["attack_probability"], errors="coerce"
            ).fillna(0).clip(0, 1)
        if "total_packets" in alerts_df.columns:
            alerts_df["total_packets"] = pd.to_numeric(
                alerts_df["total_packets"], errors="coerce"
            ).fillna(0).astype(int)
        for column in ["severity", "classification", "protocol"]:
            if column in alerts_df.columns:
                alerts_df[column] = alerts_df[column].astype(str).str.upper()

    total_alerts = len(alerts_df)
    critical_count = int((alerts_df["severity"] == "CRITICAL").sum()) if "severity" in alerts_df else 0
    high_count = int((alerts_df["severity"] == "HIGH").sum()) if "severity" in alerts_df else 0
    medium_count = int((alerts_df["severity"] == "MEDIUM").sum()) if "severity" in alerts_df else 0
    low_count = int((alerts_df["severity"] == "LOW").sum()) if "severity" in alerts_df else 0

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Alerts", f"{total_alerts:,}")
    m2.metric("Critical", f"{critical_count:,}")
    m3.metric("High", f"{high_count:,}")
    m4.metric("Medium", f"{medium_count:,}")
    m5.metric("Low", f"{low_count:,}")

    st.divider()
    st.subheader("Alert Investigation")

    if alerts_df.empty:
        st.success("No saved security alerts found.")
        st.info(
            "The live engine writes an alert only when its binary classifier "
            "returns ATTACK. BENIGN prediction events are stored separately "
            "in reports/live_events/predictions.jsonl."
        )
    else:
        filter_col, search_col = st.columns([1, 2])
        severity_options = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        selected_severity = filter_col.selectbox(
            "Filter by severity", severity_options, key="alert_severity_filter"
        )
        search_text = search_col.text_input(
            "Search IP, protocol or alert ID", key="alert_search"
        )

        filtered = alerts_df.copy()
        if selected_severity != "All" and "severity" in filtered.columns:
            filtered = filtered[filtered["severity"] == selected_severity]
        if search_text.strip():
            term = search_text.strip().lower()
            searchable = [
                column for column in [
                    "alert_id", "source_ip", "destination_ip", "protocol"
                ] if column in filtered.columns
            ]
            if searchable:
                mask = filtered[searchable].astype(str).apply(
                    lambda column: column.str.lower().str.contains(term, regex=False)
                ).any(axis=1)
                filtered = filtered[mask]

        display = filtered.copy()
        if "timestamp" in display.columns:
            display = display.sort_values("timestamp", ascending=False, na_position="last")
            display["timestamp"] = display["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("Unknown")
        if "attack_probability" in display.columns:
            display["attack_probability"] = display["attack_probability"].map(
                lambda value: f"{value:.4f}"
            )

        display_columns = [
            "alert_id", "timestamp", "severity", "source_ip",
            "destination_ip", "destination_port", "protocol",
            "total_packets", "attack_probability", "classification"
        ]
        display_columns = [column for column in display_columns if column in display.columns]
        st.dataframe(
            display[display_columns],
            use_container_width=True,
            hide_index=True,
            height=420
        )
        st.caption(f"Showing {len(filtered):,} of {total_alerts:,} saved alert records.")

        csv_bytes = filtered.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Export filtered alerts (CSV)",
            data=csv_bytes,
            file_name="deepshield_alerts.csv",
            mime="text/csv"
        )

    st.caption(
        "Severity is assigned from the model's attack probability using the "
        "thresholds configured in AlertManager. It is a triage label, not a "
        "validated real-world incident severity assessment."
    )

# EVENT LOGS
# =====================================================

elif dashboard_mode == "Event Logs":

    st.title("📜 Event Logs")
    st.caption("Browse prediction events recorded by the live detection engine.")

    event_df = load_live_events()
    if event_df.empty:
        st.info("No prediction events have been saved yet.")
    else:
        search_col, type_col = st.columns([2, 1])
        event_search = search_col.text_input(
            "Search source IP, destination IP or protocol", key="event_log_search"
        )
        stage_filter = type_col.selectbox(
            "Prediction stage", ["All", "PROVISIONAL", "FINAL"],
            key="event_stage_filter"
        )
        view = event_df.copy()
        if stage_filter != "All" and "prediction_stage" in view.columns:
            view = view[view["prediction_stage"].astype(str).str.upper() == stage_filter]
        if event_search.strip():
            term = event_search.strip().lower()
            searchable = [
                column for column in ["source_ip", "destination_ip", "protocol"]
                if column in view.columns
            ]
            if searchable:
                mask = view[searchable].astype(str).apply(
                    lambda column: column.str.lower().str.contains(term, regex=False)
                ).any(axis=1)
                view = view[mask]
        if "timestamp" in view.columns:
            view = view.sort_values("timestamp", ascending=False)
            view["timestamp"] = view["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("Unknown")
        cols = [
            "timestamp", "prediction_stage", "classification", "attack_probability",
            "source_ip", "destination_ip", "destination_port", "protocol", "total_packets"
        ]
        cols = [column for column in cols if column in view.columns]
        st.dataframe(view[cols].head(1000), use_container_width=True, hide_index=True, height=520)
        st.caption(f"Showing up to 1,000 of {len(view):,} matching prediction events.")

# ANALYTICS
# =====================================================

elif dashboard_mode == "Analytics":

    st.title("📊 Security Analytics")
    st.caption("Summary statistics calculated from saved live prediction events.")
    event_df = load_live_events()
    if event_df.empty:
        st.info("No live events are available for analytics yet.")
    else:
        stats = get_live_statistics(event_df)
        a, b, d, e = st.columns(4)
        a.metric("Prediction Events", f"{stats['total_events']:,}")
        b.metric("Benign", f"{stats['benign_events']:,}")
        d.metric("Attack", f"{stats['attack_events']:,}")
        e.metric("Average Attack Probability", f"{stats['average_attack_probability']:.2%}")

        chart_df = event_df.copy()
        if "timestamp" in chart_df.columns:
            chart_df["minute"] = chart_df["timestamp"].dt.floor("min")
            trend = chart_df.groupby(["minute", "prediction"], dropna=False).size().reset_index(name="events")
            if not trend.empty:
                fig = px.line(
                    trend, x="minute", y="events", color="prediction",
                    title="Prediction Events Over Time", markers=True,
                    color_discrete_map={"BENIGN": "#20c9f5", "ATTACK": "#ff5263"}
                )
                fig.update_layout(
                    template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=10,r=10,t=45,b=10)
                )
                st.plotly_chart(fig, use_container_width=True)
        if "protocol" in chart_df.columns:
            protocol_counts = chart_df["protocol"].astype(str).str.upper().value_counts().rename_axis("Protocol").reset_index(name="Events")
            fig = px.bar(
                protocol_counts, x="Protocol", y="Events", color="Protocol",
                title="Protocol Distribution"
            )
            fig.update_layout(
                template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)", showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)
        st.caption("These charts describe saved prediction events, not raw packet throughput or unique network flows.")

# MODELS & PERFORMANCE
# =====================================================

elif dashboard_mode == "Models & Performance":

    st.title("🧠 Models & Performance")
    st.caption(
        "Measured evaluation results, model availability and feature importance "
        "from the reports saved with this project."
    )

    model_dir = BASE_DIR.parent / "models"
    model_files = [
        ("Binary XGBoost", "binary_xgboost.joblib"),
        ("Multiclass XGBoost", "multiclass_xgboost.joblib"),
        ("Calibrated Hybrid Detector", "calibrated_hybrid_detector.joblib")
    ]

    st.subheader("Model artifacts")
    model_columns = st.columns(3)
    for column, (label, filename) in zip(model_columns, model_files):
        if (model_dir / filename).exists():
            column.success(f"{label}\n\nAvailable")
        else:
            column.warning(f"{label}\n\nNot found locally")

    report_dir = BASE_DIR.parent / "reports"

    def read_evaluation_report(filename):
        path = report_dir / filename
        if not path.exists():
            return None
        try:
            return pd.read_csv(path)
        except (OSError, pd.errors.ParserError, UnicodeDecodeError) as error:
            st.warning(f"Could not read {filename}: {error}")
            return None

    calibrated_df = read_evaluation_report("calibrated_anomaly_results.csv")
    ablation_df = read_evaluation_report("feature_ablation_results.csv")
    hybrid_df = read_evaluation_report("hybrid_evaluation.csv")
    importance_df = read_evaluation_report("binary_feature_importance.csv")
    ablation_importance_df = read_evaluation_report("ablation_feature_importance.csv")

    st.divider()
    st.subheader("Primary detector — held-out capture evaluation")

    if calibrated_df is not None and not calibrated_df.empty:
        primary_rows = calibrated_df[
            calibrated_df["System"].astype(str).str.strip() == "Supervised XGBoost"
        ]
        if not primary_rows.empty:
            primary = primary_rows.iloc[0]
            metric_cols = st.columns(5)
            metric_specs = [
                ("Accuracy", "Accuracy"),
                ("Precision", "Precision"),
                ("Recall", "Recall"),
                ("F1 score", "F1 Score"),
                ("False positive rate", "False Positive Rate")
            ]
            for col, (label, field) in zip(metric_cols, metric_specs):
                value = pd.to_numeric(pd.Series([primary[field]]), errors="coerce").iloc[0]
                col.metric(label, f"{value:.2%}" if pd.notna(value) else "N/A")
            st.caption(
                "These figures come from the saved calibrated-anomaly evaluation: "
                "the Friday DDoS capture was held out from training. They are dataset-specific "
                "results, not a guarantee of performance on other networks."
            )
        else:
            st.info("The saved calibrated evaluation does not contain a Supervised XGBoost row.")
    else:
        st.info("calibrated_anomaly_results.csv is not available; primary detector metrics cannot be displayed.")

    st.divider()
    st.subheader("Detector comparison")

    if calibrated_df is not None and not calibrated_df.empty:
        comparison = calibrated_df.copy()
        metric_columns = ["Accuracy", "Precision", "Recall", "F1 Score", "False Positive Rate"]
        for field in metric_columns:
            if field in comparison.columns:
                comparison[field] = pd.to_numeric(comparison[field], errors="coerce")
        available_metrics = [field for field in metric_columns if field in comparison.columns]
        if available_metrics:
            display_comparison = comparison.copy()
            for field in available_metrics:
                display_comparison[field] = display_comparison[field].map(
                    lambda value: f"{value:.2%}" if pd.notna(value) else "N/A"
                )
            st.dataframe(display_comparison, use_container_width=True, hide_index=True)

            chart_metric = st.selectbox(
                "Compare metric",
                ["F1 Score", "Recall", "Precision", "Accuracy", "False Positive Rate"],
                key="model_comparison_metric"
            )
            if chart_metric in comparison.columns:
                chart = px.bar(
                    comparison,
                    x="System",
                    y=chart_metric,
                    title=f"{chart_metric} by detector",
                    text=comparison[chart_metric].map(
                        lambda value: f"{value:.1%}" if pd.notna(value) else ""
                    )
                )
                chart.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    yaxis=dict(tickformat=".0%", range=[0, 1])
                )
                st.plotly_chart(chart, use_container_width=True)
    else:
        st.info("No detector comparison table is available.")

    st.warning(
        "The calibrated Isolation Forest and hybrid results are shown separately. "
        "The Isolation Forest's 1% calibration false-positive target was measured on its "
        "benign calibration sample; its false-positive rate on the held-out Friday capture "
        "is different. The hybrid OR rule increases false positives, so XGBoost remains "
        "the primary supervised detector."
    )

    st.divider()
    st.subheader("Feature ablation — held-out capture")

    if ablation_df is not None and not ablation_df.empty:
        ablation_display = ablation_df.copy()
        percent_fields = ["Accuracy", "Precision", "Recall", "F1 Score", "ROC AUC"]
        for field in percent_fields:
            if field in ablation_display.columns:
                ablation_display[field] = pd.to_numeric(
                    ablation_display[field], errors="coerce"
                ).map(lambda value: f"{value:.2%}" if pd.notna(value) else "N/A")
        st.dataframe(ablation_display, use_container_width=True, hide_index=True)
        st.caption(
            "Removing the four most important features produced only a small change "
            "in this held-out experiment; feature reduction did not solve the "
            "generalization gap."
        )
    else:
        st.info("feature_ablation_results.csv is not available.")

    st.divider()
    st.subheader("Top binary-model features")

    if importance_df is not None and not importance_df.empty:
        importance_df["Importance"] = pd.to_numeric(
            importance_df["Importance"], errors="coerce"
        )
        top_features = importance_df.dropna(
            subset=["Importance"]
        ).nlargest(15, "Importance").sort_values("Importance")
        feature_chart = px.bar(
            top_features,
            x="Importance",
            y="Feature",
            orientation="h",
            title="Top 15 features by saved model importance"
        )
        feature_chart.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            yaxis_title=""
        )
        st.plotly_chart(feature_chart, use_container_width=True)
        with st.expander("View complete feature-importance table"):
            st.dataframe(
                importance_df.sort_values("Importance", ascending=False),
                use_container_width=True,
                hide_index=True
            )
    else:
        st.info("binary_feature_importance.csv is not available.")

    if ablation_importance_df is not None and not ablation_importance_df.empty:
        with st.expander("View feature importance from ablation experiment"):
            st.dataframe(
                ablation_importance_df,
                use_container_width=True,
                hide_index=True
            )

    st.divider()
    st.subheader("Download evaluation reports")
    downloadable_reports = [
        "calibrated_anomaly_results.csv",
        "hybrid_evaluation.csv",
        "feature_ablation_results.csv",
        "binary_feature_importance.csv",
        "ablation_feature_importance.csv"
    ]
    download_columns = st.columns(2)
    for index, filename in enumerate(downloadable_reports):
        path = report_dir / filename
        if path.exists():
            try:
                download_columns[index % 2].download_button(
                    label=f"⬇️ {filename}",
                    data=path.read_bytes(),
                    file_name=filename,
                    mime="text/csv",
                    key=f"download_{filename}",
                    use_container_width=True
                )
            except OSError as error:
                st.warning(f"Could not prepare {filename}: {error}")

    st.info(
        "Confusion-matrix counts and multiclass per-class metrics are not included "
        "in the CSV reports currently available to this page, so they are not displayed. "
        "Random-split validation scores are intentionally not presented as unseen-network "
        "performance."
    )

# SETTINGS
# =====================================================

elif dashboard_mode == "Settings":

    st.title("⚙️ Settings")
    st.caption("Read-only view of current DeepShield configuration.")
    st.write("API endpoint:", API_URL)
    st.write("Prediction event file:", str(LIVE_EVENTS_FILE))
    st.write("Alert history file:", str(LIVE_ALERTS_FILE))
    st.write("Live dashboard refresh: every 2 seconds")
    st.write("Live prediction threshold: 0.50 (configured in live predictor)")
    st.info("Settings are currently informational. Changing these values does not reconfigure the detection engine.")

# CSV TRAFFIC ANALYSIS
# =====================================================

elif dashboard_mode == "CSV Traffic Analysis":

    st.header("📂 Network Traffic Analysis")

    st.caption(
        "Upload a CIC-IDS2017-compatible network-flow CSV "
        "to analyze traffic using DeepShield AI models."
    )

    st.sidebar.markdown("### Supported Input")
    st.sidebar.write("CIC-IDS2017 network-flow CSV")
    st.sidebar.write("Maximum upload: 50,000 rows")

    uploaded_file = st.file_uploader(
        "Upload your network traffic CSV",
        type=["csv"]
    )

    if uploaded_file is not None:

        st.info(
            f"Selected file: {uploaded_file.name}"
        )

        if st.button(
            "🚀 Analyze Network Traffic",
            type="primary"
        ):

            try:

                with st.spinner(
                    "Analyzing network traffic with AI models..."
                ):

                    response = requests.post(
                        f"{API_URL}/predict",
                        files={
                            "file": (
                                uploaded_file.name,
                                uploaded_file.getvalue(),
                                "text/csv"
                            )
                        },
                        timeout=300
                    )

                    if response.status_code != 200:

                        st.error(
                            f"API Error {response.status_code}: "
                            f"{response.text}"
                        )

                    else:

                        st.session_state["analysis_result"] = (
                            response.json()
                        )

                        st.session_state["analysis_filename"] = (
                            uploaded_file.name
                        )

                        st.success(
                            "Network traffic analysis completed!"
                        )

            except requests.exceptions.ConnectionError:

                st.error(
                    "Cannot connect to DeepShield API. "
                    "Start FastAPI in another terminal."
                )

            except requests.exceptions.RequestException as error:

                st.error(
                    f"Request failed: {error}"
                )

            except ValueError:

                st.error(
                    "The API returned an invalid JSON response."
                )

    # =================================================
    # RESULTS
    # =================================================

    if "analysis_result" in st.session_state:

        result = st.session_state["analysis_result"]

        summary = result["summary"]

        total = int(result["total_records"])
        benign = int(summary["benign_records"])
        attacks = int(summary["attack_records"])
        anomalies = int(summary["anomalous_records"])

        predictions_df = pd.DataFrame(
            result["predictions"]
        )

        if predictions_df.empty:

            st.warning(
                "No prediction records were returned."
            )

            st.stop()

        # =============================================
        # TRAFFIC OVERVIEW
        # =============================================

        st.divider()

        st.header("📊 Threat Analysis Overview")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Total Records",
            f"{total:,}"
        )

        col2.metric(
            "Benign Traffic",
            f"{benign:,}"
        )

        col3.metric(
            "Detected Attacks",
            f"{attacks:,}"
        )

        col4.metric(
            "Anomaly Flags",
            f"{anomalies:,}"
        )

        # =============================================
        # TRAFFIC ANALYTICS
        # =============================================

        st.divider()

        st.header("📈 Traffic Analytics")

        left, right = st.columns(2)

        traffic_df = pd.DataFrame({
            "Traffic Type": [
                "Benign",
                "Attack"
            ],
            "Records": [
                benign,
                attacks
            ]
        })

        with left:

            st.subheader("Traffic Distribution")

            fig = px.pie(
                traffic_df,
                names="Traffic Type",
                values="Records",
                hole=0.55,
                title="Benign vs Attack Traffic"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        with right:

            st.subheader("Attack Family Distribution")

            family_data = summary.get(
                "attack_families",
                {}
            )

            if family_data:

                family_df = pd.DataFrame(
                    list(family_data.items()),
                    columns=[
                        "Attack Family",
                        "Records"
                    ]
                )

                fig = px.bar(
                    family_df,
                    x="Attack Family",
                    y="Records",
                    title="Detected Attack Families"
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True
                )

            else:

                st.info(
                    "No attack families detected."
                )

        # =============================================
        # ANOMALY DETECTION
        # =============================================

        st.divider()

        st.header("🔍 Anomaly Detection")

        anomaly_percentage = (
            anomalies / total * 100 if total else 0
        )

        st.metric(
            "Anomalous Traffic Percentage",
            f"{anomaly_percentage:.2f}%"
        )

        st.progress(
            min(anomaly_percentage / 100, 1.0)
        )

        # =============================================
        # THREAT INTELLIGENCE
        # =============================================

        st.divider()

        st.header(
            "🚨 Threat Intelligence & Risk Assessment"
        )

        required_columns = [
            "row_number",
            "prediction",
            "attack_probability",
            "anomaly_detected",
            "attack_family"
        ]

        missing_columns = [
            column
            for column in required_columns
            if column not in predictions_df.columns
        ]

        if missing_columns:

            st.error(
                "API response is missing columns: "
                + ", ".join(missing_columns)
            )

            st.stop()

        predictions_df["attack_probability"] = (
            pd.to_numeric(
                predictions_df["attack_probability"],
                errors="coerce"
            )
            .fillna(0)
            .clip(0, 1)
        )

        predictions_df["anomaly_detected"] = (
            predictions_df["anomaly_detected"]
            .fillna(False)
            .astype(bool)
        )

        # Preliminary heuristic score
        predictions_df["risk_score"] = (
            predictions_df["attack_probability"] * 80
            + predictions_df["anomaly_detected"].astype(int) * 20
        ).clip(0, 100).round(2)

        def get_severity(score):

            if score >= 90:
                return "CRITICAL"

            elif score >= 70:
                return "HIGH"

            elif score >= 40:
                return "MEDIUM"

            return "LOW"

        predictions_df["severity"] = (
            predictions_df["risk_score"].apply(get_severity)
        )

        severity_counts = (
            predictions_df["severity"]
            .value_counts()
            .reindex(
                [
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW"
                ],
                fill_value=0
            )
        )

        st.subheader(
            "Threat Severity Overview"
        )

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "🔴 Critical",
            int(severity_counts["CRITICAL"])
        )

        c2.metric(
            "🟠 High",
            int(severity_counts["HIGH"])
        )

        c3.metric(
            "🟡 Medium",
            int(severity_counts["MEDIUM"])
        )

        c4.metric(
            "🟢 Low",
            int(severity_counts["LOW"])
        )

        severity_df = (
            severity_counts
            .rename_axis("Severity")
            .reset_index(name="Records")
        )

        fig = px.bar(
            severity_df,
            x="Severity",
            y="Records",
            color="Severity",
            title="Threat Severity Distribution",
            category_orders={
                "Severity": [
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW"
                ]
            }
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

        # =============================================
        # PRIORITY ALERTS
        # =============================================

        st.subheader(
            "⚠️ Priority Threat Alerts"
        )

        priority_df = predictions_df[
            predictions_df["severity"].isin(
                ["CRITICAL", "HIGH"]
            )
        ].sort_values(
            "risk_score",
            ascending=False
        )

        if not priority_df.empty:

            st.dataframe(
                priority_df[
                    [
                        "row_number",
                        "prediction",
                        "attack_probability",
                        "attack_family",
                        "anomaly_detected",
                        "risk_score",
                        "severity"
                    ]
                ],
                use_container_width=True,
                hide_index=True
            )

        else:

            st.success(
                "No high or critical risk records found."
            )

        # =============================================
        # DETAILED PREDICTIONS
        # =============================================

        st.divider()

        st.header(
            "📋 Detailed Prediction Results"
        )

        st.dataframe(
            predictions_df,
            use_container_width=True,
            hide_index=True
        )

        # =============================================
        # AUTOMATED REPORT GENERATION
        # =============================================

        st.divider()

        st.header(
            "📑 Automated Security Reporting"
        )

        st.write(
            "Generate a security report containing traffic statistics, "
            "attack families, threat severity and priority alerts."
        )

        report_col1, report_col2 = st.columns(2)

        with report_col1:

            st.subheader("📄 PDF Security Report")

            try:

                pdf_data = generate_pdf_report(
                    result,
                    predictions_df
                )

                st.download_button(
                    label="⬇️ Download PDF Report",
                    data=pdf_data,
                    file_name="DeepShield_Security_Report.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )

            except Exception as error:

                st.error(
                    f"PDF generation failed: {error}"
                )

        with report_col2:

            st.subheader("📊 CSV Prediction Report")

            csv_data = predictions_df.to_csv(
                index=False
            ).encode("utf-8")

            st.download_button(
                label="⬇️ Download CSV Report",
                data=csv_data,
                file_name="DeepShield_Threat_Report.csv",
                mime="text/csv",
                use_container_width=True
            )

        # =============================================
        # FOOTER
        # =============================================

        st.divider()

        st.success(
            "DeepShield network traffic analysis completed successfully."
        )

        st.caption(
            "Risk scores are preliminary heuristic indicators, "
            "not calibrated real-world incident severity. "
            "Anomaly flags are separate from confirmed attack predictions."
        )

    else:

        st.info(
            "Upload a network traffic CSV file to begin analysis."
        )

        st.markdown("""
        ### 🛡️ DeepShield Capabilities

        - AI-powered intrusion detection
        - Binary BENIGN / ATTACK classification
        - Multiclass attack family identification
        - Isolation Forest anomaly detection
        - Threat severity and risk assessment
        - Automated PDF security reports
        - CSV prediction exports
        """)
