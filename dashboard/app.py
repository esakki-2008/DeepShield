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


# =====================================================
# CUSTOM CSS
# =====================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
:root { --bg:#061326; --panel:#0b1c33; --line:#174a78; --cyan:#19c7f7; --blue:#238cff; --green:#00e58b; --red:#ff5268; --purple:#a66cff; --text:#e8f3ff; --muted:#91aac6; }
html, body, [class*="css"] { font-family:'Inter',sans-serif; }
.stApp { background:radial-gradient(ellipse at 50% -20%,rgba(0,139,255,.20),transparent 45%),linear-gradient(135deg,#061326 0%,#07152a 55%,#061020 100%); color:var(--text); }
[data-testid="stHeader"] { background:rgba(5,15,29,.82); }
[data-testid="stSidebar"] { background:linear-gradient(180deg,#08172b 0%,#061020 100%); border-right:1px solid #12385d; }
[data-testid="stSidebar"] * { color:var(--text); }
/* Force Streamlit's main canvas to use the full browser width */
[data-testid="stMainBlockContainer"],
.stMainBlockContainer,
.block-container {
  width: 100% !important;
  max-width: 100% !important;
  padding-left: 2rem !important;
  padding-right: 2rem !important;
  padding-top: 1.25rem !important;
  padding-bottom: 2rem !important;
  margin-left: 0 !important;
  margin-right: 0 !important;
  box-sizing: border-box !important;
}
@media (max-width: 900px) {
  [data-testid="stMainBlockContainer"],
  .stMainBlockContainer,
  .block-container {
    padding-left: 1rem !important;
    padding-right: 1rem !important;
  }
}
h1,h2,h3 { color:#f3f8ff !important; letter-spacing:-.03em; font-weight:800 !important; }
[data-testid="stMetric"] { background:linear-gradient(145deg,rgba(13,39,68,.98),rgba(8,25,46,.98)); border:1px solid #18558a; border-radius:15px; padding:15px 17px; box-shadow:0 8px 24px rgba(0,0,0,.18),inset 0 1px 0 rgba(255,255,255,.04); min-height:112px; }
[data-testid="stMetricLabel"] { color:#a9c3df !important; font-weight:600; }
[data-testid="stMetricValue"] { color:#f4f9ff !important; font-weight:800; }
div[data-testid="stPlotlyChart"] { background:linear-gradient(145deg,rgba(9,28,51,.95),rgba(7,21,39,.95)); border:1px solid #164b79; border-radius:16px; padding:8px; }
div[data-testid="stDataFrame"] { border:1px solid #164b79; border-radius:13px; overflow:hidden; }
.stButton>button,.stDownloadButton>button { border-radius:10px; border:1px solid #168dd0; background:linear-gradient(90deg,#087cc5,#1555b8); color:white; font-weight:700; }
hr { border-color:#173d63 !important; }
[data-testid="stCaptionContainer"] { color:#91aac6 !important; }
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
# HEADER
# =====================================================

st.title("🛡️ DeepShield")

st.subheader(
    "Intelligent Network Intrusion Detection & Threat Analytics"
)

st.caption(
    "AI-powered network traffic classification, "
    "attack identification and real-time anomaly monitoring."
)

st.divider()


# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.title("⚙️ Control Panel")

dashboard_mode = st.sidebar.radio(
    "Select Monitoring Mode",
    [
        "Live SOC Monitoring",
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
# LIVE SOC MONITORING
# =====================================================

if dashboard_mode == "Live SOC Monitoring":

    st.markdown(
        """
        <div style="padding:18px 20px;border:1px solid #174a78;border-radius:16px;
                    background:linear-gradient(110deg,rgba(9,34,62,.96),rgba(7,22,42,.94));">
          <div style="font-size:12px;color:#55cfff;font-weight:700;letter-spacing:2px;">DEEPSHIELD / LIVE DEFENSE</div>
          <div style="font-size:27px;font-weight:800;color:#f2f8ff;margin-top:3px;">Security Operations Center</div>
          <div style="font-size:13px;color:#9eb8d4;margin-top:4px;">Real-time network-flow analysis, threat detection and event intelligence</div>
          <div style="margin-top:12px;color:#4fffb3;font-size:12px;font-weight:700;">● LIVE SOC &nbsp;&nbsp; | &nbsp;&nbsp; MODEL · XGBOOST &nbsp;&nbsp; | &nbsp;&nbsp; AUTO REFRESH · 2s</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.info(
        "Make sure capture/live_detection_engine.py "
        "is running in a separate terminal."
    )

    @st.fragment(run_every="2s")
    def live_soc_dashboard():

        df = load_live_events()

        if df.empty:

            st.warning(
                "No live prediction events found yet."
            )

            st.markdown(
                """
                ### Start Live Monitoring

                Open another PowerShell terminal and run:

                ```powershell
                python capture\\live_detection_engine.py
                ```

                Once network traffic is captured, "
                "predictions will appear here automatically.
                """
            )

            return

        stats = get_live_statistics(df)

        # ---------------------------------------------
        # SUMMARY METRICS
        # ---------------------------------------------

        st.subheader("📊 Live Traffic Overview")

        provisional_count = int(
            (df["prediction_stage"].astype(str).str.upper() == "PROVISIONAL").sum()
        ) if "prediction_stage" in df.columns else 0

        final_count = int(
            (df["prediction_stage"].astype(str).str.upper() == "FINAL").sum()
        ) if "prediction_stage" in df.columns else 0

        metric_cols = st.columns(6)
        metric_cols[0].metric("Total Events", f"{stats['total_events']:,}")
        metric_cols[1].metric("Benign Traffic", f"{stats['benign_events']:,}")
        metric_cols[2].metric("Attack Traffic", f"{stats['attack_events']:,}")
        metric_cols[3].metric("Avg Attack Probability", f"{stats['average_attack_probability'] * 100:.2f}%")
        metric_cols[4].metric("Provisional", f"{provisional_count:,}")
        metric_cols[5].metric("Final Predictions", f"{final_count:,}")

        st.divider()

        # ---------------------------------------------
        # TRAFFIC DISTRIBUTION
        # ---------------------------------------------

        st.subheader("📈 Traffic Distribution")

        left, right = st.columns(2)

        traffic_df = pd.DataFrame({
            "Traffic Type": [
                "BENIGN",
                "ATTACK"
            ],
            "Events": [
                stats["benign_events"],
                stats["attack_events"]
            ]
        })

        with left:

            fig = px.pie(
                traffic_df,
                names="Traffic Type",
                values="Events",
                hole=0.55,
                title="Benign vs Attack Predictions"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        with right:

            st.metric(
                "Average Attack Probability",
                f"{stats['average_attack_probability'] * 100:.2f}%"
            )

            st.progress(
                float(
                    stats["average_attack_probability"]
                )
            )

            st.caption(
                "Average model attack probability across "
                "recorded prediction events."
            )

        st.divider()

        # ---------------------------------------------
        # ATTACK PROBABILITY TIMELINE
        # ---------------------------------------------

        st.subheader("📉 Attack Probability Timeline")

        if (
            "timestamp" in df.columns
            and "attack_probability" in df.columns
        ):

            timeline_df = df.dropna(
                subset=["timestamp"]
            ).sort_values("timestamp")

            if not timeline_df.empty:

                fig = px.line(
                    timeline_df,
                    x="timestamp",
                    y="attack_probability",
                    color="prediction",
                    title="Live Attack Probability",
                    labels={
                        "timestamp": "Time",
                        "attack_probability": "Attack Probability",
                        "prediction": "Prediction"
                    }
                )

                fig.update_yaxes(
                    range=[0, 1]
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True
                )

            else:

                st.info(
                    "No valid timestamps available."
                )

        else:

            st.info(
                "Probability timeline data is unavailable."
            )

        st.divider()

        # ---------------------------------------------
        # ATTACK EVENTS
        # ---------------------------------------------

        st.subheader("🚨 Detected Attack Events")

        attack_df = df[
            df["prediction"] == "ATTACK"
        ].copy()

        if not attack_df.empty:

            display_columns = [
                column for column in [
                    "timestamp",
                    "prediction",
                    "attack_probability",
                    "source_ip",
                    "destination_ip",
                    "destination_port",
                    "protocol",
                    "total_packets",
                    "prediction_stage"
                ]
                if column in attack_df.columns
            ]

            st.dataframe(
                attack_df[display_columns].sort_values(
                    "timestamp",
                    ascending=False
                ) if "timestamp" in display_columns
                else attack_df[display_columns],
                use_container_width=True,
                hide_index=True
            )

        else:

            st.success(
                "No ATTACK predictions have been recorded."
            )

        st.divider()

        # ---------------------------------------------
        # RECENT NETWORK EVENTS
        # ---------------------------------------------

        st.subheader("🌐 Recent Network Predictions")

        recent_df = df.tail(50).copy()

        display_columns = [
            column for column in [
                "timestamp",
                "prediction",
                "attack_probability",
                "source_ip",
                "destination_ip",
                "destination_port",
                "protocol",
                "total_packets",
                "prediction_stage"
            ]
            if column in recent_df.columns
        ]

        st.dataframe(
            recent_df[display_columns].sort_values(
                "timestamp",
                ascending=False
            ) if "timestamp" in display_columns
            else recent_df[display_columns],
            use_container_width=True,
            hide_index=True
        )

        # ---------------------------------------------
        # LAST EVENT
        # ---------------------------------------------

        if (
            "timestamp" in df.columns
            and df["timestamp"].notna().any()
        ):

            latest_time = df["timestamp"].max()

            st.caption(
                f"Last prediction event: {latest_time}"
            )

        st.caption(
            "Note: These counts represent prediction events, "
            "not necessarily unique network flows. A flow may "
            "produce provisional and final predictions."
        )

    live_soc_dashboard()

    st.divider()

    st.caption(
        "DeepShield | Live SOC Monitoring | "
        "Network Intrusion Detection"
    )

    st.stop()

# =====================================================
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
