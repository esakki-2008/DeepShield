
import streamlit as st
import pandas as pd
import plotly.express as px
import requests

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


# =====================================================
# CUSTOM CSS
# =====================================================

st.markdown("""
<style>

.stApp {
    background: #0b1120;
    color: #e5e7eb;
}

[data-testid="stMetric"] {
    background: #151f32;
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #26344d;
}

h1, h2, h3 {
    color: #60a5fa;
}

section[data-testid="stSidebar"] {
    background: #111827;
}

</style>
""", unsafe_allow_html=True)


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

    # -------------------------------------------------
    # TITLE
    # -------------------------------------------------

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

    # -------------------------------------------------
    # TRAFFIC SUMMARY
    # -------------------------------------------------

    story.append(
        Paragraph("2. Traffic Analysis", styles["SectionHeading"])
    )

    traffic_data = [
        ["Metric", "Records", "Percentage"],
        [
            "Total Records",
            f"{total:,}",
            "100%"
        ],
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

    # -------------------------------------------------
    # ATTACK FAMILY BREAKDOWN
    # -------------------------------------------------

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

    # -------------------------------------------------
    # SEVERITY BREAKDOWN
    # -------------------------------------------------

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

    # -------------------------------------------------
    # TOP PRIORITY THREATS
    # -------------------------------------------------

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

        threat_data = [
            [
                "Row",
                "Prediction",
                "Attack Family",
                "Risk Score",
                "Severity"
            ]
        ]

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
            Paragraph("No high or critical risk records were identified.",
                      styles["Normal"])
        )

    # -------------------------------------------------
    # METHODOLOGY AND LIMITATIONS
    # -------------------------------------------------

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

    # -------------------------------------------------
    # FOOTER
    # -------------------------------------------------

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
    "attack identification and anomaly detection."
)

st.divider()


# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.title("⚙️ Control Panel")

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

st.sidebar.markdown("### Supported Input")
st.sidebar.write("CIC-IDS2017 network-flow CSV")
st.sidebar.write("Maximum upload: 50,000 rows")

st.sidebar.divider()

st.sidebar.caption("DeepShield AI Security Platform")


# =====================================================
# FILE UPLOAD
# =====================================================

st.header("📂 Network Traffic Analysis")

uploaded_file = st.file_uploader(
    "Upload your network traffic CSV",
    type=["csv"]
)

if uploaded_file is not None:

    st.info(f"Selected file: {uploaded_file.name}")

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

            st.error(f"Request failed: {error}")

        except ValueError:

            st.error("The API returned an invalid JSON response.")


# =====================================================
# RESULTS
# =====================================================

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

        st.warning("No prediction records were returned.")
        st.stop()

    # =================================================
    # TRAFFIC OVERVIEW
    # =================================================

    st.divider()
    st.header("📊 Threat Analysis Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Records", f"{total:,}")
    col2.metric("Benign Traffic", f"{benign:,}")
    col3.metric("Detected Attacks", f"{attacks:,}")
    col4.metric("Anomaly Flags", f"{anomalies:,}")

    # =================================================
    # TRAFFIC ANALYTICS
    # =================================================

    st.divider()
    st.header("📈 Traffic Analytics")

    left, right = st.columns(2)

    traffic_df = pd.DataFrame({
        "Traffic Type": ["Benign", "Attack"],
        "Records": [benign, attacks]
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
                columns=["Attack Family", "Records"]
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

            st.info("No attack families detected.")

    # =================================================
    # ANOMALY DETECTION
    # =================================================

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

    # =================================================
    # THREAT INTELLIGENCE
    # =================================================

    st.divider()
    st.header("🚨 Threat Intelligence & Risk Assessment")

    required_columns = [
        "row_number",
        "prediction",
        "attack_probability",
        "anomaly_detected",
        "attack_family"
    ]

    missing_columns = [
        column for column in required_columns
        if column not in predictions_df.columns
    ]

    if missing_columns:

        st.error(
            "API response is missing columns: "
            + ", ".join(missing_columns)
        )

        st.stop()

    predictions_df["attack_probability"] = pd.to_numeric(
        predictions_df["attack_probability"],
        errors="coerce"
    ).fillna(0).clip(0, 1)

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
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            fill_value=0
        )
    )

    st.subheader("Threat Severity Overview")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("🔴 Critical", int(severity_counts["CRITICAL"]))
    c2.metric("🟠 High", int(severity_counts["HIGH"]))
    c3.metric("🟡 Medium", int(severity_counts["MEDIUM"]))
    c4.metric("🟢 Low", int(severity_counts["LOW"]))

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

    # =================================================
    # PRIORITY ALERTS
    # =================================================

    st.subheader("⚠️ Priority Threat Alerts")

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

        st.success("No high or critical risk records found.")

    # =================================================
    # DETAILED PREDICTIONS
    # =================================================

    st.divider()
    st.header("📋 Detailed Prediction Results")

    st.dataframe(
        predictions_df,
        use_container_width=True,
        hide_index=True
    )

    # =================================================
    # AUTOMATED REPORT GENERATION
    # =================================================

    st.divider()
    st.header("📑 Automated Security Reporting")

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

            st.error(f"PDF generation failed: {error}")

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

    # =================================================
    # FOOTER
    # =================================================

    st.divider()

    st.success(
        "DeepShield network traffic analysis completed successfully."
    )

    st.caption(
        "Risk scores are preliminary heuristic indicators, "
        "not calibrated real-world incident severity. "
        "Anomaly flags are separate from confirmed attack predictions. "
        "This system analyzes uploaded network-flow CSV records "
        "and does not currently capture live network packets."
    )


# =====================================================
# EMPTY STATE
# =====================================================

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
