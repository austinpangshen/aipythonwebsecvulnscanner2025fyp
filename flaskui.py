from flask import Flask, render_template, request, send_file, jsonify
from main import run_scan  
from xml.sax.saxutils import escape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
import io
import threading
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

import os

app = Flask(__name__)

# Shared state
scan_progress = {"percent": 0, "status": "Idle"}
scan_status = {"result": None, "running": False}

def generate_pie_chart(results):

    counts = {
        "XSS": len(results.get("xss", [])),
        "HTML": len(results.get("html", [])),
        "CSRF": len(results.get("csrf", [])),
        "SSRF": len(results.get("ssrf", [])),
        "SQLi": 1 if results.get("sqlmap") and results["sqlmap"].get("vulnerable") else 0
    }

    labels = [k for k, v in counts.items() if v > 0]
    values = [v for v in counts.values() if v > 0]

    if not values:
        return

    plt.figure(figsize=(7, 5), facecolor='none')

    wedges, texts, autotexts = plt.pie(
        values,
        labels=labels,
        autopct='%1.1f%%',
        startangle=90
    )

    # White text for dark background
    for text in texts:
        text.set_color("white")
        text.set_fontsize(12)

    for autotext in autotexts:
        autotext.set_color("white")
        autotext.set_fontsize(11)

    plt.title(
        "Vulnerability Distribution",
        color="white",
        fontsize=16,
        pad=20
    )

    # Transparent background
    plt.gca().set_facecolor('none')

    os.makedirs("static", exist_ok=True)

    plt.savefig(
        "static/pie.png",
        transparent=True,
        bbox_inches='tight'
    )

    plt.close()

def run_scan_async(target):
    """Runs in a background thread so Flask stays responsive."""
    global scan_status, scan_progress

    try:
        scan_status["running"] = True
        scan_status["result"] = None  # Clear old results

        result = run_scan(target)

        generate_pie_chart(result)
        scan_status["result"] = result

        scan_progress["percent"] = 100
        scan_progress["status"] = "Completed"

    except Exception as e:
        scan_progress["status"] = f"Error: {str(e)}"
        scan_status["result"] = {"error": str(e)}
    finally:
        scan_status["running"] = False

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target")

        # Reset state for new scan
        scan_status["result"] = None
        scan_progress["percent"] = 0
        scan_progress["status"] = "Starting..."

        # Run scan in background thread
        thread = threading.Thread(target=run_scan_async, args=(target,))
        thread.daemon = True
        thread.start()

        # Return 204 (no content) — JS handles everything
        return "", 204

    # GET request — show results if available
    return render_template("index.html", results=scan_status["result"])

@app.route("/progress")
def progress():
    return jsonify(scan_progress)

@app.route("/results")
def results():
    return jsonify({"done": scan_status["result"] is not None})

@app.route("/jsonify")
def jsonresults():
    if not scan_status["result"]:
        return jsonify({
            "status": "No scan results available"
        }), 404
    return jsonify(scan_status["result"])

def generate_pdf(results):
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Image,
        PageBreak,
        Table,
        TableStyle
    )

    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus.flowables import HRFlowable

    import io
    import os
    from datetime import datetime
    from xml.sax.saxutils import escape

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=30
    )

    styles = getSampleStyleSheet()
    elements = []

    # =====================================================
    # HELPER FUNCTIONS
    # =====================================================

    def add_heading(text):
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(text, styles["Heading1"]))
        elements.append(HRFlowable(width="100%"))
        elements.append(Spacer(1, 10))

    def add_subheading(text):
        elements.append(Spacer(1, 8))
        elements.append(Paragraph(text, styles["Heading2"]))
        elements.append(Spacer(1, 6))

    def add_paragraph(text):
        elements.append(Paragraph(text, styles["BodyText"]))
        elements.append(Spacer(1, 6))

    def severity_color(severity):
        severity = severity.lower()

        if severity == "critical":
            return colors.red
        elif severity == "high":
            return colors.orange
        elif severity == "medium":
            return colors.gold
        elif severity == "low":
            return colors.green
        else:
            return colors.lightgrey

    # =====================================================
    # COUNT FINDINGS
    # =====================================================

    xss_count = len(results.get("xss", []))
    html_count = len(results.get("html", []))
    csrf_count = len(results.get("csrf", []))
    ssrf_count = len(results.get("ssrf", []))
    xxe_count = len(results.get("xxe", []))

    sqli_count = 0
    if results.get("sqlmap", {}).get("vulnerable"):
        sqli_count = 1

    total_findings = (
        xss_count +
        html_count +
        csrf_count +
        ssrf_count +
        xxe_count +
        sqli_count
    )

    # =====================================================
    # COVER PAGE
    # =====================================================

    elements.append(Spacer(1, 120))

    title = "Automated Web Vulnerability Assessment Report"
    elements.append(Paragraph(title, styles["Title"]))

    elements.append(Spacer(1, 30))

    add_paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    add_paragraph(f"<b>Total Vulnerabilities Detected:</b> {total_findings}")

    elements.append(Spacer(1, 200))

    add_paragraph("Final Year Project")
    add_paragraph("Automated Vulnerability Assessment System")

    elements.append(PageBreak())

    # =====================================================
    # EXECUTIVE SUMMARY
    # =====================================================

    add_heading("Executive Summary")

    summary_text = f"""
    The automated vulnerability assessment system performed security testing
    against the target web application through active payload injection,
    crawling, and response analysis techniques.

    A total of <b>{total_findings}</b> potential vulnerabilities were identified
    across multiple categories including Cross-Site Scripting (XSS),
    Server-Side Request Forgery (SSRF), Cross-Site Request Forgery (CSRF),
    HTML Injection, XML External Entity Injection (XXE), and SQL Injection (SQLi).

    The assessment identified weaknesses that may allow attackers to execute
    malicious scripts, access internal resources, bypass authentication mechanisms,
    or compromise application confidentiality and integrity.
    """

    add_paragraph(summary_text)

    # =====================================================
    # VULNERABILITY SUMMARY TABLE
    # =====================================================

    add_subheading("Vulnerability Summary")

    summary_data = [
        ["Vulnerability Type", "Count"],
        ["Cross-Site Scripting (XSS)", str(xss_count)],
        ["HTML Injection", str(html_count)],
        ["Cross-Site Request Forgery (CSRF)", str(csrf_count)],
        ["Server-Side Request Forgery (SSRF)", str(ssrf_count)],
        ["XML External Entity (XXE)", str(xxe_count)],
        ["SQL Injection (SQLi)", str(sqli_count)],
    ]

    summary_table = Table(summary_data, colWidths=[300, 100])

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

        ("GRID", (0, 0), (-1, -1), 1, colors.black),

        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),

        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),

        ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
    ]))

    elements.append(summary_table)

    elements.append(Spacer(1, 20))

    # =====================================================
    # PIE CHART
    # =====================================================

    if os.path.exists("static/pie.png"):
        add_subheading("Vulnerability Distribution")
        elements.append(Image("static/pie.png", width=400, height=250))
        elements.append(Spacer(1, 20))

    # =====================================================
    # DETAILED FINDINGS
    # =====================================================

    add_heading("Detailed Vulnerability Findings")

    vulnerability_sections = [
        ("XSS", results.get("xss", []), "High"),
        ("HTML Injection", results.get("html", []), "Medium"),
        ("CSRF", results.get("csrf", []), "Medium"),
        ("SSRF", results.get("ssrf", []), "Critical"),
        ("XXE", results.get("xxe", []), "Critical")
    ]

    for vuln_name, vuln_list, severity in vulnerability_sections:

        if not vuln_list:
            continue

        add_subheading(vuln_name)

        for vuln in vuln_list:

            vuln_data = [
                ["Field", "Details"],
                ["Severity", severity],
                ["URL", escape(str(vuln.get("url", "N/A")))],
                ["Parameter", escape(str(vuln.get("parameter", "N/A")))],
                ["Payload", escape(str(vuln.get("payloads", vuln.get("payload", "N/A"))))],
                ["Evidence", escape(str(vuln.get("evidence", "N/A")))],
            ]

            table = Table(vuln_data, colWidths=[120, 350])

            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

                ("BACKGROUND", (0, 1), (0, -1), colors.lightgrey),

                ("GRID", (0, 0), (-1, -1), 1, colors.black),

                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),

                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ]))

            elements.append(table)
            elements.append(Spacer(1, 16))

    # =====================================================
    # SQLMAP SECTION
    # =====================================================

    if results.get("sqlmap"):

        add_heading("SQL Injection Assessment")

        sqlmap_result = results["sqlmap"]

        sqli_text = f"""
        <b>Target:</b> {escape(str(sqlmap_result.get("url", "N/A")))}<br/>
        <b>Vulnerable:</b> {sqlmap_result.get("vulnerable", False)}<br/>
        """

        add_paragraph(sqli_text)

    # =====================================================
    # SECURITY RECOMMENDATIONS
    # =====================================================

    add_heading("Security Recommendations")
    recommendations = []

    # -----------------------------
    # XSS
    # -----------------------------
    if xss_count > 0:
        recommendations.append(
            "Implement proper input validation and output encoding to mitigate Cross-Site Scripting (XSS) vulnerabilities."
        )

    # -----------------------------
    # HTML Injection
    # -----------------------------
    if html_count > 0:
        recommendations.append(
            "Sanitize user-controlled HTML content and apply strict output filtering to prevent HTML Injection attacks."
        )

    # -----------------------------
    # CSRF
    # -----------------------------
    if csrf_count > 0:
        recommendations.append(
            "Implement anti-CSRF tokens and enforce SameSite cookie protections to prevent unauthorized request forgery."
        )

    # -----------------------------
    # SSRF
    # -----------------------------
    if ssrf_count > 0:
        recommendations.append(
            "Restrict server-side outbound requests using allowlists, firewall rules, and internal network segmentation to mitigate SSRF attacks."
        )

    # -----------------------------
    # XXE
    # -----------------------------
    if xxe_count > 0:
        recommendations.append(
            "Disable unsafe XML entity processing and configure secure XML parsers to mitigate XXE vulnerabilities."
        )

    # -----------------------------
    # SQLi
    # -----------------------------
    if sqli_count > 0:
        recommendations.append(
            "Use parameterized queries and prepared statements to prevent SQL Injection vulnerabilities."
        )

    # -----------------------------
    # GENERIC RECOMMENDATIONS
    # -----------------------------
    recommendations.extend([
        "Apply the principle of least privilege for server-side components and database accounts.",
        "Keep frameworks, dependencies, and server technologies updated with the latest security patches.",
        "Perform regular security assessments and continuous vulnerability monitoring.",
        "Implement secure coding practices throughout the software development lifecycle."
    ])

    # -----------------------------
    # NO VULNS CASE
    # -----------------------------
    if total_findings == 0:

        add_paragraph("""
        No critical security recommendations were generated because the assessment
        did not identify any obvious vulnerabilities within the scope of the
        performed tests.

        Nevertheless, organizations are encouraged to continue applying secure
        development practices, routine patch management, and periodic security
        assessments to maintain a strong security posture.
        """)

    else:

        for rec in recommendations:
            add_paragraph(f"• {rec}")

    # =====================================================
    # CONCLUSION
    # =====================================================

    add_heading("Conclusion")

    if total_findings > 0:

        conclusion_text = f"""
        The automated vulnerability assessment successfully identified multiple
        security weaknesses through automated crawling, payload injection,
        machine-learning-assisted analysis, and vulnerability validation techniques.

        A total of <b>{total_findings}</b> potential vulnerabilities were detected
        during the assessment process. The identified findings may expose the
        application to risks such as unauthorized access, malicious script execution,
        server-side exploitation, or sensitive information disclosure.

        Organizations are strongly encouraged to remediate the identified issues
        promptly to improve the overall security posture of the web application.
        Continuous security testing and secure development practices should also
        be implemented to reduce future attack surfaces.
        """

    else:

        conclusion_text = f"""
        The automated vulnerability assessment completed successfully and did not
        identify any obvious security vulnerabilities within the scope of the
        performed tests.

        The absence of detected vulnerabilities indicates that the assessed web
        application demonstrates a relatively stronger security posture against
        the implemented scanning techniques and payload-based attacks used by
        the system.

        However, security testing should be conducted continuously as new
        vulnerabilities, configuration weaknesses, or application changes may
        introduce future risks. Regular security assessments and secure coding
        practices remain essential for maintaining application security.
        """

    add_paragraph(conclusion_text)

    # =====================================================
    # BUILD PDF
    # =====================================================

    doc.build(elements)

    buffer.seek(0)

    return buffer

@app.route("/download_pdf")
def download_pdf():
    if not scan_status["result"]:
        return "No scan results available", 400
    pdf = generate_pdf(scan_status["result"])
    return send_file(pdf, as_attachment=True, download_name="scan_report.pdf", mimetype="application/pdf")

if __name__ == "__main__":
    app.run(debug=True)