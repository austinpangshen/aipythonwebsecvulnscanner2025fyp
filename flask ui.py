from flask import Flask, render_template, request, send_file
from main import run_scan  
from xml.sax.saxutils import escape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import io

app = Flask(__name__)

scan_status = {"result": None}

@app.route("/", methods=["GET", "POST"])
def index():
    global results
    results = None
    if request.method == "POST":
        target = request.form.get("target")

        try:           
            results = run_scan(target)
            print("FINAL RESULTS:", results)
            scan_status["result"] = results
        except Exception as e:
            results = {"error": str(e)}

    return render_template("index.html", results=results)

def generate_pdf(results):
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()

    elements = []

    elements.append(Paragraph("Vulnerability Scan Report", styles["Title"]))
    elements.append(Spacer(1, 20))

    # =========================
    # XSS SECTION
    # =========================
    elements.append(Paragraph("XSS Findings", styles["Heading2"]))
    elements.append(Spacer(1, 10))

    for x in results.get("xss", []):
        elements.append(Paragraph(f"<b>URL:</b> {escape(x.get('url', 'N/A'))}", styles["Normal"]))
        elements.append(Paragraph(f"<b>Payload:</b> {escape(x.get('payload', 'N/A'))}", styles["Normal"]))

        # Limit response length (VERY important)
        response = escape(x.get("response", "N/A"))[:500]
        elements.append(Paragraph(f"<b>Response:</b> {response}...", styles["Normal"]))

        elements.append(Spacer(1, 12))

    # =========================
    # HTML INJECTION
    # =========================
    elements.append(Paragraph("HTML Injection Findings", styles["Heading2"]))
    elements.append(Spacer(1, 10))

    for h in results.get("html", []):
        elements.append(Paragraph(f"<b>URL:</b> {escape(h.get('url', 'N/A'))}", styles["Normal"]))
        elements.append(Paragraph(f"<b>Payload:</b> {escape(h.get('payload', 'N/A'))}", styles["Normal"]))

        response = escape(h.get("response", "N/A"))[:500]
        elements.append(Paragraph(f"<b>Response:</b> {response}...", styles["Normal"]))

        elements.append(Spacer(1, 12))

    # =========================
    # CSRF
    # =========================
    elements.append(Paragraph("CSRF Findings", styles["Heading2"]))
    elements.append(Spacer(1, 10))

    for c in results.get("csrf", []):
        elements.append(Paragraph(f"<b>URL:</b> {escape(c.get('url', 'N/A'))}", styles["Normal"]))
        elements.append(Paragraph(f"<b>Method:</b> {escape(c.get('method', 'N/A'))}", styles["Normal"]))
        elements.append(Paragraph(f"<b>Issue:</b> {escape(c.get('subtype', 'N/A'))}", styles["Normal"]))
        elements.append(Paragraph(f"<b>Impact:</b> {escape(c.get('impact', 'N/A'))}", styles["Normal"]))

        elements.append(Spacer(1, 12))

    doc.build(elements)
    buffer.seek(0)

    return buffer

@app.route("/download_pdf")
def download_pdf():
    global scan_status

    if not scan_status["result"]:
        return "No scan results available"
    
    pdf = generate_pdf(scan_status["result"])

    return send_file(
        pdf,
        as_attachment=True,
        download_name="scan_report.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True)