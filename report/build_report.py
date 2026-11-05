from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, PageBreak, PageTemplate, Paragraph,
    Spacer, Table, TableStyle, Preformatted, NextPageTemplate, Image,
)
from reportlab.platypus.tableofcontents import TableOfContents


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "Secure_Authentication_for_IoT_Devices_CCA_Report.pdf"
PAGE_W, PAGE_H = A4
INK = colors.HexColor("#1d2a3a")
BLUE = colors.HexColor("#234b70")
PALE = colors.HexColor("#eef3f7")


class ReportDoc(BaseDocTemplate):
    def __init__(self, filename):
        super().__init__(str(filename), pagesize=A4, leftMargin=24*mm, rightMargin=24*mm,
                         topMargin=23*mm, bottomMargin=21*mm, title="Secure Authentication for IoT Devices")
        cover = Frame(18*mm, 18*mm, PAGE_W-36*mm, PAGE_H-36*mm, id="cover", leftPadding=8*mm,
                      rightPadding=8*mm, topPadding=8*mm, bottomPadding=8*mm)
        body = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="body")
        self.addPageTemplates([
            PageTemplate(id="cover", frames=cover, onPage=draw_cover),
            PageTemplate(id="body", frames=body, onPage=draw_body),
        ])

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name == "SectionTitle":
            title = flowable.getPlainText()
            key = "section-%s" % self.seq.nextf("section")
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(title, key, 0, False)
            self.notify("TOCEntry", (0, title, self.page, key))


def draw_cover(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.black)
    canvas.setLineWidth(.6)
    canvas.rect(12*mm, 12*mm, PAGE_W-24*mm, PAGE_H-24*mm)
    canvas.restoreState()


def draw_body(canvas, doc):
    canvas.saveState()
    page = canvas.getPageNumber()
    if page >= 4:
        canvas.setFont("Times-Roman", 8)
        canvas.setFillColor(colors.HexColor("#657180"))
        canvas.drawString(24*mm, PAGE_H-14*mm, "INFORMATION AND NETWORK SECURITY  |  BCS701")
        canvas.setStrokeColor(colors.HexColor("#c9d2da"))
        canvas.setLineWidth(.4)
        canvas.line(24*mm, PAGE_H-16*mm, PAGE_W-24*mm, PAGE_H-16*mm)
    canvas.setFont("Times-Roman", 9)
    canvas.setFillColor(colors.black)
    canvas.drawRightString(PAGE_W-24*mm, 12*mm, str(page))
    canvas.restoreState()


styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="CoverInstitute", fontName="Times-Bold", fontSize=15, leading=19, alignment=TA_CENTER, textColor=colors.black))
styles.add(ParagraphStyle(name="CoverLine", fontName="Times-Roman", fontSize=12, leading=17, alignment=TA_CENTER))
styles.add(ParagraphStyle(name="CoverTitle", fontName="Times-Bold", fontSize=16, leading=21, alignment=TA_CENTER, textColor=INK))
styles.add(ParagraphStyle(name="SectionTitle", fontName="Times-Bold", fontSize=16, leading=20, spaceBefore=2, spaceAfter=12, textColor=INK, keepWithNext=True))
styles.add(ParagraphStyle(name="SubTitle", fontName="Times-Bold", fontSize=12, leading=15, spaceBefore=9, spaceAfter=5, textColor=BLUE, keepWithNext=True))
styles.add(ParagraphStyle(name="ReportBody", fontName="Times-Roman", fontSize=10.5, leading=15, alignment=TA_JUSTIFY, spaceAfter=7))
styles.add(ParagraphStyle(name="BulletBody", parent=styles["ReportBody"], leftIndent=14, firstLineIndent=-8, spaceAfter=4))
styles.add(ParagraphStyle(name="Small", fontName="Times-Roman", fontSize=8.5, leading=11, spaceAfter=2))
styles.add(ParagraphStyle(name="TableHead", fontName="Times-Bold", fontSize=8.4, leading=10, alignment=TA_CENTER, textColor=colors.white))
styles.add(ParagraphStyle(name="EvalHead", fontName="Times-Bold", fontSize=8.4, leading=10, alignment=TA_CENTER, textColor=colors.black))
styles.add(ParagraphStyle(name="TableCell", fontName="Times-Roman", fontSize=8.4, leading=10.5))
styles.add(ParagraphStyle(name="TableCenter", fontName="Times-Roman", fontSize=8.5, leading=10, alignment=TA_CENTER))
styles.add(ParagraphStyle(name="TOCTitle", fontName="Times-Roman", fontSize=18, leading=22, alignment=TA_LEFT))
styles.add(ParagraphStyle(name="ReportCode", fontName="Courier", fontSize=8, leading=10, leftIndent=5, rightIndent=5, backColor=PALE, borderPadding=7))


def P(text, style="ReportBody"):
    return Paragraph(text, styles[style])


def bullets(items):
    return [P("•  " + item, "BulletBody") for item in items]


def make_table(headers, rows, widths, font=8.4):
    data = [[P(h, "TableHead") for h in headers]]
    for row in rows:
        data.append([P(str(v), "TableCell") for v in row])
    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), BLUE),
        ("GRID", (0,0), (-1,-1), .45, colors.HexColor("#aab7c2")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 6), ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f5f7f9")]),
    ]))
    return t


def section(title, flowables):
    return [P(title, "SectionTitle"), *flowables]


def build():
    doc = ReportDoc(OUTPUT)
    story = []

    # Page 1: title page follows the submitted template's centered hierarchy.
    story += [Spacer(1, 9*mm), P("BMS INSTITUTE OF TECHNOLOGY AND MANAGEMENT", "CoverInstitute"),
              P("Autonomous Institute under VTU, Belagavi, Karnataka - 590 018", "CoverLine"),
              Spacer(1, 2*mm), P("Yelahanka, Bengaluru, Karnataka - 560 119", "CoverLine"), Spacer(1, 13*mm)]
    # A simple typographic emblem keeps the title sheet clean without substituting an unverified logo.
    emblem = Table([[P("BMSIT&amp;M", "CoverInstitute")]], colWidths=[43*mm], rowHeights=[25*mm], hAlign="CENTER")
    emblem.setStyle(TableStyle([("BOX", (0,0),(-1,-1),1.1,BLUE), ("ROUNDEDCORNERS", [14]),
                                ("ALIGN",(0,0),(-1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                                ("TEXTCOLOR",(0,0),(-1,-1),BLUE)]))
    logo_path = ROOT / "bmsitm_emblem.png"
    if logo_path.exists():
        story += [Image(str(logo_path), width=34*mm, height=39*mm, hAlign="CENTER")]
    else:
        story += [emblem]
    story += [Spacer(1, 11*mm), P("Information and Network Security (BCS701) CCA Report", "CoverLine"),
              Spacer(1, 4*mm), P("On", "CoverLine"), Spacer(1, 2*mm),
              P("SECURE AUTHENTICATION FOR IoT DEVICES", "CoverTitle"), Spacer(1, 18*mm),
              P("BACHELOR OF ENGINEERING", "CoverLine"), Spacer(1, 2*mm), P("in", "CoverLine"),
              Spacer(1, 2*mm), P("INFORMATION SCIENCE AND ENGINEERING", "CoverLine"),
              Spacer(1, 2*mm), P("by", "CoverLine"), Spacer(1, 2*mm),
              P("NAME: ________________________________     USN: __________________", "CoverLine"), Spacer(1, 13*mm),
              P("Under the Guidance of", "CoverLine"), P("Dr. Swetha M S", "CoverLine"),
              P("Associate Professor", "CoverLine"), Spacer(1, 18*mm),
              P("DEPARTMENT OF INFORMATION SCIENCE AND ENGINEERING", "CoverLine"),
              P("Avalahalli, Yelahanka, Bengaluru, Karnataka - 560119", "CoverLine"),
              P("2025-26", "CoverLine"), NextPageTemplate("body"), PageBreak()]

    # Page 2: evaluation grid and marks distribution from the supplied format.
    story += [Spacer(1, 8*mm), P("Evaluation sheet", "CoverInstitute"), Spacer(1, 17*mm)]
    eval_headers = ["Name", "USN", "Problem Understanding &amp; Requirements", "Design &amp; Implementation",
                    "Security Analysis &amp; Testing", "Innovation &amp; Application Relevance", "Documentation &amp; Presentation", "Total"]
    eval_row = ["", "", "3", "9", "2", "2", "4", "20"]
    widths = [21*mm, 21*mm, 31*mm, 30*mm, 22*mm, 28*mm, 29*mm, 19*mm]
    evaldata = [[P(x,"EvalHead") for x in eval_headers], [P(x,"TableCenter") for x in eval_row], [""]*8]
    evaluation = Table(evaldata, colWidths=widths, rowHeights=[23*mm, 11*mm, 11*mm], hAlign="CENTER")
    evaluation.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#f0f2f4")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.black),("FONTNAME",(0,0),(-1,-1),"Times-Roman"),
        ("GRID",(0,0),(-1,-1),.6,colors.black),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("LEFTPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),4)]))
    story += [evaluation, PageBreak()]

    # Page 3: contents entries are generated from the numbered headings below.
    toc_header = Table([[P("Content", "TOCTitle"), P("Page No.", "TOCTitle")]], colWidths=[118*mm, 34*mm])
    toc_header.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"BOTTOM"), ("ALIGN",(1,0),(1,0),"RIGHT"),
                                    ("LEFTPADDING",(0,0),(-1,-1),0), ("RIGHTPADDING",(0,0),(-1,-1),0)]))
    story += [toc_header, Spacer(1, 3*mm)]
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle(name="TOC0", fontName="Times-Roman", fontSize=11, leading=19,
                                      leftIndent=4*mm, firstLineIndent=-4*mm, spaceBefore=2)]
    story += [toc, PageBreak()]

    story += section("1. Introduction", [
        P("Internet of Things (IoT) deployments connect sensors, controllers, gateways, and cloud services that may be unattended and resource-constrained. Each device must establish its identity before it can publish readings or accept commands. If an attacker can impersonate a device, inject messages, or reuse captured authentication data, the system may make unsafe decisions or lose trustworthy telemetry."),
        P("This project implements a compact challenge-response prototype. A device proves possession of a provisioned secret by computing a keyed message authentication code (HMAC) over a fresh server challenge, its device identity, and a one-time session identifier. The design follows the basic security goals of authenticating peers and protecting communications; deployment guidance also emphasizes lifecycle controls for IoT products [1], while HMAC is specified as a keyed message authentication construction [2]."),
        P("The prototype is intentionally small enough to study. It contains a local authentication server, a simulated device, a JSON demonstration registry, and a report. The source files are in the accompanying <i>iot-auth-project</i> folder."),
    ])

    story += section("2. Abstract", [
        P("This report presents a secure authentication prototype for IoT devices using nonce-based challenge-response authentication. The server issues a cryptographically random 256-bit challenge associated with a registered device and a unique session identifier. The simulated device computes an HMAC-SHA-256 proof using its pre-provisioned symmetric key. The server verifies the proof with a constant-time comparison and consumes the session regardless of success, limiting reuse of a captured response. Challenges expire after 60 seconds."),
        P("The prototype is implemented with Python's standard library and exposes two JSON endpoints: <font name='Courier'>/challenge</font> and <font name='Courier'>/authenticate</font>. Optional TLS can be enabled by providing a certificate and private key. The design meets the educational objectives of demonstrating identity validation, integrity, freshness, and replay resistance. The evaluation is a design-based security analysis and a documented test plan; it does not claim production readiness or formal verification. Real deployments additionally require protected per-device keys, verified TLS, authorization, revocation, rotation, monitoring, and fault-tolerant replay state."),
        P("Keywords: IoT security, device identity, HMAC, challenge-response, nonce, replay resistance."),
    ])

    story += section("3. Problem Statement", [
        P("A large IoT network may contain devices that communicate over shared or exposed networks. A static device password or reusable MAC value can be copied from traffic and replayed. Weak identity checks may also accept unregistered devices, while inconsistent key handling can expose the whole deployment."),
        P("The problem addressed is to demonstrate a lightweight authentication flow that lets a server distinguish a registered device possessing its assigned secret from an unauthenticated claimant, while making each proof specific to one fresh session."),
        P("Objectives", "SubTitle"),
        *bullets(["Register demonstration device identities with individual symmetric keys.",
                  "Issue unpredictable challenges with bounded validity.",
                  "Bind the authentication proof to the device ID, challenge, and session ID.",
                  "Reject unknown devices, invalid proofs, expired sessions, and reused sessions.",
                  "Document the security properties, limits, and future deployment requirements."]),
        P("Scope and assumptions", "SubTitle"),
        P("The demonstration assumes an attacker may observe, modify, delay, or replay network messages, but cannot read the server's device registry or extract the device's secret key. The prototype does not implement device onboarding, authorization of individual commands, protected hardware storage, certificate issuance, or a production database. Those assumptions are explicit because authentication alone does not establish that every authenticated device is authorized for every action."),
    ])

    story += section("4. System Requirements", [
        P("Functional requirements", "SubTitle"),
        make_table(["ID", "Requirement", "Implementation"], [
            ("FR-1", "Identify a device using a registered device ID.", "JSON device registry"),
            ("FR-2", "Generate a fresh server challenge and session ID.", "Python secrets module"),
            ("FR-3", "Compute and verify an HMAC proof over all session context.", "HMAC-SHA-256"),
            ("FR-4", "Reject an unknown device or malformed request.", "Input checks and 4xx responses"),
            ("FR-5", "Expire and consume each challenge at most once.", "60-second TTL and atomic pop"),
            ("FR-6", "Support encrypted transport for a local demonstration.", "Optional Python TLS socket"),
        ], [15*mm, 73*mm, 66*mm]),
        Spacer(1, 4*mm), P("Non-functional requirements", "SubTitle"),
        *bullets(["Use standard cryptographic primitives from the Python standard library; do not invent a MAC algorithm.",
                  "Keep the demo runnable without third-party Python packages.",
                  "Use a constant-time comparison for the supplied proof.",
                  "Return clear authentication outcomes without disclosing secret material.",
                  "Keep the sample deployment local by default and identify production security gaps."]),
        P("Hardware and software", "SubTitle"),
        P("The prototype runs on a computer with Python 3.10 or newer. A real IoT target needs a network interface, a cryptographic random source, and protected persistent storage for a unique device key. The demo server binds to 127.0.0.1 by default; HTTPS can be enabled with a trusted certificate and matching client configuration."),
    ])

    story += section("5. Design and Implementation", [
        P("Architecture", "SubTitle"),
        P("The system has three logical components: (1) an authentication server holding the registered device keys and pending challenges, (2) a device simulator holding the matching demo key, and (3) an HTTP(S) JSON interface connecting them. The server does not transmit a device key. It sends a random challenge, and the client returns only a keyed proof."),
        make_table(["Step", "Message / action", "Security purpose"], [
            ("1", "Device → server: POST /challenge {device_id}", "Requests a session for a known identity"),
            ("2", "Server → device: random challenge + session_id + expiry", "Fresh unpredictable verifier input"),
            ("3", "Device: HMAC(key, context || ID || session || challenge)", "Proves key possession; binds context"),
            ("4", "Device → server: POST /authenticate {ID, session, proof}", "Submits one session-specific proof"),
            ("5", "Server: consume session, recompute, constant-time compare", "Rejects replay and avoids simple timing leaks"),
        ], [13*mm, 78*mm, 63*mm]),
        Spacer(1, 4*mm), P("Authentication message", "SubTitle"),
        Preformatted("message = b\"INS-IOT-AUTH-v1\" + b\"|\" + device_id\n          + b\"|\" + session_id + b\"|\" + challenge\nproof   = HMAC-SHA-256(device_key, message)\n", styles["ReportCode"]),
        P("The fixed domain label separates this use from other possible uses of the same key. The challenge and session identifier are generated by the server; the client does not choose either. The server stores pending state under a random session ID and removes it before proof comparison, so a failed attempt cannot reuse that challenge. An expiry timestamp bounds how long abandoned challenges remain usable."),
        P("Project structure", "SubTitle"),
        Preformatted("iot-auth-project/\n  server.py                 challenge service and verifier\n  device.py                 device simulator\n  data/demo_devices.json    public classroom sample identities\n  README.md                 setup and security limitations\n  report/build_report.py    report source\n  report/Secure_Authentication_for_IoT_Devices_CCA_Report.pdf\n", styles["ReportCode"]),
        P("Run the server with <font name='Courier'>python server.py</font>, then use another terminal to run <font name='Courier'>python device.py sensor-001</font>. The expected successful result is a JSON response with <font name='Courier'>authenticated: true</font>. The sample keys are deliberately public and must never be reused."),
    ])

    story += section("6. Security Analysis", [
        P("Security objectives", "SubTitle"),
        make_table(["Property", "How the prototype supports it", "Boundary"], [
            ("Device authentication", "Proof is checked against the key registered for the claimed ID.", "Compromised key allows impersonation of that device."),
            ("Integrity of proof", "HMAC-SHA-256 detects a modified proof or message context.", "Authentication proof does not encrypt telemetry."),
            ("Freshness", "A random challenge is tied to a short-lived session.", "In-memory state is lost on server restart."),
            ("Replay resistance", "The session is consumed once before verification.", "A multi-server deployment needs shared atomic state."),
            ("Transport confidentiality", "Optional TLS socket support.", "HTTP demo mode must remain on localhost."),
        ], [31*mm, 66*mm, 57*mm]),
        Spacer(1, 4*mm), P("Threat analysis", "SubTitle"),
        *bullets(["Replay: an earlier proof includes an old challenge and session. Once consumed or expired, that session is no longer accepted.",
                  "Impersonation: a claimant without the registered secret cannot feasibly create the expected HMAC, assuming a strong secret and sound implementation.",
                  "Unknown identity: challenge issuance is refused when the device ID is absent from the registry.",
                  "Tampering: changing the device ID, session ID, or challenge changes the authenticated message and invalidates the proof.",
                  "Eavesdropping: the HMAC does not conceal readings or API metadata. TLS is required for confidentiality and channel protection. TLS 1.3 is designed to protect against eavesdropping, tampering, and message forgery [3]."]),
        P("Key management and limitations", "SubTitle"),
        P("Key secrecy is the central assumption. The checked-in JSON keys are public test fixtures, the file is unencrypted, and a copied key permits device impersonation. Before real deployment, provision a distinct high-entropy key per device through an authenticated process, store it in a secure element or equivalent protected hardware, and design revocation, replacement, and audit procedures. NIST's IoT manufacturer guidance emphasizes foundational activities across device lifecycles [1]. NIST defines replay resistance as protection from capturing and retransmitting authentication information [4]."),
        P("The server uses process-local challenge memory. A restart clears active sessions, which is fail-closed for these sessions, but concurrent server instances do not share replay state. Production operation needs a durable, atomic challenge store, request rate limits, monitoring, authorization checks, secure backups, and operational key rotation. The prototype should not be represented as certified or production hardened."),
    ])

    story += [PageBreak()]
    story += section("7. System Testing", [
        P("The following verification cases are defined for demonstration and evaluation. They describe expected behavior; no measured execution results are claimed in this report."),
        make_table(["Test", "Input / action", "Expected result"], [
            ("ST-1", "Authenticate sensor-001 with its demo key.", "HTTP 200 and authenticated=true."),
            ("ST-2", "Request a challenge for an unknown device ID.", "HTTP 401; no challenge is issued."),
            ("ST-3", "Change one character of a valid proof.", "HTTP 401; session is consumed."),
            ("ST-4", "Submit the same session and proof a second time.", "HTTP 401 because the session no longer exists."),
            ("ST-5", "Submit an expired challenge after 60 seconds.", "HTTP 401; expired proof is rejected."),
            ("ST-6", "Send missing fields or malformed JSON.", "HTTP 400 with a generic request error."),
            ("ST-7", "Enable TLS with a trusted local certificate.", "Client connects only after certificate validation."),
        ], [17*mm, 70*mm, 67*mm]),
        Spacer(1, 4*mm), P("Evaluation measures", "SubTitle"),
        P("The implementation is small and deterministic in its protocol shape, uses standard library cryptography interfaces, and keeps the secret off the wire. Functional acceptance should be established by completing the scenarios above. Security acceptance additionally requires code review of key storage, deployment configuration, TLS certificate validation, session-state consistency, logging, and authorization. Performance and memory measurements are outside this classroom prototype's current scope."),
    ])

    story += section("8. Innovation and Application relevance", [
        P("The key design choice is the use of a one-time server challenge with the device identity and session identifier included in the HMAC input. This keeps the protocol understandable while addressing the common weakness of repeatedly transmitting a static credential. Explicit session consumption also makes replay handling visible in the implementation, rather than relying on timestamps alone."),
        P("The prototype is relevant to smart home sensors, environmental monitoring, industrial telemetry, and classroom IoT testbeds where a gateway must establish device identity before accepting data. Its standard-library implementation lowers setup friction for learning and makes the message flow easy to adapt to constrained clients."),
        P("Potential extensions include mutual authentication, certificate-based identity, per-device authorization policies, secure enrollment, key rotation, revocation lists, persistent clustered replay state, and integration with MQTT over verified TLS. Any extension should preserve the same principles: unique identity, protected credentials, cryptographic freshness, authenticated transport, and a clear lifecycle plan."),
    ])

    story += section("9. Conclusion", [
        P("This project demonstrates a practical device-authentication flow using a fresh challenge and an HMAC-SHA-256 proof. The server validates registered identities, consumes sessions once, and enforces a short expiry. The accompanying simulator provides a concrete way to inspect the protocol, while the report maps the implementation to system requirements and threat scenarios."),
        P("The prototype is suitable for coursework and local experimentation. Its most important deployment lesson is that a sound proof algorithm depends on sound key provisioning, protected storage, trusted transport, authorization, and lifecycle management. These controls must be added before adapting the demonstration for real IoT devices."),
    ])

    story += section("10. Referencee", [
        P("[1] National Institute of Standards and Technology, <i>Foundational Cybersecurity Activities for IoT Product Manufacturers</i>, NISTIR 8259 Rev. 1, 2026. Available: https://csrc.nist.gov/pubs/ir/8259/r1/final"),
        P("[2] H. Krawczyk, M. Bellare, and R. Canetti, <i>HMAC: Keyed-Hashing for Message Authentication</i>, RFC 2104, Internet Engineering Task Force, 1997. Available: https://www.rfc-editor.org/rfc/rfc2104"),
        P("[3] E. Rescorla, <i>The Transport Layer Security (TLS) Protocol Version 1.3</i>, RFC 8446, Internet Engineering Task Force, 2018. Available: https://www.rfc-editor.org/rfc/rfc8446"),
        P("[4] National Institute of Standards and Technology, <i>Digital Identity Guidelines: Authentication and Authenticator Management</i>, NIST SP 800-63B-4, 2025. Available: https://csrc.nist.gov/pubs/sp/800/63/B/4/final"),
    ])

    doc.multiBuild(story)
    print(OUTPUT)


if __name__ == "__main__":
    build()
