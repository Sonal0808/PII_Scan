import streamlit as st
import fitz  # PyMuPDF
import tempfile
import os
import re
from docx import Document
from io import BytesIO
import email
from email import policy
from email.parser import BytesParser
import extract_msg
import pandas as pd
import xml.etree.ElementTree as ET

# ------------------------------
# PII regex patterns (common structured info)
PII_PATTERNS = {
    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Phone": r"\+?\d[\d\s\-()]{8,}\d",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "DOB": r"\b(?:0?[1-9]|[12][0-9]|3[01])[- /.](?:0?[1-9]|1[012])[- /.](?:19|20)?\d{2}\b",
    "ZIP Code": r"\b\d{5}(-\d{4})?\b",
    "Driver License": r"\b[A-Z]{1,2}\d{4,9}\b",
    "Passport": r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b",
}

# Simple full name detection using capitalization heuristics (very naive)
def find_names(text):
    return re.findall(r"\b([A-Z][a-z]+(?: [A-Z][a-z]+)+)\b", text)

# Hardcoded keywords for some PII types
KEYWORD_PII = {
    "Gender": [r"\b(Male|Female|Other|Man|Woman|Non-binary|Transgender)\b"],
    "Race": [r"\b(Asian|Black|White|Hispanic|Latino|Native American|Caucasian)\b"],
    "Religion": [r"\b(Christian|Muslim|Jewish|Hindu|Buddhist|Atheist|Agnostic)\b"],
    "Medical": [r"\b(Diabetes|Cancer|HIV|AIDS|Asthma|Depression|Blood Pressure)\b"],
    "Place of Birth": [r"\b(New York|London|Paris|Delhi|Tokyo|Sydney|Toronto)\b"],
}

# ------------------------------
# Function to redact PII in PDFs using PyMuPDF
def redact_pdf(input_path):
    doc = fitz.open(input_path)
    for page in doc:
        text = page.get_text("text")
        names = find_names(text)
        all_pii = []
        for label, pattern in PII_PATTERNS.items():
            all_pii.extend([(label, m.group()) for m in re.finditer(pattern, text)])
        for label, patterns in KEYWORD_PII.items():
            for p in patterns:
                all_pii.extend([(label, m.group()) for m in re.finditer(p, text, flags=re.IGNORECASE)])
        for name in names:
            all_pii.append(("Full Name", name))

        for label, pii_text in all_pii:
            areas = page.search_for(pii_text)
            for area in areas:
                page.add_redact_annot(area, fill=(0, 0, 0))

        page.apply_redactions()

    out_path = input_path.replace(".pdf", "_redacted.pdf")
    doc.save(out_path)
    doc.close()
    return out_path

# ------------------------------
# Redact text files and return redacted text
def redact_text(text):
    names = find_names(text)
    for label, pattern in PII_PATTERNS.items():
        text = re.sub(pattern, f"[REDACTED {label}]", text)
    for label, patterns in KEYWORD_PII.items():
        for p in patterns:
            text = re.sub(p, f"[REDACTED {label}]", text, flags=re.IGNORECASE)
    for name in names:
        text = text.replace(name, "[REDACTED Full Name]")
    return text

# ------------------------------
# Redact DOCX files similarly and return bytes
def redact_docx(file_bytes):
    doc = Document(BytesIO(file_bytes))
    for para in doc.paragraphs:
        para.text = redact_text(para.text)
    out_stream = BytesIO()
    doc.save(out_stream)
    return out_stream.getvalue()

# ------------------------------
# Redact .eml files
def redact_eml(file_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
    
    # Redact subject
    subject = msg['subject'] or ""
    redacted_subject = redact_text(subject)
    if 'subject' in msg:
        msg.replace_header('subject', redacted_subject)
    else:
        msg['subject'] = redacted_subject

    # Redact body (assuming plain text part)
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body = part.get_content()
                redacted_body = redact_text(body)
                part.set_content(redacted_body)
    else:
        body = msg.get_content()
        redacted_body = redact_text(body)
        msg.set_content(redacted_body)
    
    return msg.as_bytes()

# ------------------------------
# Redact .msg files (Outlook)
def redact_msg_file(file_path):
    msg = extract_msg.Message(file_path)
    msg_message = msg.body or ""
    redacted_body = redact_text(msg_message)

    # Redact subject
    subject = msg.subject or ""
    redacted_subject = redact_text(subject)

    # Create a simple redacted text output for .msg since editing binary .msg is complex
    combined = f"Subject: {redacted_subject}\n\n{redacted_body}"
    return combined.encode('utf-8')

# ------------------------------
# Redact Excel (xls, xlsx) - redact all cell contents
def redact_excel(file_path):
    df = pd.read_excel(file_path, dtype=str)  # Read as strings
    for col in df.columns:
        df[col] = df[col].astype(str).apply(redact_text)
    out_stream = BytesIO()
    with pd.ExcelWriter(out_stream, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    return out_stream.getvalue()

# ------------------------------
# Redact XML files by parsing and redacting text nodes
def redact_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    def redact_element(element):
        if element.text:
            element.text = redact_text(element.text)
        for child in element:
            redact_element(child)

    redact_element(root)

    out_stream = BytesIO()
    tree.write(out_stream, encoding='utf-8', xml_declaration=True)
    return out_stream.getvalue()

# ------------------------------
# Streamlit UI
st.title("PII Scan")

st.write("""
Upload files (PDF, TXT, DOCX, EML, MSG, XLS, XLSX, XML) to detect and mask PII 
(emails, phones, Passport, credit cards, DOB, names, gender, race, religion, medical info, addresses, and more).
""")

uploaded_file = st.file_uploader("Upload your file", type=["pdf", "txt", "docx", "eml", "msg", "xls", "xlsx", "xml"])

if uploaded_file is not None:
    file_details = {"filename": uploaded_file.name, "filetype": uploaded_file.type}
    st.write(f"File uploaded: {file_details['filename']}")

    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_path = tmp_file.name

    ext = file_details["filename"].split(".")[-1].lower()

    if ext == "pdf":
        st.info("Processing PDF...")
        output_path = redact_pdf(tmp_path)
        with open(output_path, "rb") as f:
            st.success("✅ PDF redacted!")
            st.download_button("Download redacted PDF", f, file_name="redacted_" + file_details["filename"], mime="application/pdf")
        os.remove(output_path)

    elif ext == "txt":
        st.info("Processing TXT...")
        with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        redacted_text = redact_text(content)
        st.text_area("Redacted Text", redacted_text, height=400)
        st.download_button("Download redacted TXT", redacted_text, file_name="redacted_" + file_details["filename"], mime="text/plain")

    elif ext == "docx":
        st.info("Processing DOCX...")
        with open(tmp_path, "rb") as f:
            file_bytes = f.read()
        redacted_bytes = redact_docx(file_bytes)
        st.success("✅ DOCX redacted!")
        st.download_button("Download redacted DOCX", redacted_bytes, file_name="redacted_" + file_details["filename"], mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document")

    elif ext == "eml":
        st.info("Processing EML...")
        with open(tmp_path, "rb") as f:
            file_bytes = f.read()
        redacted_eml_bytes = redact_eml(file_bytes)
        st.success("✅ EML redacted!")
        st.download_button("Download redacted EML", redacted_eml_bytes, file_name="redacted_" + file_details["filename"], mime="message/rfc822")

    elif ext == "msg":
        st.info("Processing MSG...")
        redacted_msg_bytes = redact_msg_file(tmp_path)
        st.success("✅ MSG redacted!")
        st.download_button("Download redacted MSG (as text)", redacted_msg_bytes, file_name="redacted_" + file_details["filename"], mime="text/plain")

    elif ext in ["xls", "xlsx"]:
        st.info("Processing Excel file...")
        redacted_excel_bytes = redact_excel(tmp_path)
        st.success("✅ Excel redacted!")
        st.download_button("Download redacted Excel", redacted_excel_bytes, file_name="redacted_" + file_details["filename"], mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    elif ext == "xml":
        st.info("Processing XML file...")
        redacted_xml_bytes = redact_xml(tmp_path)
        st.success("✅ XML redacted!")
        st.download_button("Download redacted XML", redacted_xml_bytes, file_name="redacted_" + file_details["filename"], mime="application/xml")

    else:
        st.error("Unsupported file type.")

    os.remove(tmp_path)