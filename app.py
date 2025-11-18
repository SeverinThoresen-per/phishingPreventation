from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
from flask_cors import CORS
import os
from email import policy
from email.parser import BytesParser
import re
import ipaddress
import sys, re, email, ipaddress
from email.headerregistry import AddressHeader
from email.utils import getaddresses
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import csv
import dkim

app = Flask(__name__)
CORS(app)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def load_phish_urls(filepath="recentPhishUrls.csv"):
    with open(filepath) as f:
        return set(line.strip().lower() for line in f)
    
PHISH_URLS = load_phish_urls()

def load_tranco_domains(file_path='top-1m.csv', limit=10000):
    domains = set()
    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            for i, row in enumerate(reader):
                if len(row) > 1:
                    domains.add(row[1].strip().lower())
                if i + 1 >= limit:  
                    csvfile.close()
                    break
        print(f"[INFO] Loaded {len(domains)} domains from Tranco list.")
    except FileNotFoundError:
        print(f"[ERROR] Could not find {file_path}.")
    return domains

TRONCO_DOMAINS = load_tranco_domains(limit=10000)

@app.route('/upload', methods=['POST'])
def upload_eml():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    
    file_bytes = file.read()
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)

    subject = msg['subject']
    sender = msg['from']
    recipients = msg['to']
    body = get_body(msg)
    ip = get_ip(msg)
    urls = extract_urls(str(msg))
    domains = extract_domains(str(msg))
    suspicious_domains = [d for d in domains if d.lower() not in TRONCO_DOMAINS]

    judgement = judge(msg, file_bytes, urls, suspicious_domains)

    points = 0
    if "Phishing email" in judgement:
        points += 100
    if "Mismatched addresses" in judgement:
        points += 10
    if "Failed spf" in judgement:
        points += 30
    if "Failed dmarc" in judgement:
        points += 30
    if "Failed dkim" in judgement:
        points += 30
    if len(suspicious_domains) > 0:
        points += 20 + (10 * len(suspicious_domains))
    if points >= 100:
        print("///// Judgement /////")
        print(judgement)
        print("Score:", points)
        print("Probably phishing")
        print("/////////////////////")
    else:
        print("///// Judgement /////")
        print(judgement)
        print("Score:", points)
        print("Probably not phishing")
        print("/////////////////////")

    print(msg.get("Authentication-Results", ""))


    with open(os.path.join(UPLOAD_FOLDER, file.filename), 'wb') as f:
        f.write(file_bytes)

    return {
        "subject": subject,
        "from": sender,
        "to": recipients,
        "body": body,
        "ip" : ip,
        "urls": urls,
        "domains": domains,
        "suspicious_domains": suspicious_domains,
        "return path": msg.get("Return-Path"),
        "reply to": msg.get("Reply-To"),
        "date": msg.get("Date"),
        "judgement": judgement
    }

def judge(msg, bytes, urls, suspicious_domains):
    redFlags = []
    auth = msg.get("Authentication-Results", "")
    for url in urls:
        if scan_url(url) == True:
            redFlags.append("Phishing email")
    if msg.get('from') != msg.get("Return-Path") and msg.get('from') != msg.get("Reply-To"):
        redFlags.append("Mismatched addresses")
    if "spf" not in auth and "dkim" not in auth and "dmarc" not in auth:
        redFlags.append("Old email")
    if dkim.verify(bytes) == False:
        redFlags.append("bad dkim")
    elif msg['from'] != msg['to']:
        if "spf=pass" not in auth:
            redFlags.append("Failed spf")
        if "dmarc=pass" not in auth:
            redFlags.append("Failed dmarc")
        if "dkim=pass" not in auth:
            redFlags.append("Failed dkim")
    if len(suspicious_domains) > 0:
        redFlags.append("Unknown domain")
    return redFlags

def scan_url(url, filepath="recentPhishUrls.csv"):
    with open(filepath) as f:
        for line in f:
            if url[5:] in line:
                f.close()
                return True
    f.close()
    return False

def get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                return part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
    else:
        return msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')
        
        
    return ""

def get_ip(msg):
    received_headers = msg.get_all('Received', [])
    if not received_headers:
        return None
    
    for header in reversed(received_headers):
        tokens = header.replace("(", " ").replace(")", " ").split()
        for token in tokens:
            token = token.strip("[];,")
            try:
                ip = ipaddress.ip_address(token)
                if not (ip.is_private or ip.is_loopback or ip.is_reserved):
                    return str(ip)
            except ValueError:
                continue
    return None


def extract_urls(text):
    if not text:
        return []
    url_pattern = re.compile(
        r'https?://[^\s<>"]+'
    )
    urls = url_pattern.findall(text)
    cleaned_urls = set(url.rstrip(".,);:!\"'") for url in urls)
    
    return list(cleaned_urls)


def extract_domains(text):
    if not text:
        return []
    url_pattern = re.compile(r'https?://[^\s<>"]+')
    urls = url_pattern.findall(text)
    domains = []
    seen = set()
    for url in urls:
        domain = urlparse(url).netloc.rstrip(".,);:!\"'")
        if domain not in seen:
            seen.add(domain)
            domains.append(domain)

    return domains



@app.route('/')
def start():
    return render_template('Index.html')

@app.route('/Index.html')
def home():
    return render_template('Index.html')

@app.route('/downloadGuide.html')
def about():
    return render_template('downloadGuide.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)