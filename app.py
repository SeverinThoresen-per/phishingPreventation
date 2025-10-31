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
import csv

app = Flask(__name__)
CORS(app)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def load_tranco_domains(file_path='top-1m.csv'):
    domains = set()
    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if len(row) > 1:
                    domains.add(row[1].strip().lower())
        print(f"Loaded {len(domains)} domains from Tranco list ")
    except FileNotFoundError:
        print(f"ERROR: Could not find {file_path}. ")
    return domains

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

    #print(subject)
    #print(sender)
    #print(body)
    #print(ip)
    #print(urls)
    #print(msg.get("Return-Path"))
    #print(msg.get("Reply-To"))
    #print(msg.get("Date"))

    #The information below this barely works

    #print(msg.get_all("To", []))
    #print(msg.get_all("CC", []))

    save_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(save_path)

    return {
        "subject": subject,
        "from": sender,
        "to": recipients,
        "body": body,
        "ip" : ip,
        "urls": urls,
        "return path": msg.get("Return-Path"),
        "reply to": msg.get("Reply-To"),
        "date": msg.get("Date"),
    }

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