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
from email.utils import parseaddr
import requests

global fileCount
fileCount = 0
global phishingCount
phishingCount = 0
global s
s = 0
global c
c = 0
global k
k = 0
global sc
sc = 0
global sk
sk = 0
global ck
ck = 0
global sck
sck = 0
global count
count = 0
global headerMismatches
headerMismatches = 0

def get_from_domain(msg):
    from_addr = parseaddr(msg.get("From"))[1]
    return from_addr.split("@")[-1].lower()

def aligned(org1, org2):
    """Relaxed alignment: same organizational domain."""
    if not org1 or not org2:
        return False
    return org1.split(".")[-2:] == org2.split(".")[-2:]

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

def upload_eml(file_path):
    global phishingCount, fileCount, s, c, k, sc, sk, ck, sck, headerMismatches, count

    try:
        with open(file_path, 'rb') as f:
            file_bytes = f.read()
            msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
    except Exception as e:
        print(f"[ERROR] Failed to parse {file_path}: {e}")
        return  # Skip this file

    try:
        judgement = judge(msg, file_bytes)
    except Exception as e:
        print(f"[ERROR] Failed to judge {file_path}: {e}")
        return
    fileCount += 1
    points = 0
    if "Phishing email" in judgement:
        phishingCount += 1
        points += 100
    if headerMismatch(msg):
        headerMismatches += 1
    if "Failed spf" in judgement and "Failed dmarc" in judgement and "Failed dkim" in judgement:
        sck += 1
        points += 100
    elif "Failed spf" in judgement and "Failed dmarc" in judgement:
        sc += 1
        points += 100
    elif "Failed spf" in judgement and "Failed dkim" in judgement:
        sk += 1
        points += 100
    elif "Failed dkim" in judgement and "Failed dmarc" in judgement:
        ck += 1
        points += 100
    elif "Failed spf" in judgement:
        s += 1
        points += 100
    elif "Failed dmarc" in judgement:
        c += 1
        points += 100
    elif "Failed dkim" in judgement:
        k += 1
        points += 100
    if (points >= 100):
        count += 1

def headerMismatch(msg):
    from_addr = parseaddr(msg.get("From"))[1]
    reply_to = parseaddr(msg.get("Reply-To") or "")[1]
    return from_addr != reply_to

def judge(msg, bytes):
    redFlags = []
    auth = msg.get("Authentication-Results", "")

    for url in extract_urls(str(msg)):
        if scan_url(url) == True:
            print("Got one at " + str(fileCount))
            redFlags.append("Phishing email")
    if "spf" not in auth and "dkim" not in auth and "dmarc" not in auth:
        redFlags.append("Old email")
    elif msg['from'] != msg['to']:
        if "spf=pass" not in auth:
            redFlags.append("Failed spf")
        if "dmarc=pass" not in auth:
            redFlags.append("Failed dmarc")
        if "dkim=pass" not in auth:
            redFlags.append("Failed dkim")
    return redFlags

def scan_url(url, filepath="recentPhishUrls.csv"):
    return url[5:] in PHISH_URLS

def get_body(msg):
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        return part.get_payload(decode=True).decode(
                            part.get_content_charset() or 'utf-8',
                            errors='replace'
                        )
                    except Exception:
                        continue
        else:
            return msg.get_payload(decode=True).decode(
                msg.get_content_charset() or 'utf-8',
                errors='replace'
            )
    except Exception:
        return ""
    return ""

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

filePath = "phishingEmails"

for file in os.listdir(filePath):
    file_path = os.path.join(filePath, file)
    try:
        if(fileCount % 100 == 0):
            print(fileCount)
        upload_eml(file_path)
    except Exception as e:
        print(f"[SKIP] Error processing {file}: {e}")
        continue

print(str(fileCount) + " tested files")
print(str(phishingCount) + " known phishing urls spotted")
print(str(headerMismatches) + " header mismatches")
print(str(s) + " only failed spf")
print(str(k) + " only failed dkim")
print(str(c) + " only failed dmarc")
print(str(sc) + " failed spf and dmarc")
print(str(sk) + " failed spf and dkim")
print(str(ck) + " failed dkim and dmarc")
print(str(sck) + " failed everything")
print("/////////////////////////////////////////")
print(str(count) + " out of " + str(fileCount) + " is predicted phishing")
print("/////////////////////////////////////////")
