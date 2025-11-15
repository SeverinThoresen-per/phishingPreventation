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

global fileCount
fileCount = 0
global phishingCount
phishingCount = 0
global mismatchedAddresses
mismatchedAddresses = 0
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

global a_s
a_s = 0
global a_c
a_c = 0
global a_k
a_k = 0
global a_sc
a_sc = 0
global a_sk
a_sk = 0
global a_ck
a_ck = 0
global a_sck
a_sck = 0

def get_from_domain(msg):
    from_addr = parseaddr(msg.get("From"))[1]
    return from_addr.split("@")[-1].lower()


def extract_spf_domain(auth_results):
    """
    Extract 'spf' domain from Authentication-Results header.
    Example: spf=pass smtp.mailfrom=gmail.com
    """
    m = re.search(r"smtp\.mailfrom=([^;\s]+)", auth_results)
    if m:
        return m.group(1).split("@")[-1].lower()
    return None


def extract_dkim_domain(auth_results):
    """
    Extract DKIM d= domain.
    Example: dkim=pass (good signature) header.d=google.com
    """
    m = re.search(r"header\.d=([^;\s]+)", auth_results)
    if m:
        return m.group(1).lower()
    return None


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
    global phishingCount, mismatchedAddresses, fileCount, s, c, k, sc, sk, ck, sck, a_s, a_c, a_k, a_sc, a_sk, a_ck, a_sck

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
    if "Phishing email" in judgement:
        phishingCount += 1
    if "Mismatched addresses" in judgement:
        mismatchedAddresses += 1
    if "Failed spf" in judgement and "Failed dmarc" in judgement and "Failed dkim" in judgement:
        sck += 1
    elif "Failed spf" in judgement and "Failed dmarc" in judgement:
        sc += 1
    elif "Failed spf" in judgement and "Failed dkim" in judgement:
        sk += 1
    elif "Failed dkim" in judgement and "Failed dmarc" in judgement:
        ck += 1
    elif "Failed spf" in judgement:
        s += 1
    elif "Failed dmarc" in judgement:
        c += 1
    elif "Failed dkim" in judgement:
        k += 1

    elif "spf not aligned" in judgement and "dmarc not aligned" in judgement and "dkim not aligned" in judgement:
        a_sck += 1
    elif "spf not aligned" in judgement and "dmarc not aligned" in judgement:
        a_sc += 1
    elif "spf not aligned" in judgement and "dkim not aligned" in judgement:
        a_sk += 1
    elif "dkim not aligned" in judgement and "dmarc not aligned" in judgement:
        a_ck += 1
    elif "spf not aligned" in judgement:
        a_s += 1
    elif "dmarc not aligned" in judgement:
        a_c += 1
    elif "dkim not aligned" in judgement:
        a_k += 1

def judge(msg, bytes):
    redFlags = []
    auth = msg.get("Authentication-Results", "")
    from_domain = get_from_domain(msg)
    spf_domain = extract_spf_domain(auth)
    dkim_domain = extract_dkim_domain(auth)

    for url in extract_urls(str(msg)):
        if scan_url(url) == True:
            redFlags.append("Phishing email")
    if "spf" not in auth and "dkim" not in auth and "dmarc" not in auth:
        redFlags.append("Old email")
    elif msg['from'] != msg['to']:
        if "spf=pass" not in auth:
            redFlags.append("Failed spf")
        else:
            if not aligned(from_domain, spf_domain):
                redFlags.append("spf not aligned")
        if "dmarc=pass" not in auth:
            redFlags.append("Failed dmarc")
        else:
            if not aligned(from_domain, spf_domain):
                redFlags.append("dmarc not aligned")
        if "dkim=pass" not in auth:
            redFlags.append("Failed dkim")
        else:
            if not aligned(from_domain, spf_domain):
                redFlags.append("dkim not aligned")

    reply_to = msg.get("Reply-To")
    if reply_to:
        from_addr = parseaddr(msg.get("From"))[1].split('@')[-1]
        reply_addr = parseaddr(reply_to)[1].split('@')[-1]
        if from_addr != reply_addr:
            redFlags.append("Reply-to mismatch")

    try:
        html = msg.get_body(preferencelist=('html'))
        if html:
            soup = BeautifulSoup(html.get_content(), 'html.parser')
            for a in soup.find_all("a", href=True):
                link_text = a.get_text().strip()
                link_url = a['href']
                
                if link_text and link_url and link_text != link_url:
                    redFlags.append("Link mismatch")
                    break
    except Exception:
        pass
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

for file in os.listdir(".severin"):
    file_path = os.path.join(".severin", file)
    try:
        if(fileCount % 100 == 0):
            print(fileCount)
        upload_eml(file_path)
    except Exception as e:
        print(f"[SKIP] Error processing {file}: {e}")
        continue

print(str(fileCount) + " tested files")
print(str(phishingCount) + " known phishing urls spotted")
print(str(mismatchedAddresses) + " mismatched addresses")

print(str(s) + " spf misaligned")
print(str(k) + " dkim misaligned")
print(str(c) + " dmarc misaligned")
print(str(sc) + " misaligned spf and dmarc")
print(str(sk) + " misaligned spf and dkim")
print(str(ck) + " misaligned dkim and dmarc")
print(str(sck) + " misaligned everything")

print(str(s) + " only failed spf")
print(str(k) + " only failed dkim")
print(str(c) + " only failed dmarc")
print(str(sc) + " failed spf and dmarc")
print(str(sk) + " failed spf and dkim")
print(str(ck) + " failed dkim and dmarc")
print(str(sck) + " failed everything")