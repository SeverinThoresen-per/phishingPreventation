from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
from flask_cors import CORS
import os
from email import policy
from email.parser import BytesParser

app = Flask(__name__)
CORS(app)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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

    print(subject)
    print(sender)
    print(body)

    save_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(save_path)

    return {
        "subject": subject,
        "from": sender,
        "to": recipients,
        "body": body
    }

def get_body(msg):
    """Extract the plain text body of an email."""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                return part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
    else:
        return msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')
    return ""

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