from flask import Flask, render_template
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/api/data', methods=['POST'])
def receive_data():
    data = request.get_json()
    print("Received:", data)

    return jsonify({
        "status": data
    })

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