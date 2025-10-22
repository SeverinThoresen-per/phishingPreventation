from flask import Flask, render_template
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/submit_data', methods=['POST'])
def submit_data():
    data = request.get_json()
    if not data or 'data' not in data:
        return jsonify({'error': 'Invalid input'}), 400

    print(data)
    return jsonify({'message': 'Received', 'length': len(data["data"])})

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