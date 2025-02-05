from flask import Flask, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename
import os
import json
import asyncio
from main import SecurityAnalyzer

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/template')
def get_template():
    return send_file('static/template.json',
                    mimetype='application/json',
                    as_attachment=True,
                    download_name='resources_template.json')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    if not file.filename.endswith('.json'):
        return jsonify({'error': 'Only JSON files are allowed'}), 400
        
    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze configuration
        analyzer = SecurityAnalyzer(filepath)
        report = asyncio.run(analyzer.analyze_resources())
        
        # Generate report file
        report_path = os.path.join(app.config['UPLOAD_FOLDER'], 'report.json')
        analyzer.save_report(report, report_path)
        
        return jsonify({
            'status': 'success',
            'report': report
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)