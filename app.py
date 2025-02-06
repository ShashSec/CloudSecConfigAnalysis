from flask import Flask, render_template, request, send_file, jsonify, Response, stream_with_context
from quart import Quart, websocket
from werkzeug.utils import secure_filename
import os
import json
import asyncio
from main import SecurityAnalyzer
import logging


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Use event loop for async operations
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

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
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        openai_api_key = request.form.get('openai_api_key')
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        if not file.filename.endswith('.json'):
            return jsonify({'error': 'Only JSON files are allowed'}), 400

        # Validate OpenAI API key if provided
        if openai_api_key and not openai_api_key.startswith('sk-'):
            return jsonify({'error': 'Invalid OpenAI API key format'}), 400
            
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze configuration
        analyzer = SecurityAnalyzer(filepath, openai_api_key)
        report = asyncio.run(analyzer.analyze_resources())
        
        # Generate report file
        report_path = os.path.join(app.config['UPLOAD_FOLDER'], 'report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return jsonify({
            'status': 'success',
            'report': report
        })
        
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON file'}), 400
    except Exception as e:
        app.logger.error(f"Error processing upload: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
    finally:
        # Cleanup temporary files
        try:
            if 'filepath' in locals():
                os.remove(filepath)
        except Exception as e:
            app.logger.error(f"Error cleaning up files: {str(e)}")

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        openai_api_key = request.form.get('openai_api_key')
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        if not file.filename.endswith('.json'):
            return jsonify({'error': 'Only JSON files are allowed'}), 400

        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Initialize analyzer
        analyzer = SecurityAnalyzer(filepath, openai_api_key)
        
        # Run analysis in event loop
        report = loop.run_until_complete(analyzer.analyze_resources())

        # Clean up
        if os.path.exists(filepath):
            os.remove(filepath)

        return jsonify({
            'status': 'success',
            'report': report
        })

    except Exception as e:
        logger.error(f"Error processing upload: {e}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)