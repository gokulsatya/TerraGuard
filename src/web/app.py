# src/web/app.py

from flask import Flask, render_template, request, flash, redirect, url_for
import os
from werkzeug.utils import secure_filename
from datetime import datetime

# Import our existing TerraGuard components
from ..main import analyze_terraform_file
from ..report.generator import ReportGenerator

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

# Configure upload settings
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'tf'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Render the main page"""
    # Get list of recent reports
    reports_dir = 'reports'
    reports = []
    if os.path.exists(reports_dir):
        reports = [f for f in os.listdir(reports_dir) if f.endswith('.html')]
        reports.sort(reverse=True)  # Most recent first
    return render_template('index.html', reports=reports)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and trigger security analysis"""
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        # Create upload directory if it doesn't exist
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Run security analysis
            analyze_terraform_file(filepath)
            flash('Analysis completed successfully!')
        except Exception as e:
            flash(f'Error during analysis: {str(e)}')
        
        # Clean up uploaded file
        os.remove(filepath)
        return redirect(url_for('index'))
    
    flash('Invalid file type. Please upload a .tf file.')
    return redirect(url_for('index'))

@app.route('/report/<filename>')
def view_report(filename):
    """Display a specific report"""
    report_path = os.path.join('reports', filename)
    if not os.path.exists(report_path):
        flash('Report not found')
        return redirect(url_for('index'))
    
    with open(report_path, 'r') as f:
        content = f.read()
    return render_template('report.html', content=content)

if __name__ == '__main__':
    app.run(debug=True)