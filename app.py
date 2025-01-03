import os
from flask import Flask, request, render_template, redirect, flash, url_for

# Flask App Initialization
app = Flask(__name__)

# Secret key for session
app.secret_key = 'your_secret_key'

# Upload Configuration
UPLOAD_FOLDER = '/tmp/uploads/'  # Use Render-compatible writable folder
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure folder exists
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size: 16 MB

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        # Check if the POST request has the file part
        if 'file' not in request.files:
            flash('No file part in the request', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        
        # If no file is selected
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        # Save file to the upload folder
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        flash(f'File uploaded successfully: {file.filename}', 'success')
        return redirect('/')
    except Exception as e:
        # Log and handle any unexpected errors
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(request.url)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
