import os
import io
import eventlet
import sqlite3
import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_socketio import SocketIO, emit
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = '/home/admin/smart/uploads'  # Directory to store uploaded files
socketio = SocketIO(app)

# SQLite Database Setup
def create_db():
    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS uploaded_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        uploaded_by TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS screen_share_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        request_status TEXT NOT NULL DEFAULT 'pending',
        request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(student_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

create_db()

# User class for login
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)

# User loader for Flask-login
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[3])
    return None

# Google Drive API Setup
SCOPES = ['https://www.googleapis.com/auth/drive.file']

def create_drive_service():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    # Build the Drive service
    service = build('drive', 'v3', credentials=creds)
    return service

# Function to upload a file to Google Drive
def upload_file_to_drive(file_path, file_name, folder_id):
    service = create_drive_service()

    media = MediaFileUpload(file_path, mimetype='application/octet-stream')
    file_metadata = {
        'name': file_name,
        'parents': [folder_id]
    }

    file_drive = service.files().create(media_body=media, body=file_metadata).execute()
    return file_drive

# Folder ID where you want to store the files (Create folder manually or via API)
GOOGLE_DRIVE_FOLDER_ID = 'wireless'

# Route to handle file upload
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if current_user.role != 'student':
        return 'Only students can upload files.' 
    
    file = request.files['file']
    filename = file.filename
    file_path = os.path.join('/tmp', filename)  # Save file temporarily

    # Save the file temporarily
    file.save(file_path)

    try:
        # Upload to Google Drive
        uploaded_file = upload_file_to_drive(file_path, filename, GOOGLE_DRIVE_FOLDER_ID)
        
        # Save the file details in the database
        conn = sqlite3.connect('projector.db')
        c = conn.cursor()
        c.execute("INSERT INTO uploaded_files (filename, uploaded_by) VALUES (?, ?)", (filename, current_user.username))
        conn.commit()
        conn.close()

        flash(f'File "{filename}" uploaded successfully to Google Drive!')

        os.remove(file_path)  # Clean up the temporary file

    except Exception as e:
        flash(f'File upload failed: {e}')
        os.remove(file_path)  # Clean up the temporary file

    return redirect(url_for('dashboard'))

# Start socketio server
if __name__ == '__main__':
    socketio.run(app)
