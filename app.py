import os
import logging
import eventlet
import pickle
from eventlet import wsgi
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_socketio import SocketIO, emit
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.http import MediaFileUpload
import sqlite3
import hashlib
import subprocess

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = '/home/admin/smart/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Enable logging for debugging
logging.basicConfig(level=logging.DEBUG)

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
        uploaded_by TEXT NOT NULL,
        drive_file_id TEXT NOT NULL
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        conn = sqlite3.connect('projector.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user_data = c.fetchone()

        if user_data:
            flash('Username already exists! Please choose a different one.')
            return redirect(url_for('register'))

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
        conn.commit()
        conn.close()

        flash('Account created successfully! You can now log in.')
        return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    logging.debug(f"Attempting login for user: {username}")

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
    user_data = c.fetchone()
    conn.close()

    if user_data:
        logging.debug(f"User found: {user_data}")
        user = User(user_data[0], user_data[1], user_data[3])
        login_user(user)
        logging.debug(f"User {username} logged in successfully.")
        return redirect(url_for('dashboard'))
    else:
        logging.warning(f"Login failed for user: {username}")
        flash('Login failed. Please try again.')
        return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        logging.debug(f"Rendering dashboard for user: {current_user.username}, Role: {current_user.role}")
        if current_user.role == 'teacher':
            return render_template('teacher_dashboard.html')
        else:
            return render_template('student_dashboard.html')
    except Exception as e:
        logging.error(f"Error rendering dashboard: {str(e)}")
        flash('An error occurred while loading the dashboard.')
        return redirect(url_for('index'))

def authenticate_google_drive():
    creds = None
    try:
        if os.path.exists('token.json'):
            with open('token.json', 'rb') as token:
                creds = pickle.load(token)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json',
                    ['https://www.googleapis.com/auth/drive.file']
                )
                creds = flow.run_local_server(port=0)
            with open('token.json', 'wb') as token:
                pickle.dump(creds, token)
    except Exception as e:
        logging.error(f"Error authenticating Google Drive: {e}")
        flash("Failed to authenticate Google Drive. Please check your credentials.")
    return creds

# Function to upload file to Google Drive
def upload_to_google_drive(file):
    creds = authenticate_google_drive()

    if creds:
        try:
            drive_service = build('drive', 'v3', credentials=creds)
            file_metadata = {'name': file.filename}
            media = MediaFileUpload(file, mimetype='application/octet-stream')

            # Upload the file
            file_drive = drive_service.files().create(
                body=file_metadata, media_body=media, fields='id').execute()

            return file_drive['id']
        except Exception as e:
            logging.error(f"Failed to upload file to Google Drive: {str(e)}")
            flash(f'Failed to upload file to Google Drive: {str(e)}')
            return None
    return None

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if current_user.role != 'student':
        return 'Only students can upload files.'

    if 'file' not in request.files:
        flash('No file part in the request.')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.')
        return redirect(url_for('dashboard'))

    try:
        file_drive_id = upload_to_google_drive(file)

        if file_drive_id:
            conn = sqlite3.connect('projector.db')
            c = conn.cursor()
            c.execute("INSERT INTO uploaded_files (filename, uploaded_by, drive_file_id) VALUES (?, ?, ?)",
                      (file.filename, current_user.username, file_drive_id))
            conn.commit()
            conn.close()

            flash('File uploaded successfully to Google Drive!')
        else:
            flash('Failed to upload the file to Google Drive.')
    except Exception as e:
        logging.error(f'File upload failed: {str(e)}')
        flash(f'File upload failed: {str(e)}')

    return redirect(url_for('dashboard'))

@app.route('/approve_screen_share/<int:request_id>', methods=['POST'])
@login_required
def approve_screen_share(request_id):
    if current_user.role != 'teacher':
        return "Access Denied", 403

    conn = sqlite3.connect('projector.db')
    c = conn.cursor()

    try:
        c.execute("UPDATE screen_share_requests SET request_status = 'approved' WHERE id = ?", (request_id,))
        conn.commit()

        c.execute("SELECT student_id FROM screen_share_requests WHERE id = ?", (request_id,))
        student_data = c.fetchone()

        if student_data:
            student_id = student_data[0]
            socketio.emit('screen_share_approved', {'student_id': student_id}, broadcast=True)
            flash('Screen sharing session approved.')
        else:
            flash('No student found for this request.')
    except Exception as e:
        logging.error(f"Error approving screen sharing: {e}")
        flash(f"Error approving screen sharing: {e}")
    finally:
        conn.close()

    return redirect(url_for('view_screen_share_requests'))

@socketio.on('offer')
def handle_offer(data):
    emit('offer', data, broadcast=True)

@socketio.on('answer')
def handle_answer(data):
    emit('answer', data, broadcast=True)

@socketio.on('candidate')
def handle_candidate(data):
    emit('candidate', data, broadcast=True)

@socketio.on('start_screen_share')
def handle_start_screen_share(data):
    socketio.emit('open_view_screen', {'message': 'Screen sharing started!'})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
