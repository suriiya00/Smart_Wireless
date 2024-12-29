import os
import ssl
import eventlet
import eventlet.green.ssl as ssl
from eventlet import wsgi
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_socketio import SocketIO, emit
import sqlite3
import hashlib
import subprocess


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

# Route for login page
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Check if username already exists
        conn = sqlite3.connect('projector.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user_data = c.fetchone()

        if user_data:
            flash('Username already exists! Please choose a different one.')
            return redirect(url_for('register'))

        # Hash the password before storing it
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Insert new user into the database
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
        conn.commit()
        conn.close()

        flash('Account created successfully! You can now log in.')
        return redirect(url_for('index'))

    return render_template('register.html')

# Login handler
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Hash the input password and check against the stored hashed password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        user = User(user_data[0], user_data[1], user_data[3])
        login_user(user)
        return redirect(url_for('dashboard'))
    flash('Login failed. Please try again.')
    return redirect(url_for('index'))

# Dashboard route (teacher or student)
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'teacher':
        return render_template('teacher_dashboard.html')
    else:
        return render_template('student_dashboard.html')

# File upload handler
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if current_user.role != 'student':
        return 'Only students can upload files.'
    
    file = request.files['file']
    filename = file.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("INSERT INTO uploaded_files (filename, uploaded_by) VALUES (?, ?)", (filename, current_user.username))
    conn.commit()
    conn.close()

    return 'File uploaded successfully!'

# Presentation Control Handlers
@app.route('/next')
def next_slide():
    # Handle next slide
    return 'Next slide'

@app.route('/prev')
def prev_slide():
    # Handle previous slide
    return 'Previous slide'

@app.route('/pause')
def pause_presentation():
    # Handle pause
    return 'Presentation paused'

@app.route('/resume')
def resume_presentation():
    # Handle resume
    return 'Presentation resumed'

@app.route('/control')
@login_required
def control_page():
    return render_template('control.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Admin Routes for Teachers
@app.route('/admin/users')
@login_required
def view_users():
    if current_user.role not in ['teacher', 'admin']:
        return "Access Denied", 403  # Restrict access to teachers/admins only
    
    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users")  # Fetch user details
    users = c.fetchall()
    conn.close()

    return render_template('view_users.html', users=users)

@app.route('/admin/files')
@login_required
def view_files():
    if current_user.role not in ['teacher', 'admin']:
        return "Access Denied", 403  # Restrict access to teachers/admins only
    
    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("SELECT id, filename, uploaded_by FROM uploaded_files")  # Fetch file details
    files = c.fetchall()
    conn.close()

    return render_template('view_files.html', files=files)

@app.route('/view_screen_share_requests')
@login_required
def view_screen_share_requests():
    if current_user.role != 'teacher':
        return "Access Denied", 403  # Only teachers can view requests

    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    # Fetch pending screen-sharing requests
    c.execute("SELECT r.id, u.username, r.request_time FROM screen_share_requests r JOIN users u ON r.student_id = u.id WHERE r.request_status = 'pending'")
    requests = c.fetchall()
    conn.close()

    return render_template('teacher_dashboard.html', requests=requests)


@app.route('/request_screen_share', methods=['POST'])
@login_required
def request_screen_share():
    if current_user.role != 'student':
        return "Access Denied", 403
    conn = sqlite3.connect('projector.db')
    c = conn.cursor()

    # Check if a pending request already exists for this student
    c.execute("SELECT * FROM screen_share_requests WHERE student_id = ? AND request_status = 'pending'", (current_user.id,))
    existing_request = c.fetchone()

    if existing_request:
        flash("You already have a pending screen-sharing request.")
        return redirect(url_for('dashboard'))

    c.execute("INSERT INTO screen_share_requests (student_id) VALUES (?)", (current_user.id,))
    conn.commit()
    conn.close()
    flash('Screen sharing request sent to teacher.')
    return redirect(url_for('dashboard'))

@app.route('/approve_screen_share/<int:request_id>', methods=['POST'])
@login_required
def approve_screen_share(request_id):
    if current_user.role != 'teacher':
        return "Access Denied", 403

    conn = sqlite3.connect('projector.db')
    c = conn.cursor()

    # Approve the request
    c.execute("UPDATE screen_share_requests SET request_status = 'approved' WHERE id = ?", (request_id,))
    conn.commit()

    # Notify the student via WebSocket
    c.execute("SELECT student_id FROM screen_share_requests WHERE id = ?", (request_id,))
    student_id = c.fetchone()[0]
    conn.close()

    socketio.emit('screen_share_approved', {'student_id': student_id})
    flash('Screen sharing session approved.')
    return redirect(url_for('view_screen_share_requests'))




@app.route('/deny_screen_share/<int:request_id>', methods=['POST'])
@login_required
def deny_screen_share(request_id):
    if current_user.role != 'teacher':
        return "Access Denied", 403

    conn = sqlite3.connect('projector.db')
    c = conn.cursor()

    # Deny the request
    c.execute("UPDATE screen_share_requests SET request_status = 'denied' WHERE id = ?", (request_id,))
    conn.commit()
    conn.close()

    flash('Screen sharing request denied.')
    return redirect(url_for('view_screen_share_requests'))

    
@app.route('/end_screen_share/<int:request_id>', methods=['POST'])
@login_required
def end_screen_share(request_id):
    if current_user.role != 'teacher':
        return "Access Denied", 403

    conn = sqlite3.connect('projector.db')
    c = conn.cursor()

    # Mark the request as completed
    c.execute("UPDATE screen_share_requests SET request_status = 'completed' WHERE id = ?", (request_id,))
    conn.commit()
    conn.close()

    flash('Screen sharing session completed.')
    return redirect(url_for('view_screen_share_requests'))

# Screen Share Start for Student
@app.route('/screen_share')
@login_required
def screen_share():
    if current_user.role != 'student':
        return "Access Denied", 403  # Only students can start screen sharing

    return render_template('screen_share.html')  # Template for WebRTC screen sharing

@app.route('/test_approval/<int:student_id>')
def test_approval(student_id):
    socketio.emit('screen_share_approved', {'student_id': student_id}, broadcast=True)
    return f"Test approval event emitted for student ID: {student_id}"

@app.route('/view_screen')
def view_screen():
    return render_template('view_screen.html')



# WebRTC signaling for screen sharing
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
    print("Broadcasting open_view_screen event to all clients.")
    # Emit the 'open_view_screen' event to all connected clients
    socketio.emit('open_view_screen', {'message': 'Screen sharing started!'})


 
# Create an SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
# Load the certificate and key from environment variables
cert = os.getenv('SSL_CERTIFICATE')
key = os.getenv('SSL_KEY')

# Ensure the environment variables are loaded
if cert is None or key is None:
    raise ValueError("SSL certificate or key not found in environment variables.")

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=cert, keyfile=key)

# Setup eventlet listener
listener = eventlet.listen(('0.0.0.0', 5000))

# Wrap the listener with SSL
listener = context.wrap_socket(listener, server_side=True)

# Run the WSGI server with SSL
if __name__ == '__main__':
    wsgi.server(listener, app)
