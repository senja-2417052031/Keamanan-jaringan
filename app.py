from flask import Flask, render_template, request, redirect, url_for, session, send_file
from werkzeug.utils import secure_filename
from PIL import Image
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import os, io, sqlite3, hashlib, pyotp, qrcode

app = Flask(__name__)
app.secret_key = 'digitalsign_secret_key'

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        otp_secret TEXT,
        signature_path TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        signed_filename TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    try:
        hashed = hashlib.sha256('password123'.encode()).hexdigest()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('testuser', hashed))
    except:
        pass
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    return user

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('home.html', username=session['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        user = get_user(username)
        if user and user[2] == password:
            session['username'] = username
            session['user_id'] = user[0]
            return redirect(url_for('home'))
        error = 'Username atau password salah!'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/setup_otp')
def setup_otp():
    if 'username' not in session:
        return redirect(url_for('login'))
    secret = pyotp.random_base32()
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("UPDATE users SET otp_secret=? WHERE username=?", (secret, session['username']))
    conn.commit()
    conn.close()
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(session['username'], issuer_name="DigiSign SI")
    qr = qrcode.make(otp_uri)
    qr_path = f"static/uploads/{session['username']}_qr.png"
    qr.save(qr_path)
    return render_template('setup_otp.html', qr_path=qr_path, secret=secret)

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    if 'username' not in session:
        return redirect(url_for('login'))
    otp_input = request.form['otp']
    user = get_user(session['username'])
    totp = pyotp.TOTP(user[3])
    if totp.verify(otp_input):
        session['otp_verified'] = True
        return redirect(url_for('home'))
    return render_template('setup_otp.html', error='OTP salah, coba lagi!', qr_path=f"static/uploads/{session['username']}_qr.png")

@app.route('/setup_signature', methods=['GET', 'POST'])
def setup_signature():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['signature']
        if file:
            filename = secure_filename(f"{session['username']}_signature.png")
            path = os.path.join('static/uploads/signatures', filename)
            file.save(path)
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("UPDATE users SET signature_path=? WHERE username=?", (path, session['username']))
            conn.commit()
            conn.close()
            return redirect(url_for('home'))
    return render_template('setup_signature.html')

@app.route('/sign_document', methods=['GET', 'POST'])
def sign_document():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        pdf_file = request.files['pdf']
        otp_input = request.form['otp']
        x = int(request.form['x'])
        y = int(request.form['y'])
        page = int(request.form['page']) - 1

        user = get_user(session['username'])
        if not user[3]:
            return render_template('sign_document.html', error='Setup OTP dulu!')
        totp = pyotp.TOTP(user[3])
        if not totp.verify(otp_input):
            return render_template('sign_document.html', error='OTP salah!')

        pdf_filename = secure_filename(pdf_file.filename)
        pdf_path = os.path.join('static/uploads/documents', pdf_filename)
        pdf_file.save(pdf_path)

        signature_path = user[4]
        if not signature_path:
            return render_template('sign_document.html', error='Setup tanda tangan dulu!')

        signed_filename = f"signed_{pdf_filename}"
        signed_path = os.path.join('static/uploads/documents', signed_filename)

        packet = io.BytesIO()
        c = canvas.Canvas(packet, pagesize=letter)
        c.drawImage(signature_path, x, y, width=150, height=60)
        c.save()
        packet.seek(0)

        overlay = PdfReader(packet)
        reader = PdfReader(pdf_path)
        writer = PdfWriter()
        for i, p in enumerate(reader.pages):
            if i == page:
                p.merge_page(overlay.pages[0])
            writer.add_page(p)
        with open(signed_path, 'wb') as f:
            writer.write(f)

        conn = sqlite3.connect('database.db')
        c2 = conn.cursor()
        c2.execute("INSERT INTO documents (user_id, filename, signed_filename) VALUES (?, ?, ?)",
                   (session['user_id'], pdf_filename, signed_filename))
        conn.commit()
        conn.close()

        return redirect(url_for('history'))

    return render_template('sign_document.html')

@app.route('/history')
def history():
    if 'username' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM documents WHERE user_id=? ORDER BY created_at DESC", (session['user_id'],))
    docs = c.fetchall()
    conn.close()
    return render_template('history.html', documents=docs)
@app.route('/download/<filename>')
def download(filename):
    path = os.path.join('static/uploads/documents', filename)
    return send_file(path, as_attachment=True)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'username' not in session:
        return redirect(url_for('login'))
    result = None
    if request.method == 'POST':
        pdf_file = request.files['pdf']
        if pdf_file:
            filename = secure_filename(pdf_file.filename)
            # Cek apakah file ini ada di database sebagai signed document
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute('''SELECT d.signed_filename, d.created_at, u.username
                         FROM documents d JOIN users u ON d.user_id = u.id
                         WHERE d.signed_filename = ?''', (filename,))
            doc = c.fetchone()
            conn.close()

            if doc:
                result = {
                    'valid': True,
                    'filename': doc[0],
                    'date': doc[1],
                    'signed_by': doc[2]
                }
            else:
                result = {'valid': False}

    return render_template('verify.html', result=result)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
