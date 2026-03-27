import os
import sqlite3
import json
import csv
import base64
from io import StringIO
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Change in production

# Database
DATABASE = 'civicpulse.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        phone TEXT,
        state TEXT,
        city TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        description TEXT NOT NULL,
        ward TEXT NOT NULL,
        category TEXT NOT NULL,
        sub_category TEXT,
        urgency INTEGER DEFAULT 5,
        status TEXT DEFAULT 'pending',
        date TEXT NOT NULL,
        address TEXT,
        lat REAL,
        lng REAL,
        images TEXT,
        assigned_to TEXT,
        resolved_by TEXT,
        proof TEXT,
        timeline TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def seed_admin():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email = ?", ('admin@civicpulse.org',))
    if not c.fetchone():
        c.execute('''INSERT INTO users (name, email, password, role)
                     VALUES (?, ?, ?, ?)''',
                  ('Admin Root', 'admin@civicpulse.org',
                   generate_password_hash('admin123'), 'admin'))
        conn.commit()
    conn.close()

init_db()
seed_admin()

# Decorators
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        conn.close()
        if not user or user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

# Authentication
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Missing fields'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['role'] = user['role']
        return jsonify({
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'role': user['role']
        })
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    required = ['name', 'email', 'password', 'phone', 'state', 'city']
    if not all(k in data for k in required):
        return jsonify({'error': 'Missing fields'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email = ?", (data['email'],))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'Email already exists'}), 409

    hashed = generate_password_hash(data['password'])
    c.execute('''INSERT INTO users (name, email, password, role, phone, state, city)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (data['name'], data['email'], hashed, 'citizen',
               data['phone'], data['state'], data['city']))
    user_id = c.lastrowid
    conn.commit()
    conn.close()

    session['user_id'] = user_id
    session['role'] = 'citizen'
    return jsonify({
        'id': user_id,
        'name': data['name'],
        'email': data['email'],
        'role': 'citizen'
    })

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/auth/me', methods=['GET'])
@login_required
def me():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, email, role FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    if user:
        return jsonify(dict(user))
    return jsonify({'error': 'User not found'}), 404

# Complaints
@app.route('/api/complaints', methods=['GET'])
@login_required
def get_complaints():
    conn = get_db()
    c = conn.cursor()
    if session['role'] == 'admin':
        c.execute("SELECT * FROM complaints ORDER BY date DESC")
    else:
        c.execute("SELECT * FROM complaints WHERE user_id = ? ORDER BY date DESC",
                  (session['user_id'],))
    rows = c.fetchall()
    complaints = []
    for row in rows:
        comp = dict(row)
        comp['images'] = json.loads(comp['images']) if comp['images'] else []
        comp['timeline'] = json.loads(comp['timeline']) if comp['timeline'] else []
        complaints.append(comp)
    conn.close()
    return jsonify(complaints)

@app.route('/api/complaints', methods=['POST'])
@login_required
def create_complaint():
    if session['role'] != 'citizen':
        return jsonify({'error': 'Only citizens can create complaints'}), 403

    # Form data
    data = request.form
    files = request.files.getlist('images')

    # Convert images to base64 (store as text)
    images_b64 = []
    for file in files:
        if file and file.filename:
            img_bytes = file.read()
            b64 = base64.b64encode(img_bytes).decode('utf-8')
            mime = file.mimetype
            images_b64.append(f'data:{mime};base64,{b64}')

    timeline = [{'event': 'Created', 'timestamp': datetime.now().isoformat()}]

    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO complaints
        (user_id, description, ward, category, sub_category, urgency, status, date,
         address, lat, lng, images, timeline)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (session['user_id'],
         data.get('description'),
         data.get('location'),
         data.get('category'),
         data.get('subCategory'),
         int(data.get('urgency', 5)),
         'pending',
         datetime.now().strftime('%Y-%m-%d'),
         data.get('address'),
         float(data.get('lat')) if data.get('lat') else None,
         float(data.get('lng')) if data.get('lng') else None,
         json.dumps(images_b64),
         json.dumps(timeline)))
    complaint_id = c.lastrowid
    conn.commit()
    conn.close()

    return jsonify({'id': complaint_id, 'message': 'Complaint created'}), 201

@app.route('/api/complaints/<int:complaint_id>', methods=['GET'])
@login_required
def get_complaint(complaint_id):
    conn = get_db()
    c = conn.cursor()
    if session['role'] == 'admin':
        c.execute("SELECT * FROM complaints WHERE id = ?", (complaint_id,))
    else:
        c.execute("SELECT * FROM complaints WHERE id = ? AND user_id = ?",
                  (complaint_id, session['user_id']))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    comp = dict(row)
    comp['images'] = json.loads(comp['images']) if comp['images'] else []
    comp['timeline'] = json.loads(comp['timeline']) if comp['timeline'] else []
    return jsonify(comp)

@app.route('/api/complaints/<int:complaint_id>/resolve', methods=['PUT'])
@admin_required
def resolve_complaint(complaint_id):
    data = request.get_json()
    proof = data.get('proof', '')
    resolved_by = data.get('resolvedBy', 'Admin')

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT timeline FROM complaints WHERE id = ?", (complaint_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Not found'}), 404

    timeline = json.loads(row['timeline']) if row['timeline'] else []
    timeline.append({'event': 'Resolved', 'timestamp': datetime.now().isoformat()})

    c.execute('''UPDATE complaints
                 SET status = 'resolved', proof = ?, resolved_by = ?, timeline = ?
                 WHERE id = ?''',
              (proof, resolved_by, json.dumps(timeline), complaint_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Resolved'})

# Admin stats
@app.route('/api/dashboard/stats', methods=['GET'])
@admin_required
def dashboard_stats():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM complaints")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM complaints WHERE status = 'pending'")
    pending = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM complaints WHERE status = 'resolved'")
    resolved = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM complaints WHERE status = 'pending' AND date < date('now', '-3 days')")
    overdue = c.fetchone()[0]

    c.execute('''SELECT ward, COUNT(*) as cnt FROM complaints
                 WHERE status = 'pending' GROUP BY ward ORDER BY cnt DESC LIMIT 1''')
    ward_row = c.fetchone()
    ward_with_most = {'ward': ward_row[0], 'count': ward_row[1]} if ward_row else None

    c.execute('''SELECT category, COUNT(*) as cnt FROM complaints
                 WHERE status = 'pending' GROUP BY category ORDER BY cnt DESC LIMIT 1''')
    cat_row = c.fetchone()
    top_category = {'category': cat_row[0], 'count': cat_row[1]} if cat_row else None

    c.execute("SELECT COUNT(*) FROM complaints WHERE status = 'pending' AND urgency >= 8")
    urgent = c.fetchone()[0]

    conn.close()
    return jsonify({
        'total': total,
        'pending': pending,
        'resolved': resolved,
        'overdue': overdue,
        'wardWithMost': ward_with_most,
        'topCategory': top_category,
        'urgentCount': urgent
    })

@app.route('/api/heatmap', methods=['GET'])
def get_heatmap():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT lat, lng, urgency FROM complaints WHERE lat IS NOT NULL AND lng IS NOT NULL")
    rows = c.fetchall()
    conn.close()
    heat = [[r['lat'], r['lng'], r['urgency']] for r in rows]
    return jsonify(heat)

@app.route('/api/export/csv', methods=['GET'])
@admin_required
def export_csv():
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT id, description, ward, category, urgency, status, date, proof, resolved_by
                 FROM complaints''')
    rows = c.fetchall()
    conn.close()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['ID', 'Description', 'Ward', 'Category', 'Urgency', 'Status', 'Date', 'Proof', 'Resolved By'])
    for row in rows:
        writer.writerow(list(row))
    output = si.getvalue()
    si.close()
    return output, 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename=civicpulse_reports.csv'
    }

# Frontend routes
@app.route('/')
def citizen():
    return render_template('index.html')

@app.route('/admin')
def admin_panel():
    return render_template('admin.html')

if __name__ == '__main__':
    app.run(debug=True)