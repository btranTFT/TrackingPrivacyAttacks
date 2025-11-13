"""
Flask Healthcare Portal - Mock Patient Portal
Simulates user logins, health-topic searches, and session tracking
"""

from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import sqlite3
import hashlib
import secrets
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Database setup
DB_PATH = 'healthcare_portal.db'

def init_db():
    """Initialize the healthcare portal database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        age INTEGER,
        zipcode TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Sessions table
    c.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        session_id TEXT,
        login_time TIMESTAMP,
        logout_time TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    # Page visits table
    c.execute('''CREATE TABLE IF NOT EXISTS page_visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        session_id TEXT,
        page_url TEXT,
        page_title TEXT,
        visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    # Search queries table
    c.execute('''CREATE TABLE IF NOT EXISTS search_queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        session_id TEXT,
        query_term TEXT,
        search_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    conn.commit()
    conn.close()

def hash_password(password):
    """Simple password hashing"""
    return hashlib.sha256(password.encode()).hexdigest()

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and user['password_hash'] == hash_password(password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['session_id'] = secrets.token_hex(16)
            
            # Log session start
            conn = get_db()
            conn.execute('INSERT INTO user_sessions (user_id, session_id, login_time) VALUES (?, ?, ?)',
                        (user['id'], session['session_id'], datetime.now()))
            conn.commit()
            conn.close()
            
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        age = request.form.get('age')
        zipcode = request.form.get('zipcode')
        
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, password_hash, email, age, zipcode) VALUES (?, ?, ?, ?, ?)',
                        (username, hash_password(password), email, age, zipcode))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('register.html', error='Username already exists')
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Log page visit
    log_page_visit('/dashboard', 'Dashboard')
    
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/search')
def search():
    """Health topic search page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    query = request.args.get('q', '')
    
    # Log page visit
    log_page_visit(f'/search?q={query}', f'Search: {query}')
    
    # Log search query
    if query:
        conn = get_db()
        conn.execute('INSERT INTO search_queries (user_id, session_id, query_term) VALUES (?, ?, ?)',
                    (session['user_id'], session.get('session_id'), query))
        conn.commit()
        conn.close()
    
    # Simulated search results
    results = get_search_results(query)
    
    return render_template('search.html', query=query, results=results)

@app.route('/topic/<topic_name>')
def topic_page(topic_name):
    """Health topic information page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Log page visit
    log_page_visit(f'/topic/{topic_name}', f'Topic: {topic_name}')
    
    topic_info = get_topic_info(topic_name)
    
    return render_template('topic.html', topic=topic_name, info=topic_info)

@app.route('/logout')
def logout():
    """User logout"""
    if 'user_id' in session:
        # Log session end
        conn = get_db()
        conn.execute('UPDATE user_sessions SET logout_time = ? WHERE session_id = ?',
                    (datetime.now(), session.get('session_id')))
        conn.commit()
        conn.close()
        
        session.clear()
    
    return redirect(url_for('index'))

def log_page_visit(page_url, page_title):
    """Log page visit to database"""
    if 'user_id' in session:
        conn = get_db()
        conn.execute('INSERT INTO page_visits (user_id, session_id, page_url, page_title) VALUES (?, ?, ?, ?)',
                    (session['user_id'], session.get('session_id'), page_url, page_title))
        conn.commit()
        conn.close()

def get_search_results(query):
    """Simulated search results"""
    all_topics = {
        'oncology': 'Cancer Treatment and Oncology Services',
        'cardiology': 'Heart Health and Cardiology',
        'mental health': 'Mental Health and Counseling Services',
        'hiv': 'HIV Testing and Treatment',
        'diabetes': 'Diabetes Management',
        'dermatology': 'Skin Care and Dermatology',
        'orthopedics': 'Bone and Joint Care',
        'pediatrics': 'Children\'s Health Services',
        'neurology': 'Brain and Nervous System Care',
        'gastroenterology': 'Digestive Health Services'
    }
    
    if not query:
        return []
    
    results = []
    query_lower = query.lower()
    for key, value in all_topics.items():
        if query_lower in key or query_lower in value.lower():
            results.append({'name': key, 'description': value})
    
    return results

def get_topic_info(topic_name):
    """Get information about a health topic"""
    topics = {
        'oncology': {
            'title': 'Cancer Treatment and Oncology',
            'description': 'Comprehensive cancer care including diagnosis, treatment, and support services.',
            'services': ['Chemotherapy', 'Radiation Therapy', 'Surgical Oncology', 'Support Groups']
        },
        'cardiology': {
            'title': 'Heart Health and Cardiology',
            'description': 'Expert cardiac care for heart conditions and cardiovascular health.',
            'services': ['EKG Testing', 'Stress Tests', 'Cardiac Catheterization', 'Heart Surgery']
        },
        'mental-health': {
            'title': 'Mental Health Services',
            'description': 'Confidential mental health support and counseling services.',
            'services': ['Individual Therapy', 'Group Therapy', 'Psychiatric Care', 'Crisis Support']
        },
        'hiv': {
            'title': 'HIV Testing and Treatment',
            'description': 'Confidential HIV testing, treatment, and ongoing care.',
            'services': ['HIV Testing', 'PrEP Services', 'Treatment Programs', 'Support Services']
        },
        'diabetes': {
            'title': 'Diabetes Management',
            'description': 'Comprehensive diabetes care and education.',
            'services': ['Blood Sugar Monitoring', 'Insulin Management', 'Nutrition Counseling', 'Education Programs']
        }
    }
    
    return topics.get(topic_name, {
        'title': topic_name.replace('-', ' ').title(),
        'description': f'Information about {topic_name}',
        'services': ['General Information', 'Consultation Services']
    })

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)

