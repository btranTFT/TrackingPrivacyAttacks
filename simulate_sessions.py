"""
Synthetic User Session Simulator
Generates 500 simulated user sessions with synthetic profiles
"""

import sqlite3
import random
import time
from datetime import datetime, timedelta
import hashlib
import json

# Synthetic user profiles
FIRST_NAMES = ['John', 'Jane', 'Michael', 'Sarah', 'David', 'Emily', 'Robert', 'Lisa', 
               'James', 'Mary', 'William', 'Patricia', 'Richard', 'Jennifer', 'Thomas', 
               'Linda', 'Charles', 'Barbara', 'Daniel', 'Elizabeth']

LAST_NAMES = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 
              'Davis', 'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez', 
              'Wilson', 'Anderson', 'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin']

ZIPCODES = ['10001', '90210', '60601', '02101', '94102', '33101', '77001', '85001', 
            '19101', '98101', '30301', '80201', '97201', '63101', '48201']

# Health topics with sensitivity levels
HEALTH_TOPICS = {
    'sensitive': [
        'oncology', 'hiv', 'mental health', 'mental-health', 
        'psychiatric', 'abortion', 'addiction'
    ],
    'moderate': [
        'cardiology', 'diabetes', 'neurology', 'gastroenterology'
    ],
    'general': [
        'dermatology', 'orthopedics', 'pediatrics', 'general health'
    ]
}

# Search queries
SEARCH_QUERIES = {
    'sensitive': [
        'oncology', 'cancer treatment', 'chemotherapy',
        'hiv testing', 'hiv treatment', 'aids',
        'mental health counseling', 'depression treatment', 'anxiety therapy',
        'psychiatric services', 'substance abuse treatment'
    ],
    'moderate': [
        'heart health', 'cardiology services', 'blood pressure',
        'diabetes management', 'insulin therapy',
        'brain health', 'neurology consultation'
    ],
    'general': [
        'annual checkup', 'flu shot', 'vaccination',
        'skin care', 'dermatology', 'bone health'
    ]
}

class SessionSimulator:
    def __init__(self, db_path='healthcare_portal.db', tracker_db_path='tracker_data.db'):
        self.db_path = db_path
        self.tracker_db_path = tracker_db_path
        self.users = []
        
    def init_database(self):
        """Ensure database tables exist"""
        # Initialize portal database
        conn = sqlite3.connect(self.db_path)
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
        
        # Initialize tracker database
        tracker_conn = sqlite3.connect(self.tracker_db_path)
        tracker_c = tracker_conn.cursor()
        
        # Tracking events table
        tracker_c.execute('''CREATE TABLE IF NOT EXISTS tracking_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tracker_id TEXT,
            session_id TEXT,
            timestamp TEXT,
            event_type TEXT,
            page_url TEXT,
            page_title TEXT,
            referrer TEXT,
            user_agent TEXT,
            screen_resolution TEXT,
            event_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Leakage analysis table
        tracker_c.execute('''CREATE TABLE IF NOT EXISTS leakage_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            has_sensitive_leak INTEGER DEFAULT 0,
            sensitive_terms TEXT,
            leak_type TEXT,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Create indexes
        tracker_c.execute('''CREATE INDEX IF NOT EXISTS idx_session_id ON tracking_events(session_id)''')
        tracker_c.execute('''CREATE INDEX IF NOT EXISTS idx_event_type ON tracking_events(event_type)''')
        tracker_c.execute('''CREATE INDEX IF NOT EXISTS idx_timestamp ON tracking_events(timestamp)''')
        
        tracker_conn.commit()
        tracker_conn.close()
        
        print("[OK] Databases initialized")
    
    def hash_password(self, password):
        """Hash password"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def generate_users(self, num_users=100):
        """Generate synthetic user profiles"""
        print(f"Generating {num_users} synthetic users...")
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        for i in range(num_users):
            first_name = random.choice(FIRST_NAMES)
            last_name = random.choice(LAST_NAMES)
            username = f"{first_name.lower()}.{last_name.lower()}{random.randint(1, 999)}"
            email = f"{username}@example.com"
            age = random.randint(18, 85)
            zipcode = random.choice(ZIPCODES)
            password_hash = self.hash_password('password123')
            
            try:
                c.execute('''INSERT INTO users (username, password_hash, email, age, zipcode)
                           VALUES (?, ?, ?, ?, ?)''',
                         (username, password_hash, email, age, zipcode))
                
                user_id = c.lastrowid
                self.users.append({
                    'id': user_id,
                    'username': username,
                    'age': age,
                    'zipcode': zipcode
                })
            except sqlite3.IntegrityError:
                pass  # Skip if username exists
        
        conn.commit()
        conn.close()
        print(f"[OK] Generated {len(self.users)} users")
    
    def load_existing_users(self):
        """Load existing users from database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('SELECT id, username, age, zipcode FROM users')
        rows = c.fetchall()
        
        for row in rows:
            self.users.append({
                'id': row[0],
                'username': row[1],
                'age': row[2],
                'zipcode': row[3]
            })
        
        conn.close()
        print(f"[OK] Loaded {len(self.users)} existing users")
    
    def generate_session_id(self):
        """Generate random session ID"""
        return f"session_{random.randint(100000, 999999)}_{int(time.time())}"
    
    def detect_sensitive_leakage(self, page_url, page_title, query=None):
        """Detect if tracking event contains sensitive information"""
        # Sensitive terms that indicate potential privacy leakage
        SENSITIVE_TERMS = [
            'oncology', 'cancer', 'chemotherapy',
            'hiv', 'aids',
            'mental health', 'depression', 'anxiety', 'psychiatric',
            'abortion', 'pregnancy',
            'addiction', 'substance abuse',
            'std', 'sexually transmitted',
            'erectile dysfunction',
            'fertility'
        ]
        
        # Check all text fields
        text_to_check = f"{page_url} {page_title}".lower()
        if query:
            text_to_check += f" {query}".lower()
        
        detected_terms = []
        for term in SENSITIVE_TERMS:
            if term.lower() in text_to_check:
                detected_terms.append(term)
        
        if not detected_terms:
            return None, None
        
        # Determine leak type
        leak_types = []
        if '?' in page_url:
            leak_types.append('url_parameter')
        if page_title:
            leak_types.append('page_title')
        if query:
            leak_types.append('search_query')
        
        leak_type = ','.join(leak_types) if leak_types else 'other'
        
        return detected_terms, leak_type
    
    def create_tracking_event(self, session_id, event_type, page_url, page_title, timestamp, query=None, has_sensitive=False):
        """Create a tracking event in the tracker database"""
        tracker_conn = sqlite3.connect(self.tracker_db_path)
        tracker_c = tracker_conn.cursor()
        
        # Generate tracker ID
        tracker_id = f"tracker_{random.randint(1000, 9999)}"
        
        # Create event data
        event_data = {
            'event_type': event_type,
            'page_url': page_url,
            'page_title': page_title,
            'time_on_page_seconds': random.randint(5, 120)
        }
        
        if query:
            event_data['query'] = query
        
        # Insert tracking event
        tracker_c.execute('''INSERT INTO tracking_events 
                           (tracker_id, session_id, timestamp, event_type, page_url, page_title, 
                            referrer, user_agent, screen_resolution, event_data)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                         (tracker_id, session_id, timestamp.isoformat(), event_type, page_url, page_title,
                          '', 'Mozilla/5.0 (simulated)', '1920x1080', json.dumps(event_data)))
        
        # Check for sensitive leakage and populate leakage_analysis table
        # Always check for leakage, not just when has_sensitive flag is set
        sensitive_terms, leak_type = self.detect_sensitive_leakage(page_url, page_title, query)
        if sensitive_terms:
            # Check if this session already has a leakage record
            tracker_c.execute('''SELECT id, sensitive_terms, leak_type FROM leakage_analysis WHERE session_id = ?''', (session_id,))
            existing = tracker_c.fetchone()
            
            if existing:
                # Update existing record - merge sensitive terms
                try:
                    existing_terms = json.loads(existing[1])
                    if isinstance(existing_terms, list):
                        all_terms = list(set(existing_terms + sensitive_terms))
                    else:
                        all_terms = sensitive_terms
                except:
                    all_terms = sensitive_terms
                
                # Merge leak types
                existing_types = existing[2] or ''
                all_types = ','.join(set((existing_types.split(',') if existing_types else []) + (leak_type.split(',') if leak_type else [])))
                
                tracker_c.execute('''UPDATE leakage_analysis 
                                   SET has_sensitive_leak = 1, 
                                       sensitive_terms = ?,
                                       leak_type = ?
                                   WHERE session_id = ?''',
                                 (json.dumps(all_terms), all_types, session_id))
            else:
                # Insert new record
                tracker_c.execute('''INSERT INTO leakage_analysis 
                                   (session_id, has_sensitive_leak, sensitive_terms, leak_type)
                                   VALUES (?, ?, ?, ?)''',
                                 (session_id, 1, json.dumps(sensitive_terms), leak_type))
        
        tracker_conn.commit()
        tracker_conn.close()
    
    def simulate_session(self, user, session_num):
        """Simulate a single user session"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        session_id = self.generate_session_id()
        
        # Determine session behavior profile
        # 41% of sessions will have sensitive leakage
        has_sensitive_behavior = random.random() < 0.41
        
        # Login time (random time in past 2 weeks)
        login_time = datetime.now() - timedelta(
            days=random.randint(0, 14),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        # Insert session
        c.execute('''INSERT INTO user_sessions (user_id, session_id, login_time)
                   VALUES (?, ?, ?)''',
                 (user['id'], session_id, login_time))
        
        # Simulate page visits
        num_pages = random.randint(3, 12)
        current_time = login_time
        
        # Visit dashboard
        c.execute('''INSERT INTO page_visits (user_id, session_id, page_url, page_title, visit_time)
                   VALUES (?, ?, ?, ?, ?)''',
                 (user['id'], session_id, '/dashboard', 'Dashboard', current_time))
        self.create_tracking_event(session_id, 'page_view', '/dashboard', 'Dashboard', current_time, has_sensitive=False)
        current_time += timedelta(seconds=random.randint(5, 30))
        
        # Perform searches and visit topics
        for _ in range(num_pages - 1):
            if has_sensitive_behavior and random.random() < 0.6:
                # Visit sensitive topics
                query = random.choice(SEARCH_QUERIES['sensitive'])
                topic = random.choice(HEALTH_TOPICS['sensitive'])
                is_sensitive = True
            elif random.random() < 0.3:
                query = random.choice(SEARCH_QUERIES['moderate'])
                topic = random.choice(HEALTH_TOPICS['moderate'])
                is_sensitive = False
            else:
                query = random.choice(SEARCH_QUERIES['general'])
                topic = random.choice(HEALTH_TOPICS['general'])
                is_sensitive = False
            
            # Search
            search_url = f'/search?q={query}'
            c.execute('''INSERT INTO page_visits (user_id, session_id, page_url, page_title, visit_time)
                       VALUES (?, ?, ?, ?, ?)''',
                     (user['id'], session_id, search_url, f'Search: {query}', current_time))
            self.create_tracking_event(session_id, 'search', search_url, f'Search: {query}', current_time, query=query, has_sensitive=is_sensitive)
            
            c.execute('''INSERT INTO search_queries (user_id, session_id, query_term, search_time)
                       VALUES (?, ?, ?, ?)''',
                     (user['id'], session_id, query, current_time))
            
            current_time += timedelta(seconds=random.randint(3, 15))
            
            # Visit topic page
            if random.random() < 0.7:  # 70% chance to visit topic after search
                topic_url = f'/topic/{topic}'
                c.execute('''INSERT INTO page_visits (user_id, session_id, page_url, page_title, visit_time)
                           VALUES (?, ?, ?, ?, ?)''',
                         (user['id'], session_id, topic_url, f'Topic: {topic}', current_time))
                self.create_tracking_event(session_id, 'page_view', topic_url, f'Topic: {topic}', current_time, has_sensitive=is_sensitive)
                current_time += timedelta(seconds=random.randint(20, 120))
        
        # Logout
        logout_time = current_time + timedelta(seconds=random.randint(5, 30))
        c.execute('''UPDATE user_sessions SET logout_time = ? WHERE session_id = ?''',
                 (logout_time, session_id))
        
        conn.commit()
        conn.close()
        
        return {
            'session_id': session_id,
            'user_id': user['id'],
            'has_sensitive': has_sensitive_behavior,
            'num_pages': num_pages
        }
    
    def run_simulation(self, num_sessions=500):
        """Run complete simulation"""
        print(f"\n[START] Starting simulation of {num_sessions} sessions...")
        print("=" * 60)
        
        self.init_database()
        
        # Load or generate users
        self.load_existing_users()
        if len(self.users) < 50:
            self.generate_users(100)
        
        # Generate sessions
        sessions_generated = 0
        sensitive_sessions = 0
        
        for i in range(num_sessions):
            user = random.choice(self.users)
            session_info = self.simulate_session(user, i + 1)
            
            sessions_generated += 1
            if session_info['has_sensitive']:
                sensitive_sessions += 1
            
            if (i + 1) % 50 == 0:
                print(f"Progress: {i + 1}/{num_sessions} sessions generated "
                      f"({sensitive_sessions} with sensitive content)")
        
        print("=" * 60)
        print(f"[OK] Simulation complete!")
        print(f"  Total sessions: {sessions_generated}")
        print(f"  Sessions with sensitive content: {sensitive_sessions}")
        print(f"  Leakage rate: {(sensitive_sessions/sessions_generated*100):.1f}%")
        
        # Generate summary statistics
        self.print_statistics()
    
    def print_statistics(self):
        """Print session statistics"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        print("\n[STATS] Session Statistics:")
        print("-" * 60)
        
        # Total sessions
        c.execute('SELECT COUNT(*) FROM user_sessions')
        total_sessions = c.fetchone()[0]
        print(f"Total sessions: {total_sessions}")
        
        # Total page visits
        c.execute('SELECT COUNT(*) FROM page_visits')
        total_visits = c.fetchone()[0]
        print(f"Total page visits: {total_visits}")
        
        # Total searches
        c.execute('SELECT COUNT(*) FROM search_queries')
        total_searches = c.fetchone()[0]
        print(f"Total searches: {total_searches}")
        
        # Top search terms
        c.execute('''SELECT query_term, COUNT(*) as count 
                    FROM search_queries 
                    GROUP BY query_term 
                    ORDER BY count DESC 
                    LIMIT 10''')
        print("\nTop 10 search terms:")
        for row in c.fetchall():
            print(f"  - {row[0]}: {row[1]} times")
        
        conn.close()

if __name__ == '__main__':
    simulator = SessionSimulator()
    simulator.run_simulation(500)
    print("\n[SUCCESS] Session simulation complete!")

