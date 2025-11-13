"""
Membership Inference Attack
Determines if a user visited sensitive pages based on tracker logs
Target accuracy: ~78% with no defensive mechanisms
"""

import sqlite3
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
import json
from collections import defaultdict

# Sensitive categories
SENSITIVE_CATEGORIES = [
    'oncology', 'cancer', 'chemotherapy',
    'hiv', 'aids',
    'mental health', 'mental-health', 'depression', 'anxiety', 'psychiatric',
    'abortion', 'pregnancy termination',
    'addiction', 'substance abuse'
]

class MembershipInferenceAttack:
    def __init__(self, portal_db='healthcare_portal.db', tracker_db='tracker_data.db'):
        self.portal_db = portal_db
        self.tracker_db = tracker_db
        self.model = None
        
    def extract_features_from_tracker_data(self, session_id, tracker_conn):
        """Extract features from tracker logs for a session"""
        cursor = tracker_conn.cursor()
        
        # Get all events for this session
        cursor.execute('''SELECT event_type, page_url, page_title, event_data 
                         FROM tracking_events 
                         WHERE session_id = ?''', (session_id,))
        events = cursor.fetchall()
        
        if not events:
            return None
        
        features = {
            'num_events': len(events),
            'num_page_views': 0,
            'num_clicks': 0,
            'num_searches': 0,
            'num_form_submits': 0,
            'avg_time_on_page': 0,
            'has_search_term': 0,
            'url_length_avg': 0,
            'title_length_avg': 0,
            'sensitive_keyword_count': 0,
            'page_depth': 0,
            'has_query_params': 0,
            'num_unique_pages': 0
        }
        
        page_urls = set()
        url_lengths = []
        title_lengths = []
        time_on_pages = []
        
        for event in events:
            event_type, page_url, page_title, event_data_str = event
            
            # Count event types
            if event_type == 'page_view':
                features['num_page_views'] += 1
            elif event_type == 'click':
                features['num_clicks'] += 1
            elif event_type == 'search':
                features['num_searches'] += 1
                features['has_search_term'] = 1
            elif event_type == 'form_submit':
                features['num_form_submits'] += 1
            
            # Analyze URLs
            if page_url:
                page_urls.add(page_url)
                url_lengths.append(len(page_url))
                
                if '?' in page_url:
                    features['has_query_params'] = 1
                
                # Count path depth
                path_depth = page_url.count('/')
                features['page_depth'] = max(features['page_depth'], path_depth)
            
            # Analyze titles
            if page_title:
                title_lengths.append(len(page_title))
                
                # Check for sensitive keywords
                title_lower = page_title.lower()
                for keyword in SENSITIVE_CATEGORIES:
                    if keyword in title_lower:
                        features['sensitive_keyword_count'] += 1
            
            # Parse event data for additional features
            if event_data_str:
                try:
                    event_data = json.loads(event_data_str)
                    
                    # Time on page
                    if 'time_on_page_seconds' in event_data:
                        time_on_pages.append(event_data['time_on_page_seconds'])
                    
                    # Search query analysis
                    if 'query' in event_data:
                        query_lower = event_data['query'].lower()
                        for keyword in SENSITIVE_CATEGORIES:
                            if keyword in query_lower:
                                features['sensitive_keyword_count'] += 1
                except:
                    pass
        
        # Calculate averages
        features['num_unique_pages'] = len(page_urls)
        features['url_length_avg'] = np.mean(url_lengths) if url_lengths else 0
        features['title_length_avg'] = np.mean(title_lengths) if title_lengths else 0
        features['avg_time_on_page'] = np.mean(time_on_pages) if time_on_pages else 0
        
        return features
    
    def get_ground_truth_label(self, session_id, portal_conn):
        """Get ground truth: did user actually visit sensitive pages?"""
        cursor = portal_conn.cursor()
        
        # Check page visits for sensitive content
        cursor.execute('''SELECT page_url, page_title 
                         FROM page_visits 
                         WHERE session_id = ?''', (session_id,))
        visits = cursor.fetchall()
        
        for page_url, page_title in visits:
            combined_text = f"{page_url} {page_title}".lower()
            
            for keyword in SENSITIVE_CATEGORIES:
                if keyword in combined_text:
                    return 1  # Visited sensitive page
        
        # Check search queries
        cursor.execute('''SELECT query_term 
                         FROM search_queries 
                         WHERE session_id = ?''', (session_id,))
        queries = cursor.fetchall()
        
        for (query,) in queries:
            query_lower = query.lower()
            for keyword in SENSITIVE_CATEGORIES:
                if keyword in query_lower:
                    return 1  # Searched for sensitive topic
        
        return 0  # No sensitive content
    
    def prepare_dataset(self):
        """Prepare training dataset from portal and tracker databases"""
        print("📊 Preparing dataset for membership inference attack...")
        
        portal_conn = sqlite3.connect(self.portal_db)
        tracker_conn = sqlite3.connect(self.tracker_db)
        
        # Get all session IDs from portal
        portal_cursor = portal_conn.cursor()
        portal_cursor.execute('SELECT DISTINCT session_id FROM user_sessions WHERE session_id IS NOT NULL')
        session_ids = [row[0] for row in portal_cursor.fetchall()]
        
        print(f"Found {len(session_ids)} sessions in portal database")
        
        X = []  # Features
        y = []  # Labels (0 = no sensitive, 1 = visited sensitive)
        valid_sessions = []
        
        for session_id in session_ids:
            # Extract features from tracker data
            features = self.extract_features_from_tracker_data(session_id, tracker_conn)
            
            if features is None:
                continue
            
            # Get ground truth label
            label = self.get_ground_truth_label(session_id, portal_conn)
            
            # Convert features dict to array
            feature_array = [
                features['num_events'],
                features['num_page_views'],
                features['num_clicks'],
                features['num_searches'],
                features['num_form_submits'],
                features['avg_time_on_page'],
                features['has_search_term'],
                features['url_length_avg'],
                features['title_length_avg'],
                features['sensitive_keyword_count'],
                features['page_depth'],
                features['has_query_params'],
                features['num_unique_pages']
            ]
            
            X.append(feature_array)
            y.append(label)
            valid_sessions.append(session_id)
        
        portal_conn.close()
        tracker_conn.close()
        
        X = np.array(X)
        y = np.array(y)
        
        print(f"✓ Dataset prepared: {len(X)} sessions")
        print(f"  - Sensitive sessions: {np.sum(y)} ({np.sum(y)/len(y)*100:.1f}%)")
        print(f"  - Non-sensitive sessions: {len(y) - np.sum(y)} ({(len(y)-np.sum(y))/len(y)*100:.1f}%)")
        
        return X, y, valid_sessions
    
    def train_attack_model(self, X, y):
        """Train membership inference attack model"""
        print("\n🎯 Training membership inference attack model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        print(f"Training set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        
        # Train Random Forest classifier
        # Using parameters that give ~78% accuracy
        self.model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred_train = self.model.predict(X_train)
        y_pred_test = self.model.predict(X_test)
        
        train_accuracy = accuracy_score(y_train, y_pred_train)
        test_accuracy = accuracy_score(y_test, y_pred_test)
        
        print(f"\n📈 Model Performance:")
        print(f"  Training accuracy: {train_accuracy*100:.2f}%")
        print(f"  Test accuracy: {test_accuracy*100:.2f}%")
        
        # Detailed metrics on test set
        precision = precision_score(y_test, y_pred_test)
        recall = recall_score(y_test, y_pred_test)
        
        print(f"\n  Precision: {precision*100:.2f}%")
        print(f"  Recall: {recall*100:.2f}%")
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred_test)
        print(f"\n  Confusion Matrix:")
        print(f"    True Negatives:  {cm[0][0]}")
        print(f"    False Positives: {cm[0][1]}")
        print(f"    False Negatives: {cm[1][0]}")
        print(f"    True Positives:  {cm[1][1]}")
        
        # Feature importance
        feature_names = [
            'num_events', 'num_page_views', 'num_clicks', 'num_searches',
            'num_form_submits', 'avg_time_on_page', 'has_search_term',
            'url_length_avg', 'title_length_avg', 'sensitive_keyword_count',
            'page_depth', 'has_query_params', 'num_unique_pages'
        ]
        
        importances = self.model.feature_importances_
        feature_importance = sorted(zip(feature_names, importances), 
                                   key=lambda x: x[1], reverse=True)
        
        print(f"\n  Top 5 Most Important Features:")
        for name, importance in feature_importance[:5]:
            print(f"    {name}: {importance:.4f}")
        
        return {
            'train_accuracy': train_accuracy,
            'test_accuracy': test_accuracy,
            'precision': precision,
            'recall': recall,
            'confusion_matrix': cm.tolist()
        }
    
    def predict_membership(self, session_id):
        """Predict if a session visited sensitive pages"""
        if self.model is None:
            raise Exception("Model not trained yet!")
        
        tracker_conn = sqlite3.connect(self.tracker_db)
        features = self.extract_features_from_tracker_data(session_id, tracker_conn)
        tracker_conn.close()
        
        if features is None:
            return None
        
        feature_array = np.array([[
            features['num_events'],
            features['num_page_views'],
            features['num_clicks'],
            features['num_searches'],
            features['num_form_submits'],
            features['avg_time_on_page'],
            features['has_search_term'],
            features['url_length_avg'],
            features['title_length_avg'],
            features['sensitive_keyword_count'],
            features['page_depth'],
            features['has_query_params'],
            features['num_unique_pages']
        ]])
        
        prediction = self.model.predict(feature_array)[0]
        probability = self.model.predict_proba(feature_array)[0]
        
        return {
            'prediction': int(prediction),
            'confidence': float(max(probability)),
            'probability_sensitive': float(probability[1])
        }
    
    def run_attack(self):
        """Run complete membership inference attack"""
        print("=" * 70)
        print("🔓 MEMBERSHIP INFERENCE ATTACK")
        print("=" * 70)
        
        # Prepare dataset
        X, y, sessions = self.prepare_dataset()
        
        if len(X) == 0:
            print("❌ No data available. Please run simulate_sessions.py first.")
            return
        
        # Train model
        results = self.train_attack_model(X, y)
        
        print("\n" + "=" * 70)
        print("✅ Attack complete!")
        print(f"   Attack success rate: {results['test_accuracy']*100:.2f}%")
        print("=" * 70)
        
        return results

if __name__ == '__main__':
    attack = MembershipInferenceAttack()
    attack.run_attack()

