"""
Rigorous Sanitization Testing
Tests membership inference attack on sanitized data
"""

import sqlite3
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
import json
from privacy_defenses import PrivacyDefenses
from membership_inference_attack import MembershipInferenceAttack, SENSITIVE_CATEGORIES

class SanitizationAttackTest:
    """Test membership inference attack on sanitized tracking data"""
    
    def __init__(self, portal_db='healthcare_portal.db', tracker_db='tracker_data.db'):
        self.portal_db = portal_db
        self.tracker_db = tracker_db
        self.baseline_attack = MembershipInferenceAttack(portal_db, tracker_db)
        
    def extract_features_from_sanitized_data(self, session_id):
        """Extract features from sanitized tracker logs for a session"""
        conn = sqlite3.connect(self.tracker_db)
        cursor = conn.cursor()
        
        # Get all events for this session
        cursor.execute('''SELECT event_type, page_url, page_title, event_data 
                         FROM tracking_events 
                         WHERE session_id = ?''', (session_id,))
        events = cursor.fetchall()
        conn.close()
        
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
            'sensitive_keyword_count': 0,  # Should be 0 after sanitization
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
            
            # Sanitize the data first
            event_dict = {
                'event_type': event_type,
                'page_url': page_url,
                'page_title': page_title
            }
            
            if event_data_str:
                try:
                    event_dict.update(json.loads(event_data_str))
                except:
                    pass
            
            # Apply sanitization
            sanitized_event = PrivacyDefenses.sanitize_tracking_event(event_dict)
            
            # Extract features from sanitized data
            sanitized_url = sanitized_event.get('page_url', page_url)
            sanitized_title = sanitized_event.get('page_title', page_title)
            
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
            
            # Analyze sanitized URLs
            if sanitized_url:
                page_urls.add(sanitized_url)
                url_lengths.append(len(sanitized_url))
                
                if '?' in sanitized_url:
                    features['has_query_params'] = 1
                
                path_depth = sanitized_url.count('/')
                features['page_depth'] = max(features['page_depth'], path_depth)
            
            # Analyze sanitized titles
            if sanitized_title:
                title_lengths.append(len(sanitized_title))
                
                # Check for sensitive keywords (should be removed by sanitization)
                title_lower = sanitized_title.lower()
                for keyword in SENSITIVE_CATEGORIES:
                    if keyword in title_lower:
                        features['sensitive_keyword_count'] += 1
            
            # Parse event data for time on page
            if event_data_str:
                try:
                    event_data = json.loads(event_data_str)
                    if 'time_on_page_seconds' in event_data:
                        time_on_pages.append(event_data['time_on_page_seconds'])
                except:
                    pass
        
        # Calculate averages
        features['num_unique_pages'] = len(page_urls)
        features['url_length_avg'] = np.mean(url_lengths) if url_lengths else 0
        features['title_length_avg'] = np.mean(title_lengths) if title_lengths else 0
        features['avg_time_on_page'] = np.mean(time_on_pages) if time_on_pages else 0
        
        return features
    
    def prepare_sanitized_dataset(self):
        """Prepare dataset with sanitized features"""
        print("[SANITIZATION] Preparing sanitized dataset...")
        
        portal_conn = sqlite3.connect(self.portal_db)
        portal_cursor = portal_conn.cursor()
        portal_cursor.execute('SELECT DISTINCT session_id FROM user_sessions WHERE session_id IS NOT NULL')
        session_ids = [row[0] for row in portal_cursor.fetchall()]
        
        print(f"Found {len(session_ids)} sessions")
        
        X = []
        y = []
        valid_sessions = []
        
        for session_id in session_ids:
            # Extract features from sanitized data
            features = self.extract_features_from_sanitized_data(session_id)
            
            if features is None:
                continue
            
            # Get ground truth label from portal (not tracker)
            label = self.baseline_attack.get_ground_truth_label(session_id, portal_conn)
            
            # Convert features to array
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
        
        X = np.array(X)
        y = np.array(y)
        
        print(f"[OK] Sanitized dataset prepared: {len(X)} sessions")
        print(f"  - Sensitive sessions: {np.sum(y)} ({np.sum(y)/len(y)*100:.1f}%)")
        print(f"  - Non-sensitive sessions: {len(y) - np.sum(y)} ({(len(y)-np.sum(y))/len(y)*100:.1f}%)")
        
        return X, y, valid_sessions
    
    def test_attack_on_sanitized_data(self):
        """Test membership inference attack on sanitized data"""
        print("\n" + "=" * 70)
        print("TESTING ATTACK ON SANITIZED DATA")
        print("=" * 70)
        
        # Prepare sanitized dataset
        X_sanitized, y, sessions = self.prepare_sanitized_dataset()
        
        if len(X_sanitized) == 0:
            print("[ERROR] No data available")
            return None
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_sanitized, y, test_size=0.3, random_state=42, stratify=y
        )
        
        print(f"\nTraining set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        
        # Train Random Forest on sanitized data
        model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42
        )
        
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred_test = model.predict(X_test)
        test_accuracy = accuracy_score(y_test, y_pred_test)
        precision = precision_score(y_test, y_pred_test)
        recall = recall_score(y_test, y_pred_test)
        cm = confusion_matrix(y_test, y_pred_test)
        
        print(f"\n[RESULTS] Attack Performance on Sanitized Data:")
        print(f"  Test accuracy: {test_accuracy*100:.2f}%")
        print(f"  Precision: {precision*100:.2f}%")
        print(f"  Recall: {recall*100:.2f}%")
        
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
        
        importances = model.feature_importances_
        feature_importance = sorted(zip(feature_names, importances), 
                                   key=lambda x: x[1], reverse=True)
        
        print(f"\n  Top 5 Most Important Features:")
        for name, importance in feature_importance[:5]:
            print(f"    {name}: {importance:.4f}")
        
        return {
            'test_accuracy': test_accuracy,
            'precision': precision,
            'recall': recall,
            'confusion_matrix': cm.tolist(),
            'feature_importance': dict(feature_importance)
        }
    
    def run_comparison(self):
        """Run comparison between baseline and sanitized attacks"""
        print("\n" + "=" * 70)
        print("SANITIZATION ATTACK COMPARISON")
        print("=" * 70)
        
        # Run baseline attack
        print("\n[1] Running Baseline Attack (No Sanitization)...")
        baseline_results = self.baseline_attack.run_attack()
        
        # Run attack on sanitized data
        print("\n[2] Running Attack on Sanitized Data...")
        sanitized_results = self.test_attack_on_sanitized_data()
        
        if sanitized_results is None:
            return None
        
        # Compare results
        print("\n" + "=" * 70)
        print("COMPARISON RESULTS")
        print("=" * 70)
        
        baseline_acc = baseline_results['test_accuracy']
        sanitized_acc = sanitized_results['test_accuracy']
        reduction = baseline_acc - sanitized_acc
        reduction_pct = (reduction / baseline_acc * 100) if baseline_acc > 0 else 0
        
        print(f"\nBaseline Attack Accuracy: {baseline_acc*100:.2f}%")
        print(f"Sanitized Data Attack Accuracy: {sanitized_acc*100:.2f}%")
        print(f"Accuracy Reduction: {reduction*100:.2f} percentage points ({reduction_pct:.1f}% reduction)")
        
        print("\n" + "=" * 70)
        print("[SUCCESS] Sanitization testing complete!")
        print("=" * 70)
        
        return {
            'baseline': baseline_results,
            'sanitized': sanitized_results,
            'reduction': reduction,
            'reduction_percentage': reduction_pct
        }


if __name__ == '__main__':
    print("=" * 70)
    print("RIGOROUS SANITIZATION ATTACK TEST")
    print("=" * 70)
    
    tester = SanitizationAttackTest()
    results = tester.run_comparison()
    
    if results:
        print("\n[SAVED] Results show actual attack performance on sanitized data")
        print("This is a more rigorous test than just measuring leakage reduction")

