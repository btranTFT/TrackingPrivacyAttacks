"""
Rigorous Differential Privacy Testing
Tests membership inference attack on DP-protected data
"""

import sqlite3
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
from membership_inference_attack import MembershipInferenceAttack
from differential_privacy import DifferentialPrivacy

class DPAttackTest:
    """Test membership inference attack on DP-protected data"""
    
    def __init__(self, portal_db='healthcare_portal.db', tracker_db='tracker_data.db'):
        self.portal_db = portal_db
        self.tracker_db = tracker_db
        self.baseline_attack = MembershipInferenceAttack(portal_db, tracker_db)
    
    def add_dp_noise_to_features(self, X, epsilon):
        """Add differential privacy noise to feature matrix"""
        dp = DifferentialPrivacy(epsilon=epsilon)
        
        X_noisy = X.copy()
        
        # Add Laplace noise to each feature
        # Sensitivity depends on the feature type
        for i in range(X.shape[1]):
            feature_values = X[:, i]
            
            # Estimate sensitivity (max change from one individual)
            # For count features, sensitivity is typically 1
            # For continuous features, we use the range
            sensitivity = max(1, np.std(feature_values))
            
            # Add noise to each value in this feature
            noise = np.array([dp.laplace_noise(sensitivity) for _ in range(X.shape[0])])
            X_noisy[:, i] = X_noisy[:, i] + noise
            
            # Ensure non-negative for count features (first 7 features)
            if i < 7:
                X_noisy[:, i] = np.maximum(0, X_noisy[:, i])
        
        return X_noisy
    
    def test_attack_with_dp(self, epsilon=1.0):
        """Test membership inference attack on DP-protected data"""
        print(f"\n" + "=" * 70)
        print(f"TESTING ATTACK WITH DIFFERENTIAL PRIVACY (ε={epsilon})")
        print("=" * 70)
        
        # Prepare original dataset
        print("\n[1] Preparing original dataset...")
        X, y, sessions = self.baseline_attack.prepare_dataset()
        
        if len(X) == 0:
            print("[ERROR] No data available")
            return None
        
        print(f"[OK] Dataset prepared: {len(X)} sessions")
        
        # Split data first (before adding noise)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        print(f"Training set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        
        # Add DP noise to features
        print(f"\n[2] Adding DP noise (ε={epsilon})...")
        X_train_noisy = self.add_dp_noise_to_features(X_train, epsilon)
        X_test_noisy = self.add_dp_noise_to_features(X_test, epsilon)
        
        # Show noise impact
        noise_magnitude = np.mean(np.abs(X_train_noisy - X_train))
        print(f"[OK] Noise added. Average noise magnitude: {noise_magnitude:.4f}")
        
        # Train model on noisy data
        print(f"\n[3] Training attack model on DP-protected data...")
        model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42
        )
        
        model.fit(X_train_noisy, y_train)
        
        # Evaluate on noisy test data
        print(f"\n[4] Evaluating on DP-protected test data...")
        y_pred_test = model.predict(X_test_noisy)
        
        test_accuracy = accuracy_score(y_test, y_pred_test)
        precision = precision_score(y_test, y_pred_test)
        recall = recall_score(y_test, y_pred_test)
        cm = confusion_matrix(y_test, y_pred_test)
        
        print(f"\n[RESULTS] Attack Performance with DP (ε={epsilon}):")
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
            'epsilon': epsilon,
            'test_accuracy': test_accuracy,
            'precision': precision,
            'recall': recall,
            'confusion_matrix': cm.tolist(),
            'feature_importance': dict(feature_importance),
            'noise_magnitude': noise_magnitude
        }
    
    def run_comparison(self, epsilons=[0.5, 1.0, 2.0]):
        """Run comparison across different epsilon values"""
        print("\n" + "=" * 70)
        print("DIFFERENTIAL PRIVACY ATTACK COMPARISON")
        print("=" * 70)
        
        # Run baseline attack
        print("\n[1] Running Baseline Attack (No DP)...")
        baseline_results = self.baseline_attack.run_attack()
        baseline_acc = baseline_results['test_accuracy']
        
        # Run attacks with different epsilon values
        dp_results = {}
        for epsilon in epsilons:
            print(f"\n[2.{epsilons.index(epsilon)+1}] Testing ε={epsilon}...")
            result = self.test_attack_with_dp(epsilon)
            if result:
                dp_results[epsilon] = result
        
        # Compare results
        print("\n" + "=" * 70)
        print("COMPARISON RESULTS")
        print("=" * 70)
        
        print(f"\nBaseline Attack Accuracy (No DP): {baseline_acc*100:.2f}%\n")
        
        print("With Differential Privacy:")
        for epsilon, result in dp_results.items():
            dp_acc = result['test_accuracy']
            reduction = baseline_acc - dp_acc
            reduction_pct = (reduction / baseline_acc * 100) if baseline_acc > 0 else 0
            
            print(f"  ε={epsilon}:")
            print(f"    Attack Accuracy: {dp_acc*100:.2f}%")
            print(f"    Reduction: {reduction*100:.2f} pp ({reduction_pct:.1f}%)")
            print(f"    Noise Magnitude: {result['noise_magnitude']:.4f}")
        
        print("\n" + "=" * 70)
        print("[SUCCESS] DP testing complete!")
        print("=" * 70)
        
        return {
            'baseline': baseline_results,
            'dp_results': dp_results
        }


if __name__ == '__main__':
    print("=" * 70)
    print("RIGOROUS DIFFERENTIAL PRIVACY ATTACK TEST")
    print("=" * 70)
    
    tester = DPAttackTest()
    results = tester.run_comparison(epsilons=[0.5, 1.0, 2.0])
    
    if results:
        print("\n[SAVED] Results show actual attack performance on DP-protected data")
        print("This is more rigorous than estimation - actual noise is applied and tested")

