"""
Differential Privacy Mechanisms
Implements Laplace mechanism for adding noise to analytics data
Target: 12-15% reduction in attack success rate with epsilon=1.0
"""

import numpy as np
import sqlite3
from collections import defaultdict
import json

class DifferentialPrivacy:
    """
    Differential Privacy implementation using Laplace mechanism
    """
    
    def __init__(self, epsilon=1.0):
        """
        Initialize DP mechanism
        
        Args:
            epsilon: Privacy parameter (smaller = more privacy, more noise)
                    epsilon=1.0 provides reasonable privacy-utility tradeoff
        """
        self.epsilon = epsilon
        self.noise_added_count = 0
    
    def laplace_noise(self, sensitivity, size=1):
        """
        Generate Laplace noise
        
        Args:
            sensitivity: Sensitivity of the query (max change from adding/removing one record)
            size: Number of noise values to generate
        
        Returns:
            Noise value(s) from Laplace distribution
        """
        scale = sensitivity / self.epsilon
        noise = np.random.laplace(0, scale, size)
        self.noise_added_count += size if isinstance(size, int) else 1
        return noise if size > 1 else noise[0]
    
    def add_noise_to_count(self, true_count, sensitivity=1):
        """
        Add Laplace noise to a count query
        
        Args:
            true_count: True count value
            sensitivity: Sensitivity of count query (default=1)
        
        Returns:
            Noisy count (rounded to integer, non-negative)
        """
        noise = self.laplace_noise(sensitivity)
        noisy_count = true_count + noise
        
        # Ensure non-negative and round to integer
        return max(0, int(round(noisy_count)))
    
    def add_noise_to_average(self, true_average, count, value_range):
        """
        Add Laplace noise to an average query
        
        Args:
            true_average: True average value
            count: Number of records in average
            value_range: Range of possible values (max - min)
        
        Returns:
            Noisy average
        """
        if count == 0:
            return 0
        
        # Sensitivity of average is range/count
        sensitivity = value_range / count
        noise = self.laplace_noise(sensitivity)
        
        return true_average + noise
    
    def add_noise_to_histogram(self, histogram, sensitivity=1):
        """
        Add Laplace noise to histogram bins
        
        Args:
            histogram: Dictionary of {category: count}
            sensitivity: Sensitivity per bin (default=1)
        
        Returns:
            Noisy histogram
        """
        noisy_histogram = {}
        
        for category, count in histogram.items():
            noisy_count = self.add_noise_to_count(count, sensitivity)
            noisy_histogram[category] = noisy_count
        
        return noisy_histogram
    
    def privatize_analytics_report(self, analytics_data):
        """
        Apply differential privacy to analytics report
        
        Args:
            analytics_data: Dictionary containing analytics metrics
        
        Returns:
            Privatized analytics data
        """
        privatized = {}
        
        for key, value in analytics_data.items():
            if isinstance(value, int):
                # Add noise to counts
                privatized[key] = self.add_noise_to_count(value)
            elif isinstance(value, float):
                # Add noise to averages (assuming range 0-100 for percentages)
                privatized[key] = value + self.laplace_noise(sensitivity=1.0)
            elif isinstance(value, dict):
                # Recursively privatize nested dictionaries
                privatized[key] = self.add_noise_to_histogram(value)
            else:
                # Keep other types as-is
                privatized[key] = value
        
        return privatized


class DPAnalyticsServer:
    """
    Analytics server with differential privacy
    """
    
    def __init__(self, tracker_db='tracker_data.db', epsilon=1.0):
        self.tracker_db = tracker_db
        self.dp = DifferentialPrivacy(epsilon=epsilon)
        self.epsilon = epsilon
    
    def get_private_event_counts(self):
        """
        Get event counts with differential privacy
        """
        conn = sqlite3.connect(self.tracker_db)
        cursor = conn.cursor()
        
        # Get true counts
        cursor.execute('SELECT event_type, COUNT(*) FROM tracking_events GROUP BY event_type')
        results = cursor.fetchall()
        
        conn.close()
        
        # Build histogram
        true_histogram = {event_type: count for event_type, count in results}
        
        # Add noise
        private_histogram = self.dp.add_noise_to_histogram(true_histogram)
        
        return {
            'true': true_histogram,
            'private': private_histogram,
            'epsilon': self.epsilon
        }
    
    def get_private_session_statistics(self):
        """
        Get session statistics with differential privacy
        """
        conn = sqlite3.connect(self.tracker_db)
        cursor = conn.cursor()
        
        # Total sessions
        cursor.execute('SELECT COUNT(DISTINCT session_id) FROM tracking_events')
        true_total_sessions = cursor.fetchone()[0]
        
        # Sessions with leakage
        cursor.execute('SELECT COUNT(DISTINCT session_id) FROM leakage_analysis WHERE has_sensitive_leak = 1')
        true_leakage_sessions = cursor.fetchone()[0]
        
        conn.close()
        
        # Add noise
        private_total_sessions = self.dp.add_noise_to_count(true_total_sessions)
        private_leakage_sessions = self.dp.add_noise_to_count(true_leakage_sessions)
        
        # Calculate rates
        true_leakage_rate = (true_leakage_sessions / true_total_sessions * 100) if true_total_sessions > 0 else 0
        private_leakage_rate = (private_leakage_sessions / private_total_sessions * 100) if private_total_sessions > 0 else 0
        
        return {
            'total_sessions': {
                'true': true_total_sessions,
                'private': private_total_sessions
            },
            'leakage_sessions': {
                'true': true_leakage_sessions,
                'private': private_leakage_sessions
            },
            'leakage_rate': {
                'true': f"{true_leakage_rate:.2f}%",
                'private': f"{private_leakage_rate:.2f}%"
            },
            'epsilon': self.epsilon
        }
    
    def get_private_page_visit_distribution(self):
        """
        Get page visit distribution with differential privacy
        """
        conn = sqlite3.connect(self.tracker_db)
        cursor = conn.cursor()
        
        # Get page visit counts
        cursor.execute('''SELECT page_title, COUNT(*) as count 
                         FROM tracking_events 
                         WHERE event_type = 'page_view' 
                         GROUP BY page_title 
                         ORDER BY count DESC 
                         LIMIT 20''')
        results = cursor.fetchall()
        
        conn.close()
        
        # Build histogram
        true_histogram = {page: count for page, count in results}
        
        # Add noise
        private_histogram = self.dp.add_noise_to_histogram(true_histogram)
        
        return {
            'true': true_histogram,
            'private': private_histogram,
            'epsilon': self.epsilon
        }
    
    def export_private_dataset(self, output_file='private_analytics.json'):
        """
        Export privatized analytics dataset
        """
        print(f"📊 Generating private analytics report (ε={self.epsilon})...")
        
        report = {
            'epsilon': self.epsilon,
            'privacy_mechanism': 'Laplace Mechanism',
            'event_counts': self.get_private_event_counts(),
            'session_statistics': self.get_private_session_statistics(),
            'page_visits': self.get_private_page_visit_distribution(),
            'noise_applications': self.dp.noise_added_count
        }
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✓ Private analytics saved to {output_file}")
        print(f"  Total noise applications: {self.dp.noise_added_count}")
        
        return report


class DPTrackingServer:
    """
    Modified tracking server that applies DP before storing data
    """
    
    def __init__(self, epsilon=1.0):
        self.dp = DifferentialPrivacy(epsilon=epsilon)
    
    def privatize_event_before_storage(self, event_data):
        """
        Apply differential privacy to event data before storage
        This adds noise to numerical fields
        """
        privatized = event_data.copy()
        
        # Add noise to time measurements
        if 'time_on_page_seconds' in privatized:
            true_time = privatized['time_on_page_seconds']
            # Sensitivity: assume max time is 3600 seconds (1 hour)
            noisy_time = true_time + self.dp.laplace_noise(sensitivity=10)
            privatized['time_on_page_seconds'] = max(0, int(noisy_time))
        
        if 'load_time' in privatized:
            true_load = privatized['load_time']
            noisy_load = true_load + self.dp.laplace_noise(sensitivity=100)
            privatized['load_time'] = max(0, int(noisy_load))
        
        return privatized


def compare_privacy_utility_tradeoff(epsilons=[0.1, 0.5, 1.0, 2.0, 5.0]):
    """
    Compare privacy-utility tradeoff across different epsilon values
    """
    print("=" * 70)
    print("DIFFERENTIAL PRIVACY: PRIVACY-UTILITY TRADEOFF ANALYSIS")
    print("=" * 70)
    
    results = []
    
    for eps in epsilons:
        print(f"\nTesting ε = {eps}")
        print("-" * 70)
        
        server = DPAnalyticsServer(epsilon=eps)
        stats = server.get_private_session_statistics()
        
        true_total = stats['total_sessions']['true']
        private_total = stats['total_sessions']['private']
        
        true_leakage = stats['leakage_sessions']['true']
        private_leakage = stats['leakage_sessions']['private']
        
        # Calculate utility loss (error)
        total_error = abs(private_total - true_total)
        leakage_error = abs(private_leakage - true_leakage)
        
        total_error_pct = (total_error / true_total * 100) if true_total > 0 else 0
        leakage_error_pct = (leakage_error / true_leakage * 100) if true_leakage > 0 else 0
        
        print(f"  Total Sessions: {true_total} → {private_total} (error: {total_error_pct:.1f}%)")
        print(f"  Leakage Sessions: {true_leakage} → {private_leakage} (error: {leakage_error_pct:.1f}%)")
        print(f"  True Leakage Rate: {stats['leakage_rate']['true']}")
        print(f"  Private Leakage Rate: {stats['leakage_rate']['private']}")
        
        results.append({
            'epsilon': eps,
            'total_error_pct': total_error_pct,
            'leakage_error_pct': leakage_error_pct,
            'true_leakage_rate': stats['leakage_rate']['true'],
            'private_leakage_rate': stats['leakage_rate']['private']
        })
    
    print("\n" + "=" * 70)
    print("SUMMARY: Privacy Budget vs Utility Loss")
    print("=" * 70)
    print(f"{'Epsilon':<10} {'Total Error':<15} {'Leakage Error':<15} {'Privacy Level':<15}")
    print("-" * 70)
    
    for r in results:
        privacy_level = "High" if r['epsilon'] < 1.0 else "Medium" if r['epsilon'] < 3.0 else "Low"
        print(f"{r['epsilon']:<10} {r['total_error_pct']:<14.1f}% {r['leakage_error_pct']:<14.1f}% {privacy_level:<15}")
    
    return results


if __name__ == '__main__':
    # Test differential privacy mechanisms
    print("Testing Differential Privacy Mechanisms")
    print("=" * 70)
    
    # Test basic Laplace mechanism
    print("\n1. Basic Laplace Mechanism Test:")
    dp = DifferentialPrivacy(epsilon=1.0)
    
    true_count = 100
    print(f"   True count: {true_count}")
    
    noisy_counts = [dp.add_noise_to_count(true_count) for _ in range(10)]
    print(f"   Noisy counts (10 samples): {noisy_counts}")
    print(f"   Average noisy count: {np.mean(noisy_counts):.2f}")
    print(f"   Standard deviation: {np.std(noisy_counts):.2f}")
    
    # Test analytics server
    print("\n2. Private Analytics Server Test:")
    server = DPAnalyticsServer(epsilon=1.0)
    
    try:
        stats = server.get_private_session_statistics()
        print(f"   Session Statistics (ε=1.0):")
        print(f"   - Total sessions: {stats['total_sessions']['true']} → {stats['total_sessions']['private']}")
        print(f"   - Leakage sessions: {stats['leakage_sessions']['true']} → {stats['leakage_sessions']['private']}")
        print(f"   - Leakage rate: {stats['leakage_rate']['true']} → {stats['leakage_rate']['private']}")
    except Exception as e:
        print(f"   Note: Run simulate_sessions.py first to generate data")
    
    # Test privacy-utility tradeoff
    print("\n3. Privacy-Utility Tradeoff Analysis:")
    try:
        compare_privacy_utility_tradeoff()
    except Exception as e:
        print(f"   Note: Run simulate_sessions.py first to generate data")

