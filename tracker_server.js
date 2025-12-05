/**
 * Node.js Tracking Server
 * Receives tracking events from healthcare portal and logs to SQLite database
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;
const DB_PATH = './tracker_data.db';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Initialize tracking database
function initDatabase() {
    const db = new sqlite3.Database(DB_PATH);
    
    db.serialize(() => {
        // Tracking events table
        db.run(`CREATE TABLE IF NOT EXISTS tracking_events (
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
        )`);
        
        // Leakage analysis table
        db.run(`CREATE TABLE IF NOT EXISTS leakage_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            has_sensitive_leak INTEGER DEFAULT 0,
            sensitive_terms TEXT,
            leak_type TEXT,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        
        // Create indexes for performance
        db.run(`CREATE INDEX IF NOT EXISTS idx_session_id ON tracking_events(session_id)`);
        db.run(`CREATE INDEX IF NOT EXISTS idx_event_type ON tracking_events(event_type)`);
        db.run(`CREATE INDEX IF NOT EXISTS idx_timestamp ON tracking_events(timestamp)`);
    });
    
    db.close();
    console.log('Tracking database initialized');
}

// Sensitive terms that indicate potential privacy leakage
const SENSITIVE_TERMS = [
    'oncology', 'cancer', 'chemotherapy',
    'hiv', 'aids',
    'mental health', 'depression', 'anxiety', 'psychiatric',
    'abortion', 'pregnancy',
    'addiction', 'substance abuse',
    'std', 'sexually transmitted',
    'erectile dysfunction',
    'fertility'
];

// Analyze if event contains sensitive information
function analyzeSensitiveLeakage(eventData) {
    const sensitiveLeaks = [];
    const textToAnalyze = JSON.stringify(eventData).toLowerCase();
    
    for (const term of SENSITIVE_TERMS) {
        if (textToAnalyze.includes(term.toLowerCase())) {
            sensitiveLeaks.push(term);
        }
    }
    
    return {
        hasSensitiveLeak: sensitiveLeaks.length > 0,
        sensitiveTerms: sensitiveLeaks,
        leakType: determineLeakType(eventData, sensitiveLeaks)
    };
}

function determineLeakType(eventData, sensitiveTerms) {
    if (sensitiveTerms.length === 0) return 'none';
    
    const types = [];
    if (eventData.page_url && eventData.page_url.includes('?')) {
        types.push('url_parameter');
    }
    if (eventData.page_title) {
        types.push('page_title');
    }
    if (eventData.query) {
        types.push('search_query');
    }
    if (eventData.form_fields) {
        types.push('form_data');
    }
    
    return types.join(',') || 'other';
}

// Track endpoint - receives tracking events
app.post('/track', (req, res) => {
    const eventData = req.body;
    
    console.log('Received tracking event:', {
        type: eventData.event_type,
        session: eventData.session_id,
        page: eventData.page_title
    });
    
    // Analyze for sensitive leakage
    const leakageAnalysis = analyzeSensitiveLeakage(eventData);
    
    // Store in database
    const db = new sqlite3.Database(DB_PATH);
    
    db.serialize(() => {
        // Insert tracking event
        const stmt = db.prepare(`INSERT INTO tracking_events 
            (tracker_id, session_id, timestamp, event_type, page_url, page_title, 
             referrer, user_agent, screen_resolution, event_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        
        stmt.run(
            eventData.tracker_id,
            eventData.session_id,
            eventData.timestamp,
            eventData.event_type,
            eventData.page_url,
            eventData.page_title,
            eventData.referrer,
            eventData.user_agent,
            eventData.screen_resolution,
            JSON.stringify(eventData)
        );
        stmt.finalize();
        
        // If sensitive leakage detected, log it
        if (leakageAnalysis.hasSensitiveLeak) {
            console.log('⚠️  SENSITIVE LEAKAGE DETECTED:', {
                session: eventData.session_id,
                terms: leakageAnalysis.sensitiveTerms,
                type: leakageAnalysis.leakType
            });
            
            const leakStmt = db.prepare(`INSERT INTO leakage_analysis 
                (session_id, has_sensitive_leak, sensitive_terms, leak_type)
                VALUES (?, ?, ?, ?)`);
            
            leakStmt.run(
                eventData.session_id,
                1,
                JSON.stringify(leakageAnalysis.sensitiveTerms),
                leakageAnalysis.leakType
            );
            leakStmt.finalize();
        }
    });
    
    db.close();
    
    res.status(200).json({ 
        status: 'success',
        leakage_detected: leakageAnalysis.hasSensitiveLeak
    });
});

// Analytics endpoint - get tracking statistics
app.get('/analytics/stats', (req, res) => {
    const db = new sqlite3.Database(DB_PATH);
    
    const stats = {};
    
    db.serialize(() => {
        // Total events
        db.get('SELECT COUNT(*) as count FROM tracking_events', (err, row) => {
            stats.total_events = row ? row.count : 0;
        });
        
        // Unique sessions
        db.get('SELECT COUNT(DISTINCT session_id) as count FROM tracking_events', (err, row) => {
            stats.unique_sessions = row ? row.count : 0;
        });
        
        // Events by type
        db.all('SELECT event_type, COUNT(*) as count FROM tracking_events GROUP BY event_type', (err, rows) => {
            stats.events_by_type = rows || [];
        });
        
        // Leakage statistics
        db.get('SELECT COUNT(DISTINCT session_id) as count FROM leakage_analysis WHERE has_sensitive_leak = 1', (err, row) => {
            stats.sessions_with_leakage = row ? row.count : 0;
            
            // Calculate leakage rate
            if (stats.unique_sessions > 0) {
                stats.leakage_rate = (stats.sessions_with_leakage / stats.unique_sessions * 100).toFixed(2) + '%';
            }
            
            // Send response after all queries complete
            setTimeout(() => {
                res.json(stats);
            }, 100);
        });
    });
    
    db.close();
});

// Get sessions with sensitive leakage
app.get('/analytics/leakage', (req, res) => {
    const db = new sqlite3.Database(DB_PATH);
    
    db.all(`SELECT * FROM leakage_analysis WHERE has_sensitive_leak = 1 ORDER BY analyzed_at DESC LIMIT 100`, 
        (err, rows) => {
            if (err) {
                res.status(500).json({ error: err.message });
            } else {
                res.json(rows);
            }
            db.close();
        });
});

// Get all events for a specific session
app.get('/analytics/session/:sessionId', (req, res) => {
    const sessionId = req.params.sessionId;
    const db = new sqlite3.Database(DB_PATH);
    
    db.all(`SELECT * FROM tracking_events WHERE session_id = ? ORDER BY timestamp`, 
        [sessionId],
        (err, rows) => {
            if (err) {
                res.status(500).json({ error: err.message });
            } else {
                res.json(rows);
            }
            db.close();
        });
});

// Export data for analysis
app.get('/export/events', (req, res) => {
    const db = new sqlite3.Database(DB_PATH);
    
    db.all('SELECT * FROM tracking_events ORDER BY timestamp DESC', (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
        } else {
            res.json(rows);
        }
        db.close();
    });
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'tracker-server', port: PORT });
});

// Start server
app.listen(PORT, () => {
    console.log(`🔍 Tracker Server running on http://localhost:${PORT}`);
    console.log(`📊 Analytics available at http://localhost:${PORT}/analytics/stats`);
    initDatabase();
});

