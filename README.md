# Tracking the Trackers: Privacy Attacks and Defenses in Healthcare Web Systems

**CS 5510 Final Project - Progress Report Implementation**

Team: Nicholas Ramirez-Ornelas, Kai Xue, Benjamin Tran, Andrew Tarng

## Overview

**Work in Progress** - This project is under active development for CS 5510 Final Project.

This project demonstrates privacy leakage in healthcare web portals through tracking scripts, implements membership inference attacks, and evaluates differential privacy defenses. Replicates findings similar to the 2024 Kaiser Permanente incident.

## Quick Start

### Installation
```bash
pip install -r requirements.txt
npm install
```

### Run Complete Experiment
```bash
python run_experiment.py
```

This generates 500 sessions, runs attacks, tests defenses, and produces `analysis_results.json`.

### Run Live System
```bash
# Terminal 1: Start tracker
node tracker_server.js

# Terminal 2: Start portal
python app.py

# Visit http://localhost:5000
```

## What's Implemented

- **Flask Healthcare Portal** - Login, search, session tracking  
- **JavaScript Trackers** - Embedded tracking scripts  
- **Node.js Tracking Server** - Event logging to SQLite  
- **Synthetic Session Simulator** - Generates user sessions with varied behavior
- **Membership Inference Attack** - ML-based attack model
- **Privacy Defenses** - CSP headers, sanitization, differential privacy  
- **Analysis Tools** - Leakage metrics, attack evaluation

## Project Structure

```
CS5510FinalProject/
├── app.py                          # Flask healthcare portal
├── templates/                      # HTML templates with embedded trackers
│   ├── base.html                  # Base template with JavaScript tracker
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── search.html
│   └── topic.html
├── tracker_server.js              # Node.js tracking server
├── package.json                   # Node.js dependencies
├── simulate_sessions.py           # Generate 500 synthetic sessions
├── membership_inference_attack.py # Membership inference attack implementation
├── privacy_defenses.py            # CSP headers and sanitization
├── differential_privacy.py        # Laplace mechanism for DP
├── analyze_results.py             # Comprehensive analysis scripts
├── requirements.txt               # Python dependencies
└── README.md                      # This file
```

## Manual Step-by-Step

If you prefer to run components individually:

```bash
# 1. Generate data
python simulate_sessions.py

# 2. Run attack
python membership_inference_attack.py

# 3. Analyze results
python analyze_results.py
```

## Key Results (Preliminary)

### Privacy Leakage
- **41%** of sessions resulted in potential privacy leakage
- Sensitive terms transmitted: oncology, HIV, mental health
- Leakage types: URL parameters, page titles, search queries

### Membership Inference Attack
- **78%** inference accuracy with no defensive mechanisms
- Successfully identifies if user visited sensitive pages
- Uses only anonymized tracker logs

### Differential Privacy Defense
- **12-15%** reduction in attack success rate
- Epsilon = 1.0 provides reasonable privacy-utility tradeoff
- Maintains acceptable analytics accuracy

## Files Generated

- `healthcare_portal.db` - Portal data
- `tracker_data.db` - Tracking events  
- `analysis_results.json` - Results

## Notes

- Uses only synthetic data (no real PHI/PII)
- All components run locally
- Educational/research purposes only
- Implements progress report milestone (Nov 12, 2025)

