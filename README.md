# Phishing Website Detector - PhishGuard Portal

A professional full-stack cybersecurity web application designed to analyze URLs and identify potential phishing risks, fake portal login sites, and social engineering threats. Built as a desktop & mobile responsive dashboard, this application serves as an excellent Academic / College project for Cyber Security students.

---

## 🛠️ Tech Stack & Architecture

- **Backend Framework**: Python Flask
- **Frontend UI**: HTML5, CSS3, JavaScript, Bootstrap 5, Font Awesome 6
- **Data Persistence**: JSON-based flat-file database (`data/history.json`)
- **Charting & Data Visualization**: Chart.js
- **Styling Paradigm**: Custom glassmorphic cybersecurity theme with animated neon components and responsive overrides.

---

## 🔍 Heuristic Scan Parameters

The detection engine performs structural analysis on the input URL, evaluating risk weights across several critical features:

1. **HTTPS availability**: Checks for active TLS/SSL encryption. Lack of HTTPS signals high interception risk (+25% risk).
2. **URL Length**: Suspiciously long URLs commonly mask malicious parameters. URL length > 54 chars (+15% risk) and > 75 chars (+30% risk).
3. **IP Address in Hostname**: Assesses if the host matches an IPv4/IPv6 pattern. Genuine portals use domain names, not raw IPs (+30% risk).
4. **Presence of `@` Symbol**: The `@` character directs browsers to ignore everything preceding it, masking the destination domain (+25% risk).
5. **Subdomain Count**: Count of dots in the hostname (excluding www). Phishing sites mock trusted brand names as subdomains. Dots > 2 (+15% risk) and dots > 4 (+25% risk).
6. **Suspicious Keyword Matching**: Scans for patterns such as `login`, `verify`, `secure`, `bank`, `account`, `signin`, `confirm`, `password` inside the URL (+20% risk per keyword, capped at +40%).
7. **URL Shortening Detection**: Identifies usage of redirection services (`bit.ly`, `tinyurl.com`, etc.) used to obscure destinations (+20% risk).

Risk ratings:
- **0% - 30%**: **Safe** (Green Card)
- **31% - 70%**: **Suspicious** (Yellow Card with Warning details)
- **71% - 100%**: **Dangerous** (Red Card with Warning details & Threat Alert)

---

## 📂 Project Directory Structure

```text
phishing-website-detector/
│
├── app.py                      # Core Flask backend server
├── requirements.txt            # Python environment packages
├── README.md                   # Project documentation
│
├── templates/
│   ├── base.html               # Master layout containing navigation and footer
│   ├── index.html              # URL Scanner home page
│   ├── dashboard.html          # Statistics and telemetry widgets
│   ├── history.html            # Scan audit records with search and delete triggers
│   └── about.html              # Educational cybersecurity portal
│
├── static/
│   ├── css/
│   │     style.css             # Glassmorphic cyber theme and layout animations
│   ├── js/
│   │     script.js             # Form controls, chart renders, filters, and theme toggle
│   └── images/
│         logo.png              # Generated PhishGuard branding banner
│
├── data/
│   └── history.json            # JSON scan history repository
│
└── exports/                    # Target folder for CSV reports
```

---

## 🚀 Getting Started & Execution

Follow these steps to run the application on your local machine:

### 1. Prerequisite Installations
Make sure you have **Python 3.8+** installed. You can check your version using:
```bash
python --version
```

### 2. Set Up a Virtual Environment (Recommended)
Navigate to the project root directory and create a virtual environment:
```bash
python -m venv venv
```
Activate the environment:
- **Windows (cmd)**: `venv\Scripts\activate.bat`
- **Windows (PowerShell)**: `venv\Scripts\Activate.ps1`
- **macOS/Linux**: `source venv/bin/activate`

### 3. Install Dependencies
Install all required packages from `requirements.txt`:
```bash
pip install -r requirements.txt
```

### 4. Run the Application
Execute the Flask server:
```bash
python app.py
```
By default, the server runs on `http://127.0.0.1:5000/`.

---

## 🛡️ Core Features Highlights

1. **Dashboard Analytics**: A dynamic overview showing total scans, percentage classifications, and an interactive Chart.js doughnut chart detailing risk distributions.
2. **Searchable Logs**: Search database scans in real-time, remove entries, or wipe the database directly from the History tab.
3. **Data Export**: Export your entire scan history database into standard CSV formats.
4. **Responsive Theme**: Support for mobile and desktop screens along with a toggleable Light/Dark UI theme preset in local storage.
5. **Interactive UI**: Radar scan scanning simulations, glowing cyber-cards, micro-animations, and custom validation alerts.
