import os
import re
import json
import csv
import urllib.parse
from datetime import datetime
import uuid
from flask import Flask, render_template, request, jsonify, send_file, make_response

app = Flask(__name__)

# File paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(BASE_DIR, 'data', 'history.json')
EXPORTS_DIR = os.path.join(BASE_DIR, 'exports')

# Ensure directories exist
os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
os.makedirs(EXPORTS_DIR, exist_ok=True)

# Common URL shorteners
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'rebrand.ly', 
    'is.gd', 'buff.ly', 'ow.ly', 'bit.do', 'lnkd.in', 'db.tt', 'qr.ae'
}

# Suspicious keywords in phishing attacks
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'update', 'bank', 'account', 'signin', 'confirm', 'password', 'security']

def load_history():
    """Load scan history from JSON file."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading history: {e}")
        return []

def save_history(history):
    """Save scan history to JSON file."""
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving history: {e}")
        return False

def check_ip_address(hostname):
    """Check if the hostname is an IP address."""
    # IPv4 Pattern
    ipv4_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    # IPv6 Pattern (Basic check)
    ipv6_pattern = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    
    if ipv4_pattern.match(hostname) or ipv6_pattern.match(hostname):
        return True
    return False

def analyze_url(url):
    """Analyze a URL and calculate its phishing risk score."""
    # Clean URL
    url = url.strip()
    
    # Prepend http:// if no scheme is specified for proper parsing
    parsed_url = urllib.parse.urlparse(url)
    original_scheme = parsed_url.scheme
    
    if not parsed_url.scheme:
        url_to_parse = 'http://' + url
        parsed_url = urllib.parse.urlparse(url_to_parse)
    else:
        url_to_parse = url
        
    hostname = parsed_url.netloc or parsed_url.path.split('/')[0]
    # Remove port if present in hostname
    if ':' in hostname:
        hostname = hostname.split(':')[0]

    risk_score = 0
    details = []

    # 1. HTTPS Check
    # If the user entered http:// or did not enter a scheme, we flag it as insecure (since we default to http)
    # If they entered https://, it passes this check.
    is_https = original_scheme.lower() == 'https' if original_scheme else False
    if is_https:
        details.append({
            'check': 'HTTPS Availability',
            'status': 'pass',
            'message': 'Website uses secure HTTPS encryption.',
            'impact': 0
        })
    else:
        risk_score += 25
        details.append({
            'check': 'HTTPS Availability',
            'status': 'fail',
            'message': 'Website does not use HTTPS encryption (HTTP is insecure).',
            'impact': 25
        })

    # 2. URL Length Check
    url_len = len(url)
    if url_len > 75:
        risk_score += 30
        details.append({
            'check': 'URL Length',
            'status': 'fail',
            'message': f'URL is extremely long ({url_len} chars). Phishing URLs often hide details in long paths.',
            'impact': 30
        })
    elif url_len > 54:
        risk_score += 15
        details.append({
            'check': 'URL Length',
            'status': 'warning',
            'message': f'URL is moderately long ({url_len} chars). It could be hiding suspicious text.',
            'impact': 15
        })
    else:
        details.append({
            'check': 'URL Length',
            'status': 'pass',
            'message': f'URL length is safe ({url_len} chars).',
            'impact': 0
        })

    # 3. Presence of IP Address as Hostname
    has_ip = check_ip_address(hostname)
    if has_ip:
        risk_score += 30
        details.append({
            'check': 'IP Address in Domain',
            'status': 'fail',
            'message': 'Hostname is an IP address. Legit websites almost always use domain names.',
            'impact': 30
        })
    else:
        details.append({
            'check': 'IP Address in Domain',
            'status': 'pass',
            'message': 'Hostname is a registered domain name (not an IP address).',
            'impact': 0
        })

    # 4. Presence of '@' Symbol
    # The '@' symbol redirects the browser to the domain specified after it, ignoring everything before
    if '@' in url_to_parse:
        risk_score += 25
        details.append({
            'check': 'Presence of "@" Symbol',
            'status': 'fail',
            'message': 'URL contains "@". Phishing sites use this to trick users into ignoring the real domain.',
            'impact': 25
        })
    else:
        details.append({
            'check': 'Presence of "@" Symbol',
            'status': 'pass',
            'message': 'No "@" symbol detected in the URL.',
            'impact': 0
        })

    # 5. Number of Subdomains
    # Split the domain by dots. E.g., 'sub1.sub2.example.com' has parts ['sub1', 'sub2', 'example', 'com']
    clean_host = hostname
    if clean_host.startswith('www.'):
        clean_host = clean_host[4:]
        
    dot_count = clean_host.count('.')
    # Standard domain: example.com (1 dot). Subdomain: sub.example.com (2 dots)
    if dot_count > 4:
        risk_score += 25
        details.append({
            'check': 'Subdomain Count',
            'status': 'fail',
            'message': f'Multiple subdomains detected ({dot_count}). Phishing URLs mimic subdomains of popular brands.',
            'impact': 25
        })
    elif dot_count > 2:
        risk_score += 15
        details.append({
            'check': 'Subdomain Count',
            'status': 'warning',
            'message': f'Several subdomains detected ({dot_count}). Suspicious URL structure.',
            'impact': 15
        })
    else:
        details.append({
            'check': 'Subdomain Count',
            'status': 'pass',
            'message': 'Subdomain count is in normal range.',
            'impact': 0
        })

    # 6. Suspicious Keywords Check
    found_keywords = []
    lower_url = url_to_parse.lower()
    for word in SUSPICIOUS_KEYWORDS:
        # Check domain and path for exact word match
        if word in lower_url:
            found_keywords.append(word)
            
    if found_keywords:
        keyword_impact = min(len(found_keywords) * 15, 50)  # Max 50% impact
        risk_score += keyword_impact
        details.append({
            'check': 'Suspicious Keywords',
            'status': 'fail',
            'message': f'Suspicious keyword(s) detected: {", ".join(found_keywords)}. These are common in credential theft.',
            'impact': keyword_impact
        })
    else:
        details.append({
            'check': 'Suspicious Keywords',
            'status': 'pass',
            'message': 'No typical phishing keywords found.',
            'impact': 0
        })

    # 7. URL Shortening Services
    is_shortened = hostname.lower() in SHORTENERS
    if is_shortened:
        risk_score += 20
        details.append({
            'check': 'Shortening Service',
            'status': 'warning',
            'message': 'Uses a URL shortening service. These are commonly used to mask malicious final destinations.',
            'impact': 20
        })
    else:
        details.append({
            'check': 'Shortening Service',
            'status': 'pass',
            'message': 'Not using a known URL shortening service.',
            'impact': 0
        })

    # 8. Domain Hyphenation Check
    if '-' in hostname:
        risk_score += 15
        details.append({
            'check': 'Domain Hyphenation',
            'status': 'warning',
            'message': 'Domain name contains hyphens ("-"). Phishing sites frequently use hyphens to combine brand names with fake words.',
            'impact': 15
        })
    else:
        details.append({
            'check': 'Domain Hyphenation',
            'status': 'pass',
            'message': 'Domain name does not contain hyphens.',
            'impact': 0
        })

    # 9. Suspicious TLD Check
    SUSPICIOUS_TLDS = {'.cn', '.xyz', '.top', '.club', '.work', '.fit', '.gq', '.cf', '.tk', '.ml', '.ga', '.cc'}
    has_suspicious_tld = any(hostname.lower().endswith(tld) for tld in SUSPICIOUS_TLDS)
    if has_suspicious_tld:
        risk_score += 15
        details.append({
            'check': 'Top-Level Domain (TLD) Safety',
            'status': 'warning',
            'message': 'Website uses a top-level domain frequently associated with low cost and malicious registrations.',
            'impact': 15
        })
    else:
        details.append({
            'check': 'Top-Level Domain (TLD) Safety',
            'status': 'pass',
            'message': 'Website uses a standard or highly trusted top-level domain.',
            'impact': 0
        })

    # 10. Special Characters check
    special_chars = ['@', '?', '=', '&', '_', '%', '+', '-']
    found_specials = [c for c in special_chars if c in url_to_parse]
    if found_specials:
        # Calculate impact based on count of distinct suspicious special characters
        char_impact = min(len(found_specials) * 5, 20)
        risk_score += char_impact
        details.append({
            'check': 'Special Characters',
            'status': 'warning' if len(found_specials) < 3 else 'fail',
            'message': f'URL contains special characters ({", ".join(found_specials)}) often used to carry parameters or obscure redirection.',
            'impact': char_impact
        })
    else:
        details.append({
            'check': 'Special Characters',
            'status': 'pass',
            'message': 'No suspicious special characters detected in the URL.',
            'impact': 0
        })

    # Bound risk score between 0 and 100
    risk_score = min(max(risk_score, 0), 100)

    # Determine Safety Category
    if risk_score <= 30:
        category = 'Safe'
    elif risk_score <= 70:
        category = 'Suspicious'
    else:
        category = 'Dangerous'

    return {
        'id': str(uuid.uuid4()),
        'url': url,
        'hostname': hostname,
        'risk_score': risk_score,
        'category': category,
        'details': details,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/history')
def history():
    return render_template('history.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'Please enter a valid URL.'}), 400

    # Basic regex validation for url presence
    # Allow domains without protocol as well (e.g. google.com)
    if not re.match(r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$', url) and not check_ip_address(url.split('/')[0]):
        # Let's check if it has at least one dot and some characters
        if '.' not in url or len(url) < 4:
            return jsonify({'error': 'The URL format appears invalid. Please check and try again.'}), 400

    # Perform analysis
    result = analyze_url(url)
    
    # Save to history
    history = load_history()
    history.insert(0, result) # Store new scan at the beginning
    save_history(history)
    
    return jsonify(result)

@app.route('/api/history', methods=['GET'])
def get_history():
    history = load_history()
    return jsonify(history)

@app.route('/api/history/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    history = load_history()
    updated_history = [scan for scan in history if scan.get('id') != scan_id]
    
    if len(history) == len(updated_history):
        return jsonify({'error': 'Scan ID not found.'}), 404
        
    save_history(updated_history)
    return jsonify({'success': 'Scan deleted successfully.'})

@app.route('/api/history/clear', methods=['POST'])
def clear_history():
    save_history([])
    return jsonify({'success': 'All history cleared successfully.'})

@app.route('/api/history/export', methods=['GET'])
def export_history():
    history = load_history()
    
    # Create CSV in memory
    csv_filename = f"scan_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    csv_filepath = os.path.join(EXPORTS_DIR, csv_filename)
    
    try:
        with open(csv_filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'URL', 'Hostname', 'Risk Score (%)', 'Category', 'Timestamp'])
            for scan in history:
                writer.writerow([
                    scan.get('id', ''),
                    scan.get('url', ''),
                    scan.get('hostname', ''),
                    scan.get('risk_score', 0),
                    scan.get('category', ''),
                    scan.get('timestamp', '')
                ])
        
        return send_file(
            csv_filepath,
            mimetype='text/csv',
            as_attachment=True,
            download_name=csv_filename
        )
    except Exception as e:
        return jsonify({'error': f'Failed to generate CSV: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
