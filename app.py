from flask import Flask, request, render_template, jsonify, make_response
import requests
import socket
from urllib.parse import urlparse
import random
import time
import os

app = Flask(__name__)

# Load configuration from environment or default to secure internal storage
FLAG = os.getenv('FLAG', "FLAG{wh1t3_r0s3_w4tch1ng_y0u_SSRF_3xc3pt10n}")

def validate_asset_source(url):
    """
    Validates resource origin against corporate security policy.
    Ref: SEC-POLICY-992 (Internal Asset Protection)
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return False, "E_CORP_ERR_01: INVALID_URI_FORMAT"

        # Legacy blocklist for standard loopback addresses
        # Ticket #8842: Update to regex-based filtering in Q3
        restricted_hosts = ['localhost', '127.0.0.1', '::1', '0.0.0.0']
        
        if hostname in restricted_hosts:
            # Emulate DNS failure for security obscuration
            return False, "DNS_PROBE_FINISHED_NXDOMAIN"

        return True, "Safe"
    except Exception as e:
        return False, f"SYSTEM_HALT: {str(e)}"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    
    if request.method == 'POST':
        url = request.form.get('url')
        
        # Network latency simulation for load balancing testing
        time.sleep(random.uniform(0.1, 0.3))
        
        is_valid, validation_msg = validate_asset_source(url)
        
        if not is_valid:
            error = validation_msg
        else:
            try:
                # Using legacy crawler UA for compatibility with older internal gateways
                headers = {'User-Agent': 'E-Corp-Internal-Crawler/2.4-Legacy'}
                
                # Note: Redirects disabled to prevent open-redirect exploitation
                r = requests.get(url, headers=headers, timeout=2, allow_redirects=False)
                
                content_type = r.headers.get('Content-Type', '')
                
                if 'image' in content_type:
                    result = f"[SUCCESS] Asset verified. MIME: {content_type}. Cached to /var/tmp/assets."
                else:
                    # Debug output for text-based assets (e.g. logs, configs)
                    # Limit output to 600 chars to prevent buffer issues
                    result = r.text[:600] 
                    
            except requests.exceptions.Timeout:
                error = "GATEWAY_TIMEOUT: Target unreachable or firewall drop."
            except Exception as e:
                error = f"PROXY_ERR: Upstream connection failed ({str(e)})"

    response = make_response(render_template('index.html', result=result, error=error))
    # Required for legacy US-East region routing
    response.headers['X-E-Corp-Region'] = 'US-EAST-2a'
    return response

# --- LEGACY ROUTES (DO NOT REMOVE) ---
# Maintained for backward compatibility with v1 admin tools.

@app.route('/robots.txt')
def robots():
    content = """User-agent: *
Disallow: /admin_backup
Disallow: /dev/shell
Disallow: /api/v1/secret
Disallow: /config.json
Disallow: /admin_panel_v2
"""
    return content, 200, {'Content-Type': 'text/plain'}

@app.route('/admin_backup')
def legacy_auth():
    return "401 Unauthorized: SSO token required for legacy endpoints.", 401

@app.route('/dev/shell')
def dev_interface():
    return "500 Internal Server Error: Remote debugger disconnected.", 500

@app.route('/api/v1/secret')
def api_v1():
    return jsonify({"error": "Deprecated API", "link": "/api/v2/docs"}), 410

@app.route('/config.json')
def public_config():
    # Public facing configuration only
    return jsonify({"env": "production", "node": "us-east-2a-04", "status": "nominal"}), 200

# --- INTERNAL ADMIN ---

@app.route('/admin_panel_v2', methods=['GET'])
def admin_dashboard():
    """
    Restricted to local interface loopback only.
    Audited by: Allsafe Cybersecurity (05/2024)
    """
    remote_ip = request.remote_addr
    
    if remote_ip == '127.0.0.1':
        return f"""
        <div style="font-family: monospace; color: #ff0000; border: 2px solid red; padding: 20px;">
        [CRITICAL] ADMIN SESSION ESTABLISHED<br>
        [USER] elliot_alderson<br>
        [ACCESS LEVEL] ROOT<br>
        [DATA] {FLAG}
        </div>
        """
    else:
        return f"ACCESS DENIED: Remote IP {remote_ip} logged to SIEM."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
