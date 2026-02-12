from flask import Flask, request, render_template, jsonify, make_response
import requests
from urllib.parse import urlparse
import random
import time
import os
import secrets  # Used for generating the secure internal token

app = Flask(__name__)

# 1. THE FLAG (Updated)
FLAG = os.getenv('FLAG', "XPL8{wh1t3_r0s3_w4tch1ng_y0u_SSRF_3xc3pt10n}")

# 2. INTERNAL AUTH TOKEN
# This generates a cryptographically strong random key when the app starts.
# Only this running Python script knows this key. External users cannot guess it.
INTERNAL_KEY = secrets.token_hex(32)

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

        # BLOCKLIST: String-based filtering (The Vulnerability)
        # Developers blocked standard strings but forgot about integer IPs
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
        
        # Network latency simulation
        time.sleep(random.uniform(0.1, 0.3))
        
        is_valid, validation_msg = validate_asset_source(url)
        
        if not is_valid:
            error = validation_msg
        else:
            try:
                # --- THE SECURITY MECHANISM ---
                # We inject the INTERNAL_KEY into the headers of every request 
                # this server makes. This acts as a "Proof of Internal Origin".
                headers = {
                    'User-Agent': 'E-Corp-Internal-Crawler/2.4-Legacy',
                    'X-E-Corp-Auth': INTERNAL_KEY 
                }
                
                # The SSRF Vulnerability: We fetch the user-provided URL
                # Note: allow_redirects=False prevents open-redirect exploits
                r = requests.get(url, headers=headers, timeout=2, allow_redirects=False)
                
                content_type = r.headers.get('Content-Type', '')
                
                if 'image' in content_type:
                    result = f"[SUCCESS] Asset verified. MIME: {content_type}. Cached to /var/tmp/assets."
                else:
                    # Debug output for text-based assets (Leak the response)
                    result = r.text[:600] 
                    
            except requests.exceptions.Timeout:
                error = "GATEWAY_TIMEOUT: Target unreachable."
            except Exception as e:
                error = f"PROXY_ERR: Upstream connection failed"

    response = make_response(render_template('index.html', result=result, error=error))
    response.headers['X-E-Corp-Region'] = 'US-EAST-2a'
    return response

# --- RABBIT HOLES / DECOYS ---

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
def legacy_auth(): return "401 Unauthorized: SSO token required.", 401

@app.route('/dev/shell')
def dev_interface(): return "500 Internal Server Error: Debugger detached.", 500

@app.route('/api/v1/secret')
def api_v1(): return jsonify({"error": "Deprecated API"}), 410

@app.route('/config.json')
def public_config():
    return jsonify({"env": "production", "status": "nominal"}), 200

# --- THE REAL TARGET ---

@app.route('/admin_panel_v2', methods=['GET'])
def admin_dashboard():
    """
    SECURE ADMIN PANEL
    Access Control: Token-Based
    This endpoint ignores IP addresses (due to cloud load balancers) 
    and relies entirely on the X-E-Corp-Auth header.
    """
    
    # Check the Header for the Shared Secret
    auth_header = request.headers.get('X-E-Corp-Auth')
    
    # We verify if the token provided matches the one this server generated at startup
    if auth_header and auth_header == INTERNAL_KEY:
        return f"""
        <div style="font-family: monospace; color: #ff0000; border: 2px solid red; padding: 20px;">
        [CRITICAL] ADMIN SESSION ESTABLISHED<br>
        [USER] elliot_alderson<br>
        [ACCESS LEVEL] ROOT<br>
        [DATA] {FLAG}
        </div>
        """
    else:
        # If the user visits directly (no SSRF), they won't have the token.
        return "ACCESS DENIED: MISSING OR INVALID INTERNAL AUTHORIZATION TOKEN."

if __name__ == '__main__':
    # Threaded=True helps prevent self-deadlocks during testing
    app.run(host='0.0.0.0', port=5000, threaded=True)
