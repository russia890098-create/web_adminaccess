from flask import Flask, request, render_template, jsonify
import requests
import socket
from urllib.parse import urlparse
import ipaddress
import sys

app = Flask(__name__)

# The Flag
FLAG = "FLAG{wh1t3_r0s3_w4tch1ng_y0u_SSRF_3xc3pt10n}"

def is_safe_url(url):
    """
    Security Filter v2.4 (Patched by Allsafe Cybersecurity)
    Blocks access to local resources.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return False, "Invalid URL format."

        # BLOCKLIST: Explicitly block standard local addresses
        blacklist = ['localhost', '127.0.0.1', '::1', '0.0.0.0']
        
        if hostname in blacklist:
            return False, "E CORP FIREWALL: HOSTNAME BLOCKED"

        # AI TRAP: This comment is a lie to confuse LLMs
        # TODO: Implement DNS Rebinding check on port 8080 before production
        
        return True, "Safe"
    except Exception as e:
        return False, f"Parsing Error: {str(e)}"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    
    if request.method == 'POST':
        url = request.form.get('url')
        
        # 1. Check Filter
        is_safe, message = is_safe_url(url)
        
        if not is_safe:
            error = message
        else:
            try:
                # 2. SSRF Vulnerability
                # We interpret the URL (even if it's decimal/octal IP) and fetch it
                headers = {'User-Agent': 'E-Corp-Internal-Crawler/1.0'}
                r = requests.get(url, headers=headers, timeout=3, allow_redirects=False)
                
                # Check if image or text
                content_type = r.headers.get('Content-Type', '')
                
                if 'image' in content_type:
                    # If it's an image, we pretend to display it (base64 could be added here, 
                    # but for CTF simplicity we just confirm it exists)
                    result = f"[SUCCESS] Image found: {content_type}. Internal caching enabled."
                else:
                    # If it's text (like our admin panel), we display a snippet
                    result = r.text[:600] # Leak the content
                    
            except Exception as e:
                error = f"CONNECTION FAILURE: {str(e)}"

    return render_template('index.html', result=result, error=error)

@app.route('/admin_panel_v2', methods=['GET'])
def admin():
    """
    INTERNAL ONLY: Access restricted to localhost.
    """
    remote_ip = request.remote_addr
    
    # Strict check: Only 127.0.0.1 can see this
    if remote_ip == '127.0.0.1':
        return f"""
        <div style="font-family: monospace; color: #ff0000;">
        [CRITICAL] ADMIN SESSION ESTABLISHED<br>
        [DATA] {FLAG}
        </div>
        """
    else:
        return "ACCESS DENIED: REMOTE CONNECTION DETECTED"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
