from flask import Flask, request, render_template_string, jsonify
import requests
import json

app = Flask(__name__)

# VULNERABILITY: Server-Side Request Forgery (SSRF)
# This allows attackers to make requests to internal services via the application

@app.route('/')
def index():
    return '''
    <h2>URL Fetcher Service</h2>
    <p style="color: red;">WARNING: This is intentionally vulnerable to SSRF!</p>
    <form method="GET" action="/fetch">
        <input type="text" name="url" placeholder="Enter URL to fetch" style="width: 400px;"><br>
        <input type="submit" value="Fetch URL">
    </form>
    <br>
    <h3>Example URLs:</h3>
    <ul>
        <li>http://example.com</li>
        <li>http://169.254.169.254/latest/meta-data/ (AWS metadata)</li>
        <li>http://169.254.169.254/latest/dynamic/instance-identity/document</li>
        <li>http://127.0.0.1:8080/ (internal service)</li>
        <li>http://localhost:3000/ (local service)</li>
    </ul>
    '''

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url', '')
    
    if not url:
        return 'No URL provided! <a href="/">Back</a>'
    
    # VULNERABLE: Direct request without URL validation
    # This allows SSRF attacks to access internal services
    try:
        # VULNERABLE: No URL validation or whitelist checking
        # VULNERABLE: No protocol restrictions
        # VULNERABLE: No IP range restrictions
        response = requests.get(url, timeout=10)
        
        # VULNERABLE: Returning full response content
        return f'''
        <h3>Response from: {url}</h3>
        <p><strong>Status Code:</strong> {response.status_code}</p>
        <p><strong>Headers:</strong></p>
        <pre>{dict(response.headers)}</pre>
        <p><strong>Content:</strong></p>
        <pre>{response.text}</pre>
        <br>
        <a href="/">Back</a>
        '''
    except Exception as e:
        return f'Error fetching URL: {str(e)} <a href="/">Back</a>'

@app.route('/api/fetch')
def api_fetch():
    url = request.args.get('url', '')
    
    if not url:
        return jsonify({"error": "No URL provided"})
    
    # VULNERABLE: Same SSRF vulnerability in API endpoint
    try:
        response = requests.get(url, timeout=10)
        return {
            "url": url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content": response.text
        }
    except Exception as e:
        return {"error": str(e)}

@app.route('/proxy')
def proxy():
    # VULNERABLE: Proxy endpoint that forwards requests
    target = request.args.get('target', '')
    
    if not target:
        return 'No target specified! <a href="/">Back</a>'
    
    # VULNERABLE: No validation of target URL
    # Allows access to internal services
    try:
        response = requests.get(target, timeout=10)
        return response.content, response.status_code, dict(response.headers)
    except Exception as e:
        return f'Proxy error: {str(e)} <a href="/">Back</a>'

@app.route('/webhook')
def webhook():
    # VULNERABLE: Webhook endpoint that makes requests
    callback_url = request.args.get('callback', '')
    
    if not callback_url:
        return 'No callback URL specified! <a href="/">Back</a>'
    
    # VULNERABLE: No validation of callback URL
    # Can be used to access internal services
    try:
        data = {"status": "success", "message": "Webhook triggered"}
        response = requests.post(callback_url, json=data, timeout=10)
        return f'Webhook sent to {callback_url}, status: {response.status_code}'
    except Exception as e:
        return f'Webhook error: {str(e)}'

# VULNERABLE: Function that can be exploited for SSRF
def fetch_internal_data(url):
    # VULNERABLE: No URL validation
    # VULNERABLE: No IP restrictions
    # VULNERABLE: No protocol restrictions
    response = requests.get(url)
    return response.text

# Example SSRF attack scenarios:
# 1. Access AWS metadata: http://169.254.169.254/latest/meta-data/
# 2. Access internal services: http://127.0.0.1:8080/
# 3. Access localhost services: http://localhost:3000/
# 4. Access cloud metadata: http://169.254.169.254/latest/dynamic/instance-identity/document
# 5. Access internal APIs: http://10.0.0.1/api/admin

if __name__ == '__main__':
    print("=== SSRF Vulnerability Demo ===")
    print("WARNING: This application is intentionally vulnerable to SSRF!")
    print("Do not run this in production!")
    app.run(debug=True, host='0.0.0.0', port=5012)