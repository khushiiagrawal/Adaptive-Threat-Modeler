from flask import Flask, request, render_template_string, session, redirect
import hashlib

app = Flask(__name__)
app.secret_key = 'weak_secret_key_123'

# VULNERABILITY: Application served over plain HTTP
# This exposes all data in transit to interception and tampering

@app.route('/')
def index():
    return '''
    <h2>Secure Login Portal</h2>
    <p style="color: red;">WARNING: This application is served over HTTP (insecure)</p>
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: Credentials transmitted over HTTP
    # Can be intercepted by anyone on the network
    
    if username == 'admin' and password == 'admin123':
        session['username'] = username
        return redirect('/dashboard')
    else:
        return 'Invalid credentials! <a href="/">Try again</a>'

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f'''
        <h2>Welcome {session['username']}!</h2>
        <p>This is your secure dashboard.</p>
        <p style="color: red;">WARNING: All data is transmitted over HTTP</p>
        <a href="/logout">Logout</a>
        '''
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

# VULNERABLE: API endpoints over HTTP
@app.route('/api/user_data')
def get_user_data():
    # VULNERABLE: Sensitive data transmitted over HTTP
    user_data = {
        "id": 1,
        "name": "John Doe",
        "email": "john@example.com",
        "ssn": "123-45-6789",
        "credit_card": "4111-1111-1111-1111"
    }
    return user_data

@app.route('/api/transfer', methods=['POST'])
def transfer_money():
    # VULNERABLE: Financial transaction over HTTP
    amount = request.json.get('amount', 0)
    to_account = request.json.get('to_account', '')
    
    # VULNERABLE: No encryption of sensitive financial data
    return {
        "status": "success",
        "message": f"Transferred ${amount} to {to_account}",
        "transaction_id": "12345"
    }

# VULNERABLE: No HTTPS enforcement
# VULNERABLE: No HSTS headers
# VULNERABLE: No secure cookie flags
# VULNERABLE: No CSP headers

if __name__ == '__main__':
    # VULNERABLE: Running on HTTP instead of HTTPS
    app.run(debug=True, host='0.0.0.0', port=5009)