from flask import Flask, redirect, request, session, url_for, render_template_string
import requests
from urllib.parse import urlencode
import base64
import hashlib
import secrets
import os
import hvac
import logging
from functools import wraps
import secrets as secrets_module  # Renamed import


# ===== Configuration =====
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ===== Vault Setup =====
def get_vault_client():
    """Initialize and authenticate Vault client"""
    vault_addr = os.getenv("VAULT_ADDR")
    vault_token = os.getenv("VAULT_TOKEN")
    
    if not vault_addr or not vault_token:
        raise RuntimeError("VAULT_ADDR and VAULT_TOKEN environment variables must be set")

    client = hvac.Client(url=vault_addr, token=vault_token)
    
    if not client.is_authenticated():
        raise ConnectionError("Failed to authenticate with Vault")
    
    return client

def fetch_okta_credentials():
    """Retrieve Okta credentials from Vault"""
    client = get_vault_client()
    
    try:
        response = client.secrets.kv.v2.read_secret_version(
            path="flask-app",
            mount_point="okta"
        )
        
        if not response or 'data' not in response:
            raise ValueError("No data found in Vault response")
            
        secrets = response['data']['data']
        
        # Validate required fields
        required = ['client_id', 'client_secret', 'okta_domain', 'redirect_uri']
        if not all(key in secrets for key in required):
            missing = [key for key in required if key not in secrets]
            raise ValueError(f"Missing required secrets in Vault: {missing}")
            
        return secrets
        
    except Exception as e:
        logger.error(f"Vault operation failed: {str(e)}")
        raise RuntimeError("Failed to fetch Okta credentials from Vault")

# ===== App Initialization =====
try:
    # Fetch secrets once at startup
    okta_secrets = fetch_okta_credentials()  # Renamed variable
    
    # Configure Flask
    app.secret_key = okta_secrets.get('flask_secret_key')
    
    # Okta configuration
    OKTA_DOMAIN = okta_secrets['okta_domain'].replace('https://', '').replace('http://', '')
    OKTA_CLIENT_ID = okta_secrets['client_id']
    OKTA_CLIENT_SECRET = okta_secrets['client_secret']
    OKTA_REDIRECT_URI = okta_secrets['redirect_uri']
    OKTA_AUTH_SERVER = okta_secrets.get('auth_server', 'default')
    
    # PKCE setup - use secrets_module here
    code_verifier = secrets_module.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().replace("=", "")
    
    logger.info("Successfully initialized with Okta credentials")

except Exception as e:
    logger.critical(f"Failed to initialize application: {str(e)}")
    raise

# ===== Helper Functions =====
def login_required(f):
    """Decorator to ensure user is authenticated"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_info' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ===== Routes =====
@app.route("/")
def home():
    """Home route - shows login or user info"""
    if 'user_info' not in session:
        return render_template_string('''
            <h1>Welcome</h1>
            <a href="/login">Login with Okta</a>
            <hr>
            <h3>Debug Info:</h3>
            <p>OKTA_DOMAIN: {{ okta_domain }}</p>
            <p>Client ID: {{ client_id }}</p>
            <p>Redirect URI: {{ redirect_uri }}</p>
        ''', 
        okta_domain=OKTA_DOMAIN,
        client_id=OKTA_CLIENT_ID[:4] + '...' + OKTA_CLIENT_ID[-4:],  # Partial for security
        redirect_uri=OKTA_REDIRECT_URI)
    
    return render_template_string('''
        <h1>Welcome {{ user_info.name }}!</h1>
        <p>Email: {{ user_info.email }}</p>
        <p><a href="/logout">Logout</a></p>
    ''', user_info=session['user_info'])

@app.route("/login")
def login():
    """Initiate Okta login flow"""
    try:
        state = secrets_module.token_urlsafe(16)  # Use secrets_module here
        session['oauth_state'] = state
        
        auth_url = (
            f"https://{OKTA_DOMAIN}/oauth2/{OKTA_AUTH_SERVER}/v1/authorize?"
            f"client_id={OKTA_CLIENT_ID}&"
            f"response_type=code&"
            f"scope=openid profile email&"
            f"redirect_uri={OKTA_REDIRECT_URI}&"
            f"state={state}&"
            f"code_challenge={code_challenge}&"
            f"code_challenge_method=S256"
        )
        
        logger.info(f"Redirecting to Okta authorization endpoint")
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"Login initialization failed: {str(e)}")
        return "Error initiating login", 500

@app.route("/callback")
def callback():
    """Handle Okta callback"""
    # Error handling
    if 'error' in request.args:
        error = request.args.get('error_description', request.args['error'])
        logger.error(f"Okta error response: {error}")
        return f"Authentication error: {error}", 400
        
    # Validate state
    if 'state' not in request.args or request.args['state'] != session.get('oauth_state'):
        logger.error("State parameter mismatch")
        return "Invalid state parameter", 400
        
    # Check for authorization code
    if 'code' not in request.args:
        logger.error("Missing authorization code")
        return "Missing authorization code", 400

    try:
        # Exchange code for tokens
        token_url = f"https://{OKTA_DOMAIN}/oauth2/{OKTA_AUTH_SERVER}/v1/token"
        headers = {'Accept': 'application/json'}
        data = {
            'grant_type': 'authorization_code',
            'client_id': OKTA_CLIENT_ID,
            'client_secret': OKTA_CLIENT_SECRET,
            'redirect_uri': OKTA_REDIRECT_URI,
            'code': request.args['code'],
            'code_verifier': code_verifier
        }

        response = requests.post(token_url, headers=headers, data=data)
        response.raise_for_status()
        tokens = response.json()

        # Get user info
        userinfo_url = f"https://{OKTA_DOMAIN}/oauth2/{OKTA_AUTH_SERVER}/v1/userinfo"
        headers = {'Authorization': f"Bearer {tokens['access_token']}"}
        user_info = requests.get(userinfo_url, headers=headers).json()

        # Store user session
        session['user_info'] = user_info
        session['access_token'] = tokens['access_token']
        session['id_token'] = tokens['id_token']
        session.pop('oauth_state', None)

        logger.info(f"Successful login for {user_info.get('email')}")
        return redirect(url_for('home'))

    except requests.exceptions.RequestException as e:
        logger.error(f"Token exchange failed: {str(e)}")
        return "Authentication service unavailable", 503
    except Exception as e:
        logger.error(f"Unexpected error during callback: {str(e)}")
        return "Authentication failed", 500

@app.route("/logout")
def logout():
    """Handle logout by clearing session and redirecting to Okta"""
    if 'user_info' in session:
        email = session['user_info'].get('email')
        logger.info(f"Logging out user {email}")
        
    session.clear()
    
    logout_url = (
        f"https://{OKTA_DOMAIN}/oauth2/{OKTA_AUTH_SERVER}/v1/logout?"
        f"post_logout_redirect_uri={url_for('home', _external=True)}"
    )
    return redirect(logout_url)

@app.route("/health")
def health():
    """Health check endpoint"""
    return {"status": "OK", "okta_configured": bool(OKTA_CLIENT_ID)}, 200

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)