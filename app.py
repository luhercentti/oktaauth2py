from flask import Flask, redirect, request, session, url_for, render_template_string
import requests
from urllib.parse import urlencode
import base64
import hashlib
import secrets
import os
import hvac
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Required for session

def get_vault_secrets():
    """Fetch configuration from HashiCorp Vault"""
    try:
        # Initialize Vault client
        vault_client = hvac.Client(
            url=os.getenv('VAULT_ADDR', 'http://host.docker.internal:8200'),
            token=os.getenv('VAULT_TOKEN', 'root')  # Default to root token for local dev
        )

        if not vault_client.is_authenticated():
            raise ConnectionError("Failed to authenticate with Vault")

        # Read secrets from Vault
        secrets_response = vault_client.secrets.kv.v2.read_secret_version(
            path='flask-app',
            mount_point='okta'
        )

        if not secrets_response or 'data' not in secrets_response:
            raise ValueError("No secrets found in Vault response")

        return secrets_response['data']['data']

    except Exception as e:
        logger.error(f"Error fetching secrets from Vault: {str(e)}")
        raise

def load_config():
    """Load configuration from Vault with fallback to environment variables"""
    try:
        secrets = get_vault_secrets()
        config = {
            'OKTA_DOMAIN': secrets['okta_domain'].replace('https://', '').replace('http://', ''),
            'OKTA_CLIENT_ID': secrets['client_id'],
            'OKTA_CLIENT_SECRET': secrets['client_secret'],
            'OKTA_REDIRECT_URI': secrets['redirect_uri'],
            'OKTA_AUTH_SERVER': secrets.get('auth_server', 'default')
        }
        logger.info("Successfully loaded configuration from Vault")
        return config
    except Exception as e:
        logger.warning(f"Using environment variables due to Vault error: {str(e)}")
        return {
            'OKTA_DOMAIN': os.getenv('OKTA_DOMAIN', '').replace('https://', '').replace('http://', ''),
            'OKTA_CLIENT_ID': os.getenv('OKTA_CLIENT_ID'),
            'OKTA_CLIENT_SECRET': os.getenv('OKTA_CLIENT_SECRET'),
            'OKTA_REDIRECT_URI': os.getenv('OKTA_REDIRECT_URI'),
            'OKTA_AUTH_SERVER': os.getenv('OKTA_AUTH_SERVER', 'default')
        }

# Load configuration
try:
    config = load_config()
    OKTA_DOMAIN = config['OKTA_DOMAIN']
    OKTA_CLIENT_ID = config['OKTA_CLIENT_ID']
    OKTA_CLIENT_SECRET = config['OKTA_CLIENT_SECRET']
    OKTA_REDIRECT_URI = config['OKTA_REDIRECT_URI']
    OKTA_AUTH_SERVER = config['OKTA_AUTH_SERVER']
    
    # Validate configuration
    if not all([OKTA_DOMAIN, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET, OKTA_REDIRECT_URI]):
        raise ValueError("Missing required Okta configuration")
except Exception as e:
    logger.error(f"Failed to load configuration: {str(e)}")
    raise RuntimeError("Failed to initialize application configuration") from e

# Generate PKCE code verifier and challenge
code_verifier = secrets.token_urlsafe(64)
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).decode().replace("=", "")

@app.route("/")
def home():
    """Home route - shows login or user info"""
    if 'user_info' not in session:
        return render_template_string('''
            <h1>Welcome</h1>
            <a href="/login">Login with Okta</a>
        ''')
    return render_template_string('''
        <h1>Welcome {{ user_info.name }}!</h1>
        <p>Email: {{ user_info.email }}</p>
        <p><a href="/logout">Logout</a></p>
    ''', user_info=session['user_info'])

@app.route("/login")
def login():
    """Initiate Okta login flow"""
    try:
        auth_url = (
            f"https://{OKTA_DOMAIN}/oauth2/{OKTA_AUTH_SERVER}/v1/authorize?"
            f"client_id={OKTA_CLIENT_ID}&"
            f"response_type=code&"
            f"scope=openid profile email&"
            f"redirect_uri={OKTA_REDIRECT_URI}&"
            f"state={secrets.token_urlsafe(16)}&"
            f"code_challenge={code_challenge}&"
            f"code_challenge_method=S256"
        )
        logger.info(f"Redirecting to auth URL: {auth_url}")
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"Error generating auth URL: {str(e)}")
        return "Error initiating login", 500

@app.route("/callback")
def callback():
    """Handle Okta callback"""
    if 'error' in request.args:
        error = request.args.get('error_description', request.args['error'])
        logger.error(f"Okta error: {error}")
        return f"Error: {error}", 400

    if 'code' not in request.args:
        logger.error("Missing authorization code in callback")
        return "Missing authorization code", 400

    try:
        # Exchange authorization code for tokens
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

        # Store user info in session
        session['user_info'] = user_info
        session['access_token'] = tokens['access_token']
        session['id_token'] = tokens['id_token']

        return redirect(url_for('home'))

    except requests.exceptions.RequestException as e:
        logger.error(f"Error during token exchange: {str(e)}")
        return f"Authentication failed: {str(e)}", 500

@app.route("/logout")
def logout():
    """Handle logout"""
    session.clear()
    logout_url = (
        f"https://{OKTA_DOMAIN}/oauth2/{OKTA_AUTH_SERVER}/v1/logout?"
        f"post_logout_redirect_uri={url_for('home', _external=True)}"
    )
    return redirect(logout_url)

@app.route("/health")
def health():
    """Health check endpoint"""
    return "OK", 200

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)