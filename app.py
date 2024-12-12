from flask import Flask, jsonify, render_template, request,send_file,session
import random
import time
import uuid
from functools import wraps
import os
from flask import session, jsonify

from io import BytesIO
from server_helper import get_random_redis_key, get_aes_key_and_model, get_random_rsa_keys
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
import redis
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64
import logging
import hashlib
from datetime import datetime, timedelta


app = Flask(__name__, static_folder='static')
app.secret_key = 'your_secret_key'  # Replace with a secure key for session management
IMAGE_PATH = 'PRAVEEN.jpg'

# Configuration for OTP expiry time
EXPIRY_TIME = 300  # 5 minutes in seconds
redis_client_aes = redis.StrictRedis(host='localhost', port=6379, db=1)

redis_client_rsa = redis.StrictRedis(host='localhost', port=6379, db=2)
redis_client_model = redis.StrictRedis(host='localhost', port=6379, db=3)  # db 3 for models
redis_client_user_assign = redis.StrictRedis(host='localhost', port=6379, db=5) #db 5 for user assign



# Temporary storage for OTPs (use a database in production)
otp_store = {}

@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.json
    aadhaar_number = data.get('aadhaar_number')

    if not aadhaar_number:
        return jsonify({"error": "Aadhaar number is required"}), 400

    # Generate a random 6-digit OTP
    otp = generate_otp()

    # Store the OTP with an expiration time (5 minutes)
    otp_store[aadhaar_number] = {
        "otp": otp,
        "expires_at": datetime.now() + timedelta(minutes=5)
    }

    # Simulate sending OTP (Replace with actual SMS integration)
    print(f"OTP for {aadhaar_number}: {otp}")

    return jsonify({"message": "OTP sent successfully", "otp": otp}), 200



@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    print("Received JSON data:", data)  # Log the received JSON data
    aadhaar_number = data.get('aadhaar_number')
    otp = data.get('otp')

    if not aadhaar_number or not otp:
        return jsonify({"error": "Aadhaar number and OTP are required"}), 400

    stored_otp_data = otp_store.get(aadhaar_number)
    print(stored_otp_data)

    if not stored_otp_data:
        return jsonify({"error": "No OTP found for this Aadhaar number"}), 401

    if datetime.now() > stored_otp_data["expires_at"]:
        return jsonify({"error": "OTP has expired"}), 401
    otp = int(data.get('otp'))  # Convert OTP to integer

    if stored_otp_data["otp"] != otp:
        return jsonify({"error": "Invalid OTP"}), 401

    # OTP verified successfully
    # OTP verified successfully, store user validation in the session
    USERID=generate_user_id()
    session['user_id'] = USERID
    session['validated'] = True
    assignaeskey(USERID)

    del otp_store[aadhaar_number]  # Clear OTP after successful verification
    return jsonify({"message": "OTP verified successfully"}), 200
# Generate a unique user ID
def generate_user_id():
    return uuid.uuid4().hex  # UUID for uniqueness
def assignaeskey(userid):
    keys = redis_client_aes.keys("aes_key_*")  # Fetch all keys matching the AES key pattern
    if not keys:
        return None
    choice=random.choice(keys)  # Randomly pick one key
    print("choice is",choice)
    redis_client_user_assign.set(userid, choice)  # Store AES key in db=1

    

def get_model_from_redis(redis_key):
    print(redis_key)
    redis_key=redis_key.decode()
    model_path_key = f"{redis_key}_path"
    model_path = redis_client_model.get(model_path_key)
    if model_path is None:
        return None
    
    print(f"Retrieved model path: {model_path.decode('utf-8')}")  # Debugging line
    return model_path.decode('utf-8')

# Helper function to retrieve the RSA private key and sign the model
def sign_model(model_path):
    # Read the model data (this would be encrypted)
    with open(model_path, 'rb') as model_file:
        model_data = model_file.read()

    # Create a SHA-256 hash of the model data
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(model_data)
    hashed_model_data = digest.finalize()

    # Fetch RSA keys and sign the hash
    rsa_private_key_pem, rsa_public_key_pem = get_random_rsa_keys()
    if not rsa_private_key_pem:
        return None, "No RSA private key found"

    # Load the RSA private key
    rsa_private_key = load_pem_private_key(rsa_private_key_pem.encode(), password=None, backend=default_backend())

    # Sign the hashed model data using the private key
    signature = rsa_private_key.sign(
        hashed_model_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32
        ),
        hashes.SHA256()
    )

    # Base64 encode the signature for transmission
    signature_base64 = base64.b64encode(signature).decode('utf-8')

    return signature_base64, rsa_public_key_pem

# Route for generating OTP
def generate_otp():
    otp = random.randint(100000, 999999)
    return otp
from functools import wraps
from flask import session, redirect, url_for
def require_verified_user(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # More explicit session validation
        user_id = session.get('user_id')
        validated = session.get('validated', False)  # Default to False if not set

        # Comprehensive validation checks
        if not user_id or not validated:
            session.clear()  # Clear any potentially tampered session
            
            # Handle different request types
            if request.is_json:
                return jsonify({
                    'error': 'Unauthorized access. Please log in again.', 
                    'redirect': url_for('index')
                }), 401
            else:
                return redirect(url_for('index'))
        
        # Additional Redis-based validation
        if not redis_client_user_assign.exists(user_id):
            session.clear()
            
            if request.is_json:
                return jsonify({
                    'error': 'Session invalid. Please log in again.', 
                    'redirect': url_for('index')
                }), 401
            else:
                return redirect(url_for('index'))

        return func(*args, **kwargs)
    return wrapper

# Serve the encrypted model data
@app.route('/get-model', methods=['GET'])
@require_verified_user
def get_model():
    user = session['user_id']
    model_key = redis_client_user_assign.get(user)  # The key for fetching the model from Redis
    
    # Retrieve the model path from Redis (no AES decryption needed)
    model_path = get_model_from_redis(model_key)
    print(model_path)
    
    print(model_path)
    
    if model_path is None:
        return jsonify({'error': 'Model path not found in Redis'}), 404  # Return error if model path not found
    
    # Send the encrypted model data as a downloadable file
    print(f"Attempting to open model file at path: {model_path}")
    try:
        with open(model_path, 'rb') as model_file:
            encrypted_model_data = model_file.read()
            # Calculate the SHA-256 hash of the encrypted model data
            model_hash = hashlib.sha256(encrypted_model_data).hexdigest()
            print(model_hash)
    except FileNotFoundError:
        return jsonify({'error': 'Model file not found on server'}), 404  # Handle case where the file is not found

    model_file = BytesIO(encrypted_model_data)

    return send_file(
        model_file,
        as_attachment=True,
        download_name='model_encrypted.bin',  # Name of the file when downloading
        mimetype='application/octet-stream'  # Mime type for binary files
    )

@app.route('/fetch-aes-key', methods=['POST'])
@require_verified_user
def fetch_aes_key():
    try:
        # Parse the public key from the client
        request_data = request.json
        public_key_b64 = request_data.get('public_key')
        if not public_key_b64:
            return jsonify({'error': 'Public key not provided'}), 400

        # Decode and load the public key
        public_key_der = base64.b64decode(public_key_b64)
        public_key = serialization.load_der_public_key(public_key_der)

        # Fetch the AES key from Redis
        user = session['user_id']
        model_key = redis_client_user_assign.get(user)
        aes_key = redis_client_aes.get(model_key)
        print(aes_key)

        if not aes_key:
            return jsonify({'error': 'AES key not found'}), 404

        # Encrypt the AES key using the client's RSA public key
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )

        # Encode the encrypted key as Base64
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')

        return jsonify({'encrypted_aes_key': encrypted_aes_key_b64})

    except Exception as e:
        print(f"Error encrypting AES key: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


# Serve the model signature
@app.route('/get-signature', methods=['GET'])
@require_verified_user
def get_signature():
    user=session['user_id']
    model_key = redis_client_user_assign.get(user)  # The key for fetching the model from Redis
    # Retrieve the model path from Redis
    model_path = get_model_from_redis(model_key)
    
    if model_path is None:
        return jsonify({'error': 'Model path not found in Redis'}), 404  # Error message from get_model_from_redis
    
    # Sign the model and get the signature
    signature, public_key_pem = sign_model(model_path)
    print(public_key_pem)
    print(signature)
    
    if not signature:
        return jsonify({'error': 'Signature creation failed'}), 500  # Error in signing the model
    
    # Return the public key and signature to the client
    return jsonify({
        'signature': signature,  # Base64 encoded digital signature
        'public_key': public_key_pem  # Public key as PEM for client to verify
    })

@app.route('/get-image')
def get_image():
    try:
        # Check if the image exists
        if not os.path.exists(IMAGE_PATH):
            return jsonify({"error": "Image not found"}), 404
        
        # Send the image file
        return send_file(IMAGE_PATH, mimetype='image/jpeg')
    
    except Exception as e:
        print(f"Error serving image: {e}")
        return jsonify({"error": "Unable to serve image"}), 500
# Serve the HTML page
@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
