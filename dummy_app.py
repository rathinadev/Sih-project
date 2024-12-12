from flask import Flask, jsonify, render_template, session, redirect, url_for,request
import random
import time
from server_helper import get_random_redis_key, get_aes_key_and_model, get_random_rsa_keys
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import redis




from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64
import logging


app = Flask(__name__, static_folder='static')
app.secret_key = 'your_secret_key'  # Replace with a secure key for session management

# Configuration for OTP expiry time
EXPIRY_TIME = 300  # 5 minutes in seconds
redis_client_rsa = redis.StrictRedis(host='localhost', port=6379, db=2)
redis_client_model = redis.StrictRedis(host='localhost', port=6379, db=3)  # db 3 for models


from flask import Flask, request, jsonify, session
import random
import string
from datetime import datetime, timedelta



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

    return jsonify({"message": "OTP sent successfully","otp": otp}), 200




@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    aadhaar_number = data.get('aadhaar_number')
    otp = data.get('otp')

    if not aadhaar_number or not otp:
        return jsonify({"error": "Aadhaar number and OTP are required"}), 400

    stored_otp_data = otp_store.get(aadhaar_number)

    if not stored_otp_data:
        return jsonify({"error": "No OTP found for this Aadhaar number"}), 400

    if datetime.now() > stored_otp_data["expires_at"]:
        return jsonify({"error": "OTP has expired"}), 400

    if stored_otp_data["otp"] != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    # OTP verified successfully
    del otp_store[aadhaar_number]  # Clear OTP after successful verification
    return jsonify({"message": "OTP verified successfully"}), 200



# Middleware to check OTP validity
#@app.before_request
# def check_otp_validity():
#     if request.path.startswith('/static'):
#         return  # Skip static files

#     if 'otp' in session:
#         otp_timestamp = session.get('otp_timestamp')
#         if time.time() - otp_timestamp > EXPIRY_TIME:
#             # OTP expired; clear session and redirect to login
#             session.pop('otp', None)
#             session.pop('otp_timestamp', None)
#             return redirect(url_for('index'))
#     elif request.endpoint not in ['index', 'generate_otp']:
#         # Redirect to login if OTP is missing for protected pages
#         return redirect(url_for('index'))


# Route for generating OTP

def generate_otp():
    otp = random.randint(100000, 999999)
   
    return otp



from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

@app.route('/get-model', methods=['GET'])
def get_model():
    # Fetch a random AES key from Redis
    model_key = 'aes_key_1733585985_5893'#get_random_redis_key()  # Helper function to get a random AES key from Redis
    if not model_key:
        return jsonify({'error': 'No AES key found in Redis'}), 404

    # Retrieve AES key and model from Redis
    aes_key, _ = get_aes_key_and_model(model_key)
    if not aes_key:
        return jsonify({'error': 'AES key not found'}), 404

    # Fetch the model data from Redis
    model_data = redis_client_model.get(model_key)
    if model_data is None:
        return jsonify({'error': 'Model not found in Redis'}), 404

    # Create a SHA-256 hash of the model data
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(model_data)
    hashed_model_data = digest.finalize()
    hashed_model_data_hex = hashed_model_data.hex()

    # Print the hashed model data in hex format for debugging
    #print("SHA-256 Hash of Model Data:", hashed_model_data_hex)

    # Fetch RSA keys and sign the hash
    rsa_private_key_pem, rsa_public_key_pem = get_random_rsa_keys()
    if not rsa_private_key_pem:
        return jsonify({'error': 'No RSA private key found in Redis'}), 404

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
   # print("Raw Signature:", signature)

    # Base64 encode the signature for transmission
    signature_base64 = base64.b64encode(signature).decode('utf-8')
   # print("signature is:")
    #print(signature_base64)
    #print("Public key pem is:")
    #print(rsa_public_key_pem)

    # Base64 encode the model data
    model_data_base64 = base64.b64encode(model_data).decode('utf-8')

    # Return the model, signature, and public key in the response
    return jsonify({
        'model': model_data_base64,  # Base64 encoded model data
        'signature': signature_base64,  # Base64 encoded digital signature
        'public_key': rsa_public_key_pem  # Public key as PEM for client to verify
    })


# Serve the HTML page
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':

    app.run(debug=True)
