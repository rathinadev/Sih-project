
# Smart Identity Verification System (SIH)

The **Smart Identity Verification System (SIH)** is a multi-layered authentication solution that combines traditional and cutting-edge technologies to ensure secure and reliable user identity verification. This project demonstrates our commitment to robust security, innovative design, and seamless user experience.

> **Note:** *Custom model implementation is still in progress. Currently, the project is using inbuilt JavaScript models on the client side for facial recognition and liveness detection.*

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [System Architecture & Workflow](#system-architecture--workflow)
- [Installation & Setup](#installation--setup)
- [API Endpoints & Code Highlights](#api-endpoints--code-highlights)
  - [OTP Generation and Verification](#otp-generation-and-verification)
  - [Key Management with Redis](#key-management-with-redis)
  - [Model Signing and Retrieval](#model-signing-and-retrieval)
  - [Image and AES Key Delivery](#image-and-aes-key-delivery)
  - [Session Management and Security](#session-management-and-security)
- [Challenges & Efforts](#challenges--efforts)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)

---

## Overview

SIH provides a comprehensive identity verification process that leverages:

- **Multi-Factor Authentication:** Combines Aadhaar-based verification, OTP, CAPTCHA, and biometric facial recognition.
- **Cryptographic Key Management:** Uses RSA and AES encryption with keys stored and managed in Redis.
- **Secure Model Delivery:** Delivers encrypted machine learning models, digitally signed for integrity.
- **Session & Access Control:** Ensures only verified users can access sensitive resources.

This project not only integrates multiple modern technologies but also demonstrates rigorous security practices and an emphasis on scalability.

---

## Features

- **Multi-Factor Authentication:** Combines Aadhaar, CAPTCHA, OTP, and facial recognition.
- **Real-Time Verification:** Uses client-side built-in JavaScript models for immediate facial recognition (custom models are under development).
- **Cryptographic Security:**  
  - **RSA Encryption:** Secure digital signatures for model integrity.
  - **AES Key Management:** Dynamically assigned and encrypted using RSA.
- **Redis Integration:** Fast in-memory storage for keys, models, and user assignments.
- **Secure Session Management:** Protects sensitive endpoints with robust session validation.
- **Dynamic Content Delivery:** On-demand delivery of encrypted models and images.

---

## Tech Stack

- **Backend:**
  - Python 3.x
  - [Flask](https://flask.palletsprojects.com/)
  - [Redis](https://redis.io/) for caching and key management
  - [cryptography](https://cryptography.io/) for RSA/AES operations and digital signatures
- **Frontend:**
  - HTML5, CSS3, JavaScript (ES6)
  - Built-in JavaScript models for real-time facial recognition (custom model implementation is ongoing)
- **Utilities:**
  - UUID, random, datetime, logging, hashlib for supplementary functionality

---

## System Architecture & Workflow

1. **User Initiation:**  
   - The user begins by providing an Aadhaar number.
   - An OTP is generated and sent (simulated via console output) to the user.
  
2. **OTP Verification:**  
   - The OTP submitted by the user is validated against a temporary store (with a 5-minute expiry).
   - Upon successful verification, the user is assigned a unique user ID and marked as verified.
  
3. **Key Assignment & Model Access:**  
   - A random AES key is assigned from a pool stored in Redis.
   - The verified user can request a secured model file which is digitally signed and delivered as a downloadable binary file.
  
4. **Secure Data Transmission:**  
   - Endpoints fetch the AES key and encrypt it with the client's RSA public key.
   - Images and model files are served securely upon request.
  
5. **Session & Access Control:**  
   - A decorator (`require_verified_user`) ensures only verified users can access protected endpoints.

---

## Installation & Setup

### Prerequisites

- **Python 3.x**  
- **Redis Server:** Make sure Redis is installed and running (default ports are used).
- **Virtual Environment (Recommended)**

### Steps to Install

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/rathinadev/Sih-project.git
   cd sih-project
   ```

2. **Setup Virtual Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Redis:**  
   - Ensure Redis is running and accessible on the default ports.
   - Adjust Redis configurations in `app.py` if needed.

5. **Run the Application:**
   ```bash
   python app.py
   ```
   The server will start (typically on `http://127.0.0.1:5000`).

---

## API Endpoints & Code Highlights

### OTP Generation and Verification

- **Endpoint:** `/send-otp` (POST)  
  **Functionality:**  
  - Generates a 6-digit OTP.
  - Stores the OTP with a 5-minute expiration.
  - Simulates OTP delivery (production systems should integrate an SMS/email service).

- **Endpoint:** `/verify-otp` (POST)  
  **Functionality:**  
  - Validates the provided OTP.
  - On success, marks the session as verified, assigns a unique user ID, and assigns an AES key.
  - Clears the OTP after successful verification.

### Key Management with Redis

- **Redis Databases:**  
  - **DB 1:** AES keys  
  - **DB 2:** RSA keys  
  - **DB 3:** Model metadata (paths)  
  - **DB 5:** User assignments (mapping user IDs to keys)
  
- **AES Key Assignment:**  
  - A random AES key is selected from Redis and assigned to the verified user session.

### Model Signing and Retrieval

- **Endpoint:** `/get-model` (GET, Protected)  
  **Functionality:**  
  - Retrieves the model path from Redis.
  - Reads the encrypted model file.
  - Calculates its SHA-256 hash.
  - Provides the model file as a download.
  
- **Digital Signature:**  
  - **Function:** `sign_model(model_path)`  
    - Reads the model data.
    - Creates a SHA-256 hash.
    - Signs the hash with an RSA private key.
    - Returns a Base64-encoded signature and public key PEM.

### Image and AES Key Delivery

- **Endpoint:** `/get-image` (GET)  
  **Functionality:**  
  - Serves a static image file after verifying its existence.
  
- **Endpoint:** `/fetch-aes-key` (POST, Protected)  
  **Functionality:**  
  - Accepts a client’s RSA public key.
  - Retrieves and encrypts the AES key with the client's RSA public key.
  - Returns the encrypted AES key in Base64 format.

### Session Management and Security

- **Session Handling:**  
  - Flask sessions are used to store a unique user ID and verification status.
  
- **Access Control Decorator:**  
  - **Function:** `require_verified_user`  
    - Validates the session and checks for a verified user.
    - Performs additional Redis-based validation.
    - Clears the session and redirects if verification fails.

---

## Challenges & Efforts

The SIH project represents a significant development effort addressing multiple technical challenges:

- **Multi-Layered Security:**  
  Integrating OTP, RSA, AES, and Redis required careful planning to ensure data integrity and security.
  
- **Real-Time Cryptographic Operations:**  
  Handling key encryption and model signing in real-time demanded a deep understanding of cryptographic principles.
  
- **Robust Session Management:**  
  Ensuring that only verified users access sensitive endpoints involved rigorous session validation and error handling.
  
- **Scalable Architecture:**  
  Utilizing Redis for fast in-memory operations lays the groundwork for future scaling.
  
- **Custom Model Implementation:**  
  *While our current implementation uses built-in JavaScript models on the client side for facial recognition and liveness detection, our team is actively developing a custom model to further enhance the system's accuracy and performance.*

---

## Future Enhancements

- **Custom Model Implementation:**  
  Finalize and integrate a custom-trained model for facial recognition to replace the inbuilt JS models currently in use.
- **Enhanced OTP Delivery:**  
  Integrate with SMS or email services for real-time OTP delivery.
- **Improved Cryptographic Security:**  
  Explore additional layers of encryption and secure key rotation mechanisms.
- **Advanced Logging & Monitoring:**  
  Implement centralized logging and real-time monitoring for production deployments.
- **UI/UX Enhancements:**  
  Upgrade the front-end using modern frameworks such as React or Vue.js.
- **Scalability Upgrades:**  
  Consider migrating to a more robust database system and deploying on cloud platforms.

---

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add your feature'`).
4. Push your branch (`git push origin feature/your-feature`).
5. Open a pull request with a detailed description of your changes.

---

## Acknowledgements

We would like to acknowledge:
- The open-source community for providing invaluable libraries and frameworks (Flask, cryptography, Redis, etc.).
- Our dedicated development team whose relentless efforts have brought this project to life.
- Our mentors and peers for their guidance throughout the development process.

---

