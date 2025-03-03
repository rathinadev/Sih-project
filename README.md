
# Smart Identity Verification System (SIH)

The **Smart Identity Verification System (SIH)** is a multi-layered authentication solution that combines traditional and cutting-edge technologies to ensure secure and reliable user identity verification. This project demonstrates our commitment to robust security, innovative design, and seamless user experience.

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

- **OTP Authentication:** Secure OTP generation, storage (with expiration), and verification to validate user identity.
- **Cryptographic Security:** 
  - **RSA Encryption:** For secure transmission and digital signature of model data.
  - **AES Key Management:** Dynamically assigned and encrypted with client RSA keys.
- **Redis Integration:** Utilized for fast in-memory storage of AES keys, RSA keys, models, and user assignments.
- **Session Management:** Secure session storage with Flask to ensure that only validated users access protected endpoints.
- **Dynamic Content Delivery:** On-demand delivery of encrypted models and image files with integrity checks.
- **Detailed Logging & Debugging:** Extensive logging for troubleshooting and validation.

---

## Tech Stack

- **Programming Language:** Python 3.x  
- **Web Framework:** [Flask](https://flask.palletsprojects.com/)
- **Cryptography:** [cryptography](https://cryptography.io/) library (RSA, AES, digital signatures)
- **Database & Caching:** Redis (multiple DBs for different data types) and temporary in-memory storage for OTPs
- **Image Processing & File Handling:** Built-in Python libraries (os, io, base64)
- **Session Management:** Flask sessions with secure secret keys
- **Utilities:** UUID, random, datetime, logging, and hashlib for additional functionality

---

## System Architecture & Workflow

1. **User Initiation:**  
   - The user starts by providing an Aadhaar number.  
   - An OTP is generated and sent (simulated via console output) to the user.
  
2. **OTP Verification:**  
   - The OTP submitted by the user is validated against a temporary store (with a 5-minute expiry).
   - Upon successful OTP validation, the user is marked as verified and assigned a unique user ID.
  
3. **Key Assignment & Model Access:**  
   - A random AES key is assigned from a pool stored in Redis.
   - The verified user can request a secured model file which is:
     - Retrieved from Redis.
     - Digitally signed using RSA (ensuring model integrity).
     - Sent as a downloadable binary file.
  
4. **Secure Data Transmission:**  
   - Endpoints to fetch the AES key encrypt it with the client's RSA public key.
   - Images (or other assets) are served securely on demand.

5. **Session & Access Control:**  
   - A decorator (`require_verified_user`) protects endpoints, ensuring that only verified sessions can access sensitive operations.

---

## Installation & Setup

### Prerequisites

- **Python 3.x**  
- **Redis Server:** Ensure Redis is installed and running on your local machine (default ports used: 6379 for different DBs).
- **Virtual Environment (Recommended):**

### Steps to Install

1. **Clone the Repository:**

   ```bash
   git clone https://your-repository-url.git
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
   - Ensure that Redis is running and accessible on the default ports.
   - Adjust Redis configurations in `app.py` if necessary.

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
  - Stores OTP with a 5-minute expiration.
  - Simulates OTP delivery (e.g., via SMS integration in production).

- **Endpoint:** `/verify-otp` (POST)  
  **Functionality:**  
  - Validates the provided OTP against the stored value.
  - If valid, marks the session as verified, assigns a unique user ID, and assigns an AES key.

### Key Management with Redis

- **Redis Databases:**  
  - **DB 1:** For storing AES keys.  
  - **DB 2:** For RSA key storage.
  - **DB 3:** For model metadata (including model paths).
  - **DB 5:** For user assignments (mapping user IDs to keys).

- **AES Key Assignment:**  
  - A random AES key is selected and associated with the user’s session.
  - The key is later encrypted with the client’s RSA public key upon request.

### Model Signing and Retrieval

- **Endpoint:** `/get-model` (GET, Protected)  
  **Functionality:**  
  - Retrieves the model path from Redis.
  - Opens and reads the encrypted model file.
  - Provides the file as a download after calculating its SHA-256 hash.
  
- **Digital Signature:**  
  - **Function:** `sign_model(model_path)`  
    - Reads the model data.
    - Creates a SHA-256 hash.
    - Signs the hash with a randomly selected RSA private key.
    - Returns the Base64-encoded signature and public key PEM.

### Image and AES Key Delivery

- **Endpoint:** `/get-image` (GET)  
  **Functionality:**  
  - Serves a static image file after verifying its existence.
  
- **Endpoint:** `/fetch-aes-key` (POST, Protected)  
  **Functionality:**  
  - Accepts a client’s RSA public key.
  - Retrieves the AES key from Redis.
  - Encrypts the AES key using the client's RSA public key.
  - Returns the encrypted AES key in Base64 format.

### Session Management and Security

- **Session Handling:**  
  - Flask sessions are used to store the user's unique ID and verification status.
  
- **Access Control Decorator:**  
  - **Function:** `require_verified_user`  
    - Checks for a valid session and verified status.
    - Performs additional Redis-based session validation.
    - Clears the session and redirects if verification fails.

---

## Challenges & Efforts

This project embodies a significant development effort, addressing numerous technical challenges:
- **Multi-Layered Security:**  
  Integrating OTP, RSA, AES, and Redis required careful planning to ensure data security and integrity.
- **Real-Time Cryptographic Operations:**  
  Handling key encryption and model signing in real-time was a complex task that involved deep understanding of cryptographic principles.
- **Robust Session Management:**  
  Ensuring that only verified users can access sensitive endpoints demanded rigorous session validation and error handling.
- **Scalable Architecture:**  
  Using Redis for fast in-memory operations and key management sets the foundation for scaling the application in production.
- **User-Centric Design:**  
  Extensive logging, detailed error messages, and modular code design help ensure that the system is both robust and maintainable.

---

## Future Enhancements

- **Enhanced OTP Delivery:**  
  Integrate with SMS or email services for real-time OTP delivery.
- **Improved Cryptographic Security:**  
  Explore additional layers of encryption and more secure key rotation mechanisms.
- **Advanced Logging & Monitoring:**  
  Implement centralized logging and real-time monitoring for production deployments.
- **UI/UX Enhancements:**  
  Develop a more sophisticated front-end using modern frameworks like React or Vue.js.
- **Scalability Upgrades:**  
  Consider migrating to a more scalable database system and deploying on cloud platforms.

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
