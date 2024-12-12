document.addEventListener("DOMContentLoaded", function () {
    const loginButton = document.querySelector('.login-button');
    const refreshCaptchaButton = document.querySelector('.refresh-captcha');
    // IndexedDB storage functions
    function openModelDatabase() {
        return new Promise((resolve, reject) => {
            if (!window.indexedDB) {
                reject(new Error('IndexedDB is not supported in this browser'));
                return;
            }

            const request = indexedDB.open('ModelStorageDB', 1);

            request.onupgradeneeded = function(event) {
                const db = event.target.result;
                if (!db.objectStoreNames.contains('modelStore')) {
                    db.createObjectStore('modelStore', { keyPath: 'key' });
                }
            };

            request.onsuccess = function(event) {
                resolve(event.target.result);
            };

            request.onerror = function(event) {
                console.error("IndexedDB error:", event.target.error);
                reject(new Error('Error opening IndexedDB: ' + event.target.error));
            };

            setTimeout(() => {
                reject(new Error('IndexedDB connection timed out'));
            }, 5000);
        });
    }

    function storeModelInIndexedDB(base64Model) {
        return new Promise((resolve, reject) => {
            openModelDatabase().then(db => {
                const transaction = db.transaction(['modelStore'], 'readwrite');
                const store = transaction.objectStore('modelStore');

                const request = store.put({
                    key: 'fullModel',
                    data: base64Model,
                    timestamp: Date.now()
                });

                request.onsuccess = () => resolve();
                request.onerror = () => reject(new Error('Error storing model'));
            }).catch(reject);
        });
    }

    function retrieveModelFromIndexedDB() {
        return new Promise((resolve, reject) => {
            openModelDatabase().then(db => {
                const transaction = db.transaction(['modelStore'], 'readonly');
                const store = transaction.objectStore('modelStore');

                const request = store.get('fullModel');

                request.onsuccess = function(event) {
                    console.log("Retrieve request successful:", event);
                    if (request.result) {
                        console.log("Retrieved model data:", request.result);
                        resolve(request.result.data);
                    } else {
                        console.warn('No model found in IndexedDB');
                        reject(new Error('No model found in IndexedDB'));
                    }
                };

                request.onerror = function(event) {
                    console.error('IndexedDB retrieval error:', event);
                    console.error('Full error object:', event.target.error);
                    reject(new Error('Error retrieving model: ' + event.target.error));
                };

                transaction.oncomplete = function() {
                    console.log('Transaction completed');
                };

                transaction.onerror = function(event) {
                    console.error('Transaction error:', event);
                    console.error('Transaction error details:', event.target.error);
                    reject(new Error('Transaction error: ' + event.target.error));
                };
            }).catch(error => {
                console.error('Database opening error:', error);
                reject(error);
            });
        });
    }

    // Refresh captcha logic
    refreshCaptchaButton.addEventListener('click', function () {
        showFloatingMessage("Captcha refreshed (simulated).");
    });

    // Simulate form submission for testing
    loginButton.addEventListener('click', function (event) {
        event.preventDefault();
      //  alert("Aadhaar and Captcha accepted (simulated).");

        const aadhaarNumber = document.getElementById('aadhaar-number').value;

        if (!aadhaarNumber) {
            showFloatingMessage("Please enter a valid Aadhaar number.");
            return;
        }

        // Send request to generate OTP
        fetch('/send-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ aadhaar_number: aadhaarNumber })
        })
        .then(response => {
            if (response.ok) {
              return response.json();
            } else if (response.status >= 400 ) {
              window.location.href = '/';
            } else {
              console.error('Error fetching AES key:', response.statusText);
          //    alert('An error occurred. Please try again.');
            }
          })
        .then(data => {
            if (data.error) {
            //    alert(`Error sending OTP: ${data.error}`);
            } else {
                //alert("OTP sent successfully! Please check your device.");
                console.log("Generated OTP is:", data.otp);
                displayOtpInput();
                const otpInput=document.getElementById('otp-input');
                if(otpInput){
                otpInput.value=data.otp;}
                loginButton.style.display = 'none';
            }
        })
        .catch(error => {
            console.error("Error sending OTP:", error);
            //alert("An error occurred while sending OTP.");
        });
    });

    function displayOtpInput() {
        const loginContainer = document.querySelector('.login-container');
        const otpHTML = `
            <div class="form-group">
                <label for="otp-input">Enter OTP</label>
                <input type="text" id="otp-input" placeholder="Enter OTP" required />
            </div>
            <button type="button" class="enable-webcam-button" id="otp-login-button">Login</button>
        `;
        loginContainer.insertAdjacentHTML('beforeend', otpHTML);

        const otpLoginButton = document.getElementById('otp-login-button');
        otpLoginButton.addEventListener('click', function () {
            const aadhaarNumber = document.getElementById('aadhaar-number').value;
            const otp = document.getElementById('otp-input').value;
            console.log(aadhaarNumber, otp);

            fetch('/verify-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ aadhaar_number: aadhaarNumber, otp: otp })
            })
            .then(response => {
                if (response.ok) {
                  return response.json();
                } else if (response.status >= 400  ) {
                  window.location.href = '/';
                } else {
                  console.error('Error fetching AES key:', response.statusText);
                  //alert('An error occurred. Please try again.');
                }
              })
            .then(data => {
                if (data.error) {
                   // alert(`OTP Verification Failed: ${data.error}`);
                } else {
                    showFloatingMessage("OTP Verified Successfully!");
                    fetchModelAndSignature();
                }
            })
            .catch(error => {
                console.error("Error verifying OTP:", error);
                //alert("An error occurred during OTP verification.");
            });
           // alert("OTP verified (simulated).");
            displayWebcamContainer();
        });
    }
    
function showFloatingMessage(message, type) {
    // Create a floating message container
    const messageContainer = document.createElement('div');
    messageContainer.classList.add('floating-message', type);
    messageContainer.innerText = message;

    // Append the message container to the body
    document.body.appendChild(messageContainer);

    // Automatically remove the message after 3 seconds
    setTimeout(() => {
        messageContainer.remove();
    }, 3000);
}

// Add CSS styles for floating messages
const style = document.createElement('style');
style.innerHTML = `
    .floating-message {
        position: fixed;
        top: 20px;
        left: 50%;
        transform: translateX(-50%);
        background-color: #333;
        color: white;
        padding: 10px 20px;
        border-radius: 5px;
        font-size: 16px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        z-index: 1000;
        opacity: 0;
        animation: fadeInOut 3s ease-in-out;
    }

    .floating-message.success {
        background-color: #28a745;
    }

    .floating-message.error {
        background-color: #dc3545;
    }

    @keyframes fadeInOut {
        0% { opacity: 0; }
        10% { opacity: 1; }
        90% { opacity: 1; }
        100% { opacity: 0; }
    }
`;
document.head.appendChild(style);

    function decryptModelAndCalculateHash() {
        console.log("Starting decryptModelAndCalculateHash");
        retrieveModelFromIndexedDB()
        .then(base64Model => {
            console.log("Retrieved base64Model:", base64Model);
            const base64AesKey = sessionStorage.getItem('aes_key');
            console.log("AES Key from sessionStorage:", base64AesKey);
            if (!base64Model || !base64AesKey) {
            //    alert("Model or AES key not found.");
                return;
            }

            try {
                const aesKeyBuffer = Uint8Array.from(atob(base64AesKey), c => c.charCodeAt(0)).buffer;
                const modelUint8Array = Uint8Array.from(atob(base64Model), c => c.charCodeAt(0));
                const iv = modelUint8Array.slice(0, 12);
                const tag = modelUint8Array.slice(modelUint8Array.length - 16);
                const encryptedData = modelUint8Array.slice(12, modelUint8Array.length - 16);

                return window.crypto.subtle.importKey(
                    'raw',
                    aesKeyBuffer,
                    { name: 'AES-GCM' },
                    false,
                    ['decrypt']
                )
                .then(importedKey => {
                    return window.crypto.subtle.decrypt(
                        {
                            name: 'AES-GCM',
                            iv: iv,
                            additionalData: new Uint8Array(0),
                            tagLength: 128
                        },
                        importedKey,
                        encryptedData
                    );
                })
                .then(decryptedData => {
                    const decoder = new TextDecoder('utf-8');
                    const decryptedText = decoder.decode(decryptedData);
                    return calculateHash(btoa(decryptedText));
                })
                .then(hash => {
                    console.log("Decrypted Model Hash:", hash);
                //    alert("Model successfully decrypted and hash calculated.");
                });
            } catch (error) {
                console.error("Preprocessing error:", error);
             //   alert(`Preprocessing failed: ${error.message}`);
            }
        })
        .catch(error => {
            console.error("Error retrieving model from IndexedDB:", error);
           // alert("Could not retrieve model from storage.");
        });
    }

    function fetchModelAndSignature() {
        fetch('/get-model')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to fetch model');
                }
                return response.blob();
            })
            .then(blob => {
                const reader = new FileReader();
                reader.onloadend = function() {
                    const base64Model = reader.result.split(',')[1];

                    storeModelInIndexedDB(base64Model)
                    .then(() => {
                        return calculateHash(base64Model);
                    })
                    .then(modelHash => {
                        console.log("Model hash:", modelHash);
                        sessionStorage.setItem('model_hash', modelHash);
                        return fetch('/get-signature');
                    })
                    .then(response => {
                        if (response.ok) {
                          return response.json();
                        } else if (response.status >= 400 ) {
                          window.location.href = '/';
                        } else {
                          console.error('Error fetching AES key:', response.statusText);
                     //     alert('An error occurred. Please try again.');
                        }
                      })
                    .then(signatureData => {
                        if (signatureData.error) {
                        //    alert(`Error fetching signature: ${signatureData.error}`);
                            return;
                        }
                        const publicKeyPem=signatureData.public_key;
                        decryptSign(base64Model, signatureData.signature, publicKeyPem);
                        sessionStorage.setItem('signature', JSON.stringify(signatureData.signature));
                        sessionStorage.setItem('public_key', JSON.stringify(signatureData.public_key));

                      //  alert("Model and signature successfully fetched and stored.");
                    })
                    .catch(error => {
                        console.error("Error in model processing:", error);
                      //  alert("An error occurred while processing the model.");
                    });
                };
                reader.readAsDataURL(blob);
            })
            .catch(error => {
                console.error("Error fetching model:", error);
              //  alert("An error occurred while fetching the model.");
            });
    }

    function base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const length = binaryString.length;
        const buffer = new ArrayBuffer(length);
        const view = new Uint8Array(buffer);

        for (let i = 0; i < length; i++) {
            view[i] = binaryString.charCodeAt(i);
        }

        return buffer;
    }

    async function importPublicKey(pem) {
        const binaryDerString = pemToBinary(pem);
        const binaryDer = str2ab(binaryDerString);

        return await crypto.subtle.importKey(
            "spki",
            binaryDer,
            {
                name: "RSA-PSS",
                hash: "SHA-256"
            },
            true,
            ["verify"]
        );
    }

    function str2ab(str) {
        const buf = new ArrayBuffer(str.length);
        const view = new Uint8Array(buf);
        for (let i = 0; i < str.length; i++) {
            view[i] = str.charCodeAt(i) & 0xFF;
        }
        return buf;
    }

    async function verifySignature(publicKey, signature, modelData) {
        const modelHashBuffer = await createHash(modelData);
        const modelHashHex = arrayBufferToHex(modelHashBuffer);
        console.log("Calculated Model Hash (SHA-256):", modelHashHex);
        const signatureBase64 = arrayBufferToBase64(signature);

        const isVerified = await crypto.subtle.verify(
            {
                name: "RSA-PSS",
                saltLength: 32,
            },
            publicKey,
            signature,
            modelHashBuffer
        );

        if (!isVerified) {
            console.error("Signature verification failed!");
        } else {
            console.log("Signature verification passed!");
        }

        return isVerified;
    }

    async function createHash(data) {
        const hashBuffer = await crypto.subtle.digest("SHA-256", data);
        return hashBuffer;
    }

    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    function arrayBufferToHex(buffer) {
        const byteArray = new Uint8Array(buffer);
        return Array.from(byteArray).map(byte => byte.toString(16).padStart(2, '0')).join('');
    }

    function pemToBinary(pem) {
        const lines = pem.split("\n");
        const encoded = lines.slice(1, lines.length - 1).join("");
        return window.atob(encoded);
    }

    async function decryptSign(modelDataBase64, signatureBase64, publicKeyPem) {
        const modelData = base64ToArrayBuffer(modelDataBase64);
        const signature = base64ToArrayBuffer(signatureBase64);
        const publicKey = await importPublicKey(publicKeyPem);

        const isSignatureValid = await verifySignature(publicKey, signature, modelData);

        if (isSignatureValid) {
            console.log("The model is authentic and intact.");
        } else {
            console.error("The model has been tampered with or the signature is invalid.");
        }
    }

    function calculateHash(base64Data) {
        const binaryData = atob(base64Data);
        const arrayBuffer = new ArrayBuffer(binaryData.length);
        const uint8Array = new Uint8Array(arrayBuffer);

        for (let i = 0; i < binaryData.length; i++) {
            uint8Array[i] = binaryData.charCodeAt(i);
        }

        return crypto.subtle.digest('SHA-256', arrayBuffer).then(hashBuffer => {
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
            return hashHex;
        });
    }

    function displayWebcamContainer() {
        const mainElement = document.querySelector('main');
        const webcamHTML = `
            <div class="webcam-container">
                <h3>Verify Identity via Webcam</h3>
                <video id="webcam" autoplay playsinline></video>
                <button id="veri-live" class="verify-liveness">Verify Liveness</button>
            </div>
        `;
        mainElement.insertAdjacentHTML('beforeend', webcamHTML);

        const webcamElement = document.getElementById('webcam');
        const verifyLivenessButton = document.getElementById('veri-live');
        
        verifyLivenessButton.addEventListener('click', async function () {
            const crypto = window.crypto || window.msCrypto;
            
            try {
                // Generate RSA Key Pair
                const keyPair = await crypto.subtle.generateKey(
                    {
                        name: "RSA-OAEP",
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                        hash: { name: "SHA-256" },
                    },
                    true,
                    ["encrypt", "decrypt"]
                );

                // Export Public Key
                const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
                const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKey)));

                // Fetch AES Key
                const response = await fetch('/fetch-aes-key', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ public_key: publicKeyBase64 }),
                });

                if (!response.ok) {
                    if (response.status >= 400) {
                        window.location.href = '/';
                        return;
                    }
                    throw new Error('Error fetching AES key');
                }

                const data = await response.json();
                if (data.error) {
                    console.error('AES key error:', data.error);
                    return;
                }

                // Decrypt AES Key
                const encryptedAesKey = Uint8Array.from(atob(data.encrypted_aes_key), c => c.charCodeAt(0));
                const decryptedKey = await crypto.subtle.decrypt(
                    { name: "RSA-OAEP" },
                    keyPair.privateKey,
                    encryptedAesKey
                );

                const aesKey = new TextDecoder().decode(decryptedKey);
                sessionStorage.setItem('aes_key', aesKey);

                // Start Webcam and Liveness Detection
                const stream = await navigator.mediaDevices.getUserMedia({
                    video: {
                        width: { ideal: 640 },
                        height: { ideal: 480 },
                        facingMode: 'user'
                    }
                });

                webcamElement.srcObject = stream;
                await new Promise((resolve) => {
                    webcamElement.onloadedmetadata = () => {
                        webcamElement.play();
                        resolve();
                    };
                });

                // Load Face Detection Models
                await Promise.all([
                    faceapi.nets.ssdMobilenetv1.loadFromUri('https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights/ssd_mobilenetv1_model-weights_manifest.json'),
                    faceapi.nets.faceLandmark68Net.loadFromUri('https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights/face_landmark_68_model-weights_manifest.json'),
                    faceapi.nets.faceExpressionNet.loadFromUri('https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights/face_expression_model-weights_manifest.json')
                ]);

                console.log('All face detection models loaded successfully');
                function loadScript(src) {
                    return new Promise((resolve, reject) => {
                        const script = document.createElement('script');
                        script.src = src;
                        script.onload = resolve;
                        script.onerror = reject;
                        document.head.appendChild(script);
                    });
                }
                async function initializeFaceVerification() {
                    try {
                        // Function to dynamically load a script
                        function loadScript(src) {
                            return new Promise((resolve, reject) => {
                                const script = document.createElement('script');
                                script.src = src;
                                script.onload = resolve;
                                script.onerror = reject;
                                document.head.appendChild(script);
                            });
                        }
                
                        // Load face-api.js from a reliable CDN
                        await loadScript('https://cdn.jsdelivr.net/npm/face-api.js/dist/face-api.min.js');
                
                        // Verify face-api.js is loaded
                        if (typeof faceapi === 'undefined') {
                            throw new Error('face-api.js failed to load');
                        }
                
                        // Load face detection models with multiple fallback URLs
                        const modelUrls = [
                            'https://justadudewhohacks.github.io/face-api.js/models',
                            'https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights'
                        ];
                
                        async function loadModels() {
                            for (const baseUrl of modelUrls) {
                                try {
                                    await faceapi.nets.tinyFaceDetector.loadFromUri(baseUrl);
                                    await faceapi.nets.faceLandmark68Net.loadFromUri(baseUrl);
                                    await faceapi.nets.faceRecognitionNet.loadFromUri(baseUrl);
                                    console.log(`Models loaded successfully from ${baseUrl}`);
                                    return true;
                                } catch (error) {
                                    console.error(`Failed to load models from ${baseUrl}:`, error);
                                }
                            }
                            throw new Error('Failed to load face detection models');
                        }
                
                        // Load models
                        await loadModels();
                
                        // Start video stream
                        const webcamElement = document.getElementById('webcam');
                        if (!webcamElement) {
                            throw new Error('Webcam element not found');
                        }
                
                        const stream = await navigator.mediaDevices.getUserMedia({
                            video: {
                                width: { ideal: 640 },
                                height: { ideal: 480 },
                                facingMode: 'user'
                            }
                        });
                
                        webcamElement.srcObject = stream;
                        await new Promise((resolve, reject) => {
                            webcamElement.onloadedmetadata = () => {
                                webcamElement.play();
                                resolve();
                            };
                            webcamElement.onerror = reject;
                        });
                
                        // Reference descriptor to store server image face
                        let referenceDescriptor = null;
                
                        async function requestImageFromServer() {
                            try {
                                const response = await fetch('/get-image');
                                
                                if (!response.ok) {
                                    throw new Error('Network response was not ok');
                                }
                                
                                const imageBlob = await response.blob();
                                const img = new Image();
                                
                                return new Promise((resolve, reject) => {
                                    img.onload = async () => {
                                        try {
                                            const canvas = document.createElement('canvas');
                                            canvas.width = img.width;
                                            canvas.height = img.height;
                                            const ctx = canvas.getContext('2d');
                                            ctx.drawImage(img, 0, 0, img.width, img.height);
                        
                                            const detections = await faceapi.detectAllFaces(canvas, new faceapi.TinyFaceDetectorOptions())
                                                .withFaceLandmarks()
                                                .withFaceDescriptors();
                        
                                            if (detections.length > 0) {
                                                referenceDescriptor = detections[0].descriptor;
                                                resolve(referenceDescriptor);
                                            } else {
                                                reject(new Error('No face detected in server image'));
                                            }
                                        } catch (faceError) {
                                            reject(faceError);
                                        }
                                    };
                        
                                    img.onerror = () => reject(new Error('Error loading image from server'));
                                    img.src = URL.createObjectURL(imageBlob);
                                });
                            } catch (error) {
                                throw new Error(`Error fetching image: ${error.message}`);
                            }
                        }
                
                        async function checkLiveness() {
                            try {
                                // Detect faces in the webcam stream
                                const detections = await faceapi.detectAllFaces(
                                    webcamElement, 
                                    new faceapi.SsdMobilenetv1Options({ minConfidence: 0.7 })
                                );
                                
                                if (detections.length === 0) {
                                    console.log('No face detected, retrying...');
                                    setTimeout(checkLiveness, 1000);
                                    return;
                                }
                
                                // Perform face matching
                                const webcamDetections = await faceapi.detectAllFaces(
                                    webcamElement, 
                                    new faceapi.TinyFaceDetectorOptions()
                                ).withFaceLandmarks().withFaceDescriptors();
                
                                if (webcamDetections.length === 0 || !referenceDescriptor) {
                                    throw new Error('No face descriptors available');
                                }
                
                                const currentDescriptor = webcamDetections[0].descriptor;
                                const distance = faceapi.euclideanDistance(referenceDescriptor, currentDescriptor);
                
                                // Adjust distance threshold as needed
                                if (distance < 0.4) {
                                    showFloatingMessage('Verification Successful: Face Matched and Liveness Confirmed!');
                                    
                                    window.location.href = 'https://uidai.gov.in/en/my-aadhaar/get-aadhaar.html';
                                } else {
                                    showFloatingMessage('Face Matching Failed. Please try again.');
                                    window.location.href='/'
                                }
                            } catch (error) {
                                console.error('Liveness Check Error:', error);
                                showFloatingMessage(`Verification Failed: ${error.message}`);
                            }
                        }
                
                        // Start the verification process
                        await requestImageFromServer();
                        await checkLiveness();
                
                    } catch (error) {
                        console.error('Face Verification Initialization Error:', error);
                        showFloatingMessage(`Verification Failed: ${error.message}`);
                    }
                }

                initializeFaceVerification();
                
               

            } catch (err) {
                console.error("Error during RSA key generation, AES key decryption, or liveness detection:", err);
            }
        });
    }
});