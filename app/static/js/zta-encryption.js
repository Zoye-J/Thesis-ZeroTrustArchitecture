// FINAL FIXED VERSION: app/static/js/zta-encryption.js
console.log('🔐 zta-encryption.js loaded at:', new Date().toISOString());
class ZTAEncryption {
    constructor() {
        this.agentPublicKey = null;
        this.userPrivateKey = null;
        this.userPublicKey = null;
        this.initialized = false;
        this.initPromise = null; // Add promise to track initialization
        this.setup = window.ztaAutomatedSetup;
    }
    
    async init() {
        // Prevent multiple simultaneous initializations
        if (this.initPromise) {
            return this.initPromise;
        }
        
        this.initPromise = this._doInit();
        return this.initPromise;
    }
    
    async _doInit() {
        try {
            console.log('Initializing ZTA encryption...');
            
            // Initialize IndexedDB through automated setup first
            if (this.setup) {
                await this.setup.initDB();
            }
            
            // 1. Get OPA Agent public key - NO AUTH REQUIRED
            try {
                const agentKeyResponse = await fetch('/api/opa-agent-public-key');
                
                if (agentKeyResponse.ok) {
                    const agentKeyData = await agentKeyResponse.json();
                    this.agentPublicKey = agentKeyData.public_key;
                    console.log('✅ OPA Agent public key loaded');
                } else {
                    console.warn('⚠️ Could not get OPA Agent key');
                }
            } catch (error) {
                console.warn('Failed to fetch OPA Agent key:', error);
            }
            
            // 2. Try to get user's private key from IndexedDB
            if (this.setup) {
                try {
                    const keyPair = await this.setup.getStoredKeyPair();
                    if (keyPair && keyPair.privateKey) {
                        this.userPrivateKey = keyPair.privateKey;
                        this.userPublicKey = keyPair.publicKey;
                        console.log('✅ User RSA keys loaded from IndexedDB');
                    }
                } catch (error) {
                    console.warn('Could not load user keys:', error);
                }
            }
            
            this.initialized = true;
            console.log('✅ ZTA Encryption initialized');
            return true;
            
        } catch (error) {
            console.error('❌ Failed to initialize ZTA encryption:', error);
            this.initialized = false;
            throw error;
        }
    }
    
    async ensureInitialized() {
        if (!this.initialized) {
            await this.init();
        }
        if (!this.initialized) {
            throw new Error('ZTA encryption initialization failed');
        }
        return true;
    }
    
    async encryptForAgent(data) {
        await this.ensureInitialized();
        
        if (!this.agentPublicKey) {
            throw new Error('OPA Agent public key not available');
        }
        
        try {
            // Convert data to JSON string
            const jsonString = JSON.stringify(data);
            
            // Import OPA Agent's public key
            const publicKey = await this.importPublicKey(this.agentPublicKey);
            
            // Encrypt with RSA-OAEP
            const encoder = new TextEncoder();
            const encoded = encoder.encode(jsonString);
            
            // Note: Web Crypto API has size limitations for RSA (max ~190 bytes)
            // For larger data, we need to use hybrid encryption
            if (encoded.length > 190) {
                return await this.hybridEncrypt(data);
            }
            
            const encrypted = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP"
                },
                publicKey,
                encoded
            );
            
            // Convert to base64
            return this.arrayBufferToBase64(encrypted);
            
        } catch (error) {
            console.error('Encryption failed:', error);
            throw error;
        }
    }
    
    async hybridEncrypt(data) {
        // Hybrid encryption: RSA for key, AES for data
        const jsonString = JSON.stringify(data);
        const encoder = new TextEncoder();
        const dataBytes = encoder.encode(jsonString);
        
        // Generate random AES key
        const aesKey = await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
        
        // Encrypt data with AES
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            dataBytes
        );
        
        // Export AES key
        const exportedAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
        
        // Encrypt AES key with RSA
        const agentPublicKey = await this.importPublicKey(this.agentPublicKey);
        const encryptedKey = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            agentPublicKey,
            exportedAesKey
        );
        
        return JSON.stringify({
            encrypted_key: this.arrayBufferToBase64(encryptedKey),
            encrypted_data: this.arrayBufferToBase64(encryptedData),
            iv: this.arrayBufferToBase64(iv),
            algorithm: "RSA-AES-HYBRID"
        });
    }
    
    async decryptFromAgent(encryptedData) {
        await this.ensureInitialized();
        
        if (!this.userPrivateKey) {
            // Try one more time to load from IndexedDB
            if (this.setup) {
                try {
                    const keyPair = await this.setup.getStoredKeyPair();
                    if (keyPair && keyPair.privateKey) {
                        this.userPrivateKey = keyPair.privateKey;
                        this.userPublicKey = keyPair.publicKey;
                        console.log('✅ Loaded private key on demand from IndexedDB');
                    }
                } catch (error) {
                    console.error('Failed to load private key on demand:', error);
                }
            }
            
            if (!this.userPrivateKey) {
                throw new Error('User private key not available');
            }
        }
        
        try {
            // Check if it's hybrid encrypted (from backend)
            if (typeof encryptedData === 'string') {
                // Try to parse as JSON to check for hybrid format
                try {
                    const parsed = JSON.parse(encryptedData);
                    // Backend hybrid format has 'type' field
                    if (parsed.type === 'hybrid') {
                        console.log('🔐 Detected backend hybrid encryption');
                        return await this.hybridDecryptBackend(parsed);
                    }
                    // Frontend hybrid format has 'algorithm' field
                    if (parsed.algorithm === "RSA-AES-HYBRID") {
                        return await this.hybridDecrypt(parsed);
                    }
                } catch {
                    // Not JSON, continue with regular RSA
                }
            }
            
            // Regular RSA decryption
            console.log('🔐 Using direct RSA decryption');
            const privateKey = await this.importPrivateKey(this.userPrivateKey);
            const encrypted = this.base64ToArrayBuffer(encryptedData);
            
            const decrypted = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                privateKey,
                encrypted
            );
            
            const decoder = new TextDecoder();
            return JSON.parse(decoder.decode(decrypted));
            
        } catch (error) {
            console.error('Decryption failed:', error);
            throw error;
        }
    }

    async hybridDecryptBackend(encryptedPackage) {
        const privateKey = await this.importPrivateKey(this.userPrivateKey);
        
        // Decrypt AES key with RSA
        const encryptedKey = this.base64ToArrayBuffer(encryptedPackage.encrypted_key);
        const exportedAesKey = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedKey
        );
        
        // Import AES key
        const aesKey = await window.crypto.subtle.importKey(
            "raw",
            exportedAesKey,
            { name: "AES-GCM", length: 256 },
            true,
            ["decrypt"]
        );
        
        // Decrypt data with AES
        const iv = this.base64ToArrayBuffer(encryptedPackage.iv);
        const encryptedData = this.base64ToArrayBuffer(encryptedPackage.encrypted_data);
        
        const decryptedData = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            encryptedData
        );
        
        const decoder = new TextDecoder();
        return JSON.parse(decoder.decode(decryptedData));
    }
    
    async hybridDecrypt(encryptedPackage) {
        const privateKey = await this.importPrivateKey(this.userPrivateKey);
        
        // Decrypt AES key with RSA
        const encryptedKey = this.base64ToArrayBuffer(encryptedPackage.encrypted_key);
        const exportedAesKey = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedKey
        );
        
        // Import AES key
        const aesKey = await window.crypto.subtle.importKey(
            "raw",
            exportedAesKey,
            { name: "AES-GCM", length: 256 },
            true,
            ["decrypt"]
        );
        
        // Decrypt data with AES
        const iv = this.base64ToArrayBuffer(encryptedPackage.iv);
        const encryptedData = this.base64ToArrayBuffer(encryptedPackage.encrypted_data);
        
        const decryptedData = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            encryptedData
        );
        
        const decoder = new TextDecoder();
        return JSON.parse(decoder.decode(decryptedData));
    }
    
    async importPublicKey(pem) {
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        const pemContents = pem.replace(pemHeader, '').replace(pemFooter, '').replace(/\s/g, '');
        const binaryDer = this.base64ToArrayBuffer(pemContents);
        
        return await window.crypto.subtle.importKey(
            "spki",
            binaryDer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
        );
    }
    
    async importPrivateKey(pem) {
        const pemHeader = "-----BEGIN PRIVATE KEY-----";
        const pemFooter = "-----END PRIVATE KEY-----";
        const pemContents = pem.replace(pemHeader, '').replace(pemFooter, '').replace(/\s/g, '');
        const binaryDer = this.base64ToArrayBuffer(pemContents);
        
        return await window.crypto.subtle.importKey(
            "pkcs8",
            binaryDer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt"]
        );
    }
    
    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
    
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    async sendEncryptedRequest(endpoint, method = 'GET', data = null) {
        await this.ensureInitialized();
        
        // Attach certificate if we have automated setup
        let headers = { 'Content-Type': 'application/json' };
        if (this.setup) {
            headers = await this.setup.attachCertificateToRequest(headers);
        }
        
        const requestData = {
            endpoint: endpoint,
            method: method,
            data: data,
            timestamp: new Date().toISOString()
        };
        
        const encryptedPayload = await this.encryptForAgent(requestData);
        
        const response = await fetch('/api/encrypted-request', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({
                encrypted_payload: encryptedPayload,
                user_public_key: this.userPublicKey
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${await response.text()}`);
        }
        
        const responseData = await response.json();
        
        if (responseData.encrypted_response) {
            return await this.decryptFromAgent(responseData.encrypted_response);
        } else {
            return responseData;
        }
    }
    
    // Helper to automatically attach security to all fetches
    async enableAutoSecurity() {
        const originalFetch = window.fetch;
        const self = this;
        
        window.fetch = async function(url, options = {}) {
            // Only modify requests to our API
            if (typeof url === 'string' && url.includes('/api/')) {
                // Skip registration endpoints
                if (!url.includes('/api/registration') && !url.includes('/api/auth/login')) {
                    try {
                        // Attach certificate
                        if (self.setup) {
                            options.headers = options.headers || {};
                            await self.setup.attachCertificateToRequest(options.headers);
                        }
                        
                        // Initialize encryption if needed
                        await self.ensureInitialized();
                    } catch (error) {
                        console.warn('Could not attach security headers:', error);
                    }
                }
            }
            
            return originalFetch.call(this, url, options);
        };
        
        console.log('Auto-security attachment enabled');
    }
}

class ZTAAutomatedSetup {
    constructor() {
        this.dbName = 'ZTA_Certificates';
        this.dbVersion = 2;
        this.db = null;
        this.currentUserId = null;
        this.initPromise = null;
    }
    
    async initDB() {
        if (this.initPromise) {
            return this.initPromise;
        }
        
        this.initPromise = new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.dbVersion);
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                const oldVersion = event.oldVersion;
                
                if (!db.objectStoreNames.contains('certificates')) {
                    const store = db.createObjectStore('certificates', { keyPath: 'id' });
                    store.createIndex('userId', 'userId', { unique: false });
                    store.createIndex('fingerprint', 'fingerprint', { unique: true });
                }
                
                if (!db.objectStoreNames.contains('rsa_keys')) {
                    const store = db.createObjectStore('rsa_keys', { keyPath: 'id' });
                    store.createIndex('userId', 'userId', { unique: true });
                }
                
                if (oldVersion < 2) {
                    if (!db.objectStoreNames.contains('tokens')) {
                        const store = db.createObjectStore('tokens', { keyPath: 'type' });
                    }
                }
            };
            
            request.onsuccess = (event) => {
                this.db = event.target.result;
                resolve(this.db);
            };
            
            request.onerror = (event) => {
                console.error('IndexedDB error:', event.target.error);
                reject('Failed to open IndexedDB');
            };
        });
        
        return this.initPromise;
    }
    
    async generateRSAKeyPair(userId = null) {
        await this.initDB();
        
        try {
            console.log('Generating RSA key pair...');
            
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256",
                },
                true,
                ["encrypt", "decrypt"]
            );
            
            const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
            const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
            
            const publicKeyPem = this.arrayBufferToPem(publicKey, 'PUBLIC KEY');
            const privateKeyPem = this.arrayBufferToPem(privateKey, 'PRIVATE KEY');
            
            await this.storeKeyPair(publicKeyPem, privateKeyPem, userId);
            
            console.log('✅ RSA key pair generated successfully');
            return {
                publicKey: publicKeyPem,
                publicKeyArray: publicKey,
                privateKey: privateKeyPem,
                userId: userId
            };
            
        } catch (error) {
            console.error('❌ RSA key generation failed:', error);
            throw error;
        }
    }
    
    arrayBufferToPem(buffer, label) {
        const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        const pem = `-----BEGIN ${label}-----\n`;
        const pemEnd = `\n-----END ${label}-----\n`;
        
        let formatted = '';
        for (let i = 0; i < base64.length; i += 64) {
            formatted += base64.substr(i, 64) + '\n';
        }
        
        return pem + formatted + pemEnd;
    }
    
    async storeKeyPair(publicKeyPem, privateKeyPem, userId = null) {
        await this.initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['rsa_keys'], 'readwrite');
            const store = transaction.objectStore('rsa_keys');
            
            const keyData = {
                id: 'user_rsa_keypair',
                userId: userId || 'current_user',
                publicKey: publicKeyPem,
                privateKey: privateKeyPem,
                createdAt: new Date().toISOString(),
                algorithm: 'RSA-OAEP-2048'
            };
            
            const request = store.put(keyData);
            
            request.onsuccess = () => {
                console.log('✅ RSA key pair stored in IndexedDB');
                resolve();
            };
            
            request.onerror = (event) => {
                reject('Failed to store key pair: ' + event.target.error);
            };
        });
    }
    
    async getStoredKeyPair() {
        await this.initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['rsa_keys'], 'readonly');
            const store = transaction.objectStore('rsa_keys');
            const request = store.get('user_rsa_keypair');
            
            request.onsuccess = (event) => {
                resolve(event.target.result);
            };
            
            request.onerror = (event) => {
                reject('Failed to retrieve key pair: ' + event.target.error);
            };
        });
    }
    
    async generateCSR(publicKeyPem, userInfo) {
        const csrData = {
            publicKey: publicKeyPem,
            subject: {
                CN: userInfo.email,
                O: `Government ${userInfo.department}`,
                C: 'GB',
                ST: 'England',
                L: 'London',
                emailAddress: userInfo.email
            },
            userInfo: userInfo
        };
        
        return JSON.stringify(csrData);
    }
    
    async storeCertificate(certPem, userId) {
        await this.initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['certificates'], 'readwrite');
            const store = transaction.objectStore('certificates');
            
            const fingerprint = this.calculateFingerprintSimple(certPem);
            const certData = {
                id: `cert_${Date.now()}`,
                userId: userId,
                certificate: certPem,
                storedAt: new Date().toISOString(),
                fingerprint: fingerprint,
                isActive: true
            };
            
            const request = store.put(certData);
            
            request.onsuccess = () => {
                console.log('✅ Certificate stored in IndexedDB');
                resolve(certData);
            };
            
            request.onerror = (event) => {
                reject('Failed to store certificate: ' + event.target.error);
            };
        });
    }
    
    calculateFingerprintSimple(certPem) {
        const certBody = certPem
            .replace(/-----BEGIN CERTIFICATE-----/, '')
            .replace(/-----END CERTIFICATE-----/, '')
            .replace(/\s/g, '');
        
        let hash = 0;
        for (let i = 0; i < certBody.length; i++) {
            const char = certBody.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        
        return Math.abs(hash).toString(16).substring(0, 16);
    }
    
    async attachCertificateToRequest(headers = {}) {
        await this.initDB();
        
        try {
            const cert = await this.getCurrentCertificate();
            if (cert && cert.certificate) {
                const certBase64 = btoa(cert.certificate);
                headers['X-Client-Certificate'] = certBase64;
                headers['X-Certificate-Fingerprint'] = cert.fingerprint;
            }
            return headers;
        } catch (error) {
            console.warn('Could not attach certificate:', error);
            return headers;
        }
    }
    
    async getCurrentCertificate() {
        await this.initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['certificates'], 'readonly');
            const store = transaction.objectStore('certificates');
            const index = store.index('userId');
            
            const request = index.get(this.currentUserId || 'current_user');
            
            request.onsuccess = (event) => {
                resolve(event.target.result);
            };
            
            request.onerror = (event) => {
                reject('Failed to retrieve certificate: ' + event.target.error);
            };
        });
    }
    
    async storeToken(tokenType, tokenValue) {
        await this.initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['tokens'], 'readwrite');
            const store = transaction.objectStore('tokens');
            
            const tokenData = {
                type: tokenType,
                value: tokenValue,
                storedAt: new Date().toISOString()
            };
            
            const request = store.put(tokenData);
            
            request.onsuccess = () => resolve();
            request.onerror = (event) => reject(event.target.error);
        });
    }
    
    async getToken(tokenType) {
        await this.initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['tokens'], 'readonly');
            const store = transaction.objectStore('tokens');
            
            const request = store.get(tokenType);
            
            request.onsuccess = (event) => resolve(event.target.result?.value);
            request.onerror = (event) => reject(event.target.error);
        });
    }
    
    setCurrentUserId(userId) {
        this.currentUserId = userId;
        console.log('Current user ID set:', userId);
    }
    
    async automatedRegistration(formData) {
        await this.initDB();
        
        try {
            console.log('Starting automated registration...');
            
            const keyPair = await this.generateRSAKeyPair();
            
            const csrData = await this.generateCSR(keyPair.publicKey, {
                email: formData.email,
                department: formData.department || 'Operations',
                username: formData.username
            });
            
            const response = await fetch('/api/registration/automated', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_data: formData,
                    csr_data: JSON.parse(csrData),
                    public_key: keyPair.publicKey
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                await this.storeCertificate(result.certificate, result.user_id);
                await this.storeKeyPair(keyPair.publicKey, keyPair.privateKey, result.user_id);
                this.setCurrentUserId(result.user_id);
                
                return {
                    success: true,
                    user_id: result.user_id,
                    message: 'Registration complete!'
                };
            } else {
                throw new Error(result.error || 'Registration failed');
            }
            
        } catch (error) {
            console.error('Automated registration failed:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }
}

// Initialize global instances
window.ztaAutomatedSetup = new ZTAAutomatedSetup();
window.ztaEncryptor = new ZTAEncryption();

// Export for module systems (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ZTAEncryption, ZTAAutomatedSetup };
}

