// CREATE: app/static/js/zta-encryption.js

class ZTAEncryption {
    constructor() {
        this.agentPublicKey = null;
        this.userPrivateKey = null;
        this.userPublicKey = null;
        this.initialized = false;
    }
    
    async init() {
        try {
            // 1. Get OPA Agent public key
            const agentKeyResponse = await fetch('/api/opa-agent-public-key');
            if (!agentKeyResponse.ok) throw new Error('Failed to get OPA Agent key');
            
            const agentKeyData = await agentKeyResponse.json();
            this.agentPublicKey = agentKeyData.public_key;
            
            // 2. Try to load user's private key from localStorage (demo)
            // In production, use Web Crypto API or hardware security module
            const storedPrivateKey = localStorage.getItem('zta_user_private_key');
            if (storedPrivateKey) {
                this.userPrivateKey = storedPrivateKey;
            }
            
            // 3. Get user's public key from server (after login)
            const userPublicKeyResponse = await fetch('/api/user-public-key');
            if (userPublicKeyResponse.ok) {
                const userKeyData = await userPublicKeyResponse.json();
                this.userPublicKey = userKeyData.public_key;
            }
            
            this.initialized = true;
            console.log('ZTA Encryption initialized');
            
        } catch (error) {
            console.error('Failed to initialize ZTA encryption:', error);
            throw error;
        }
    }
    
    async encryptForAgent(data) {
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
            
            // Note: Web Crypto API has size limitations for RSA
            // We need to handle large data differently
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
    
    async decryptFromAgent(encryptedBase64) {
        if (!this.userPrivateKey) {
            throw new Error('User private key not available');
        }
        
        try {
            // Import user's private key
            const privateKey = await this.importPrivateKey(this.userPrivateKey);
            
            // Convert from base64
            const encrypted = this.base64ToArrayBuffer(encryptedBase64);
            
            // Decrypt
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP"
                },
                privateKey,
                encrypted
            );
            
            // Convert back to string
            const decoder = new TextDecoder();
            return JSON.parse(decoder.decode(decrypted));
            
        } catch (error) {
            console.error('Decryption failed:', error);
            throw error;
        }
    }
    
    async importPublicKey(pem) {
        // Convert PEM to ArrayBuffer
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        const pemContents = pem.replace(pemHeader, '').replace(pemFooter, '').replace(/\s/g, '');
        const binaryDer = this.base64ToArrayBuffer(pemContents);
        
        return await window.crypto.subtle.importKey(
            "spki",
            binaryDer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["encrypt"]
        );
    }
    
    async importPrivateKey(pem) {
        // Convert PEM to ArrayBuffer
        const pemHeader = "-----BEGIN PRIVATE KEY-----";
        const pemFooter = "-----END PRIVATE KEY-----";
        const pemContents = pem.replace(pemHeader, '').replace(pemFooter, '').replace(/\s/g, '');
        const binaryDer = this.base64ToArrayBuffer(pemContents);
        
        return await window.crypto.subtle.importKey(
            "pkcs8",
            binaryDer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
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
    
    // Helper method to send encrypted request
    async sendEncryptedRequest(endpoint, method = 'GET', data = null) {
        if (!this.initialized) {
            await this.init();
        }
        
        // Prepare request data
        const requestData = {
            endpoint: endpoint,
            method: method,
            data: data,
            timestamp: new Date().toISOString()
        };
        
        // Encrypt for OPA Agent
        const encryptedPayload = await this.encryptForAgent(requestData);
        
        // Send to Gateway
        const response = await fetch('/api/encrypted-request', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                encrypted_payload: encryptedPayload,
                user_public_key: this.userPublicKey
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${await response.text()}`);
        }
        
        const responseData = await response.json();
        
        // Decrypt the response
        if (responseData.encrypted_response) {
            return await this.decryptFromAgent(responseData.encrypted_response);
        } else {
            return responseData;
        }
    }
}

// Create global instance
window.ztaEncryptor = new ZTAEncryption();