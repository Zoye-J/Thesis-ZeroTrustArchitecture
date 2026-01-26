// app/static/js/automated-registration.js
class AutomatedRegistration {
    constructor() {
        this.setup = window.ztaAutomatedSetup;
    }
    
    async init() {
        try {
            await this.setup.initDB();
            console.log('Automated registration ready');
        } catch (error) {
            console.error('Failed to init automated registration:', error);
        }
    }
    
    async handleRegistration(formData) {
        try {
            // Step 1: Generate RSA key pair in browser
            console.log('Generating RSA key pair...');
            const keyPair = await this.setup.generateRSAKeyPair();
            
            // Step 2: Create CSR
            console.log('Creating CSR...');
            const csrData = await this.setup.generateCSR(keyPair.publicKey, {
                email: formData.email,
                department: formData.department || 'Operations',
                username: formData.username
            });
            
            // Step 3: Send registration request with CSR and public key
            console.log('Sending automated registration...');
            const response = await fetch('https://localhost:5001/api/register/automated', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    user_data: formData,
                    csr_data: JSON.parse(csrData),
                    public_key: keyPair.publicKey
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                // Step 4: Store certificate in IndexedDB
                console.log('Storing certificate...');
                await this.setup.storeCertificate(result.certificate, result.user_id);
                
                // Step 5: Update key storage with user ID
                await this.updateKeyPairUserId(result.user_id);
                
                return {
                    success: true,
                    message: 'Registration complete!',
                    user_id: result.user_id,
                    has_certificate: true
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
    
    async updateKeyPairUserId(userId) {
        // Update the stored key pair with actual user ID
        const keyPair = await this.setup.getStoredKeyPair();
        if (keyPair) {
            keyPair.userId = userId;
            
            const transaction = this.setup.db.transaction(['rsa_keys'], 'readwrite');
            const store = transaction.objectStore('rsa_keys');
            await store.put(keyPair);
        }
    }
    
    async attachSecurityToFetch() {
        // Monkey-patch fetch to automatically attach certificate
        const originalFetch = window.fetch;
        
        window.fetch = async function(url, options = {}) {
            // Add certificate to requests to our API
            if (url.includes('/api/') && !url.includes('/api/registration')) {
                const setup = window.ztaAutomatedSetup;
                if (setup && setup.db) {
                    options.headers = options.headers || {};
                    await setup.attachCertificateToRequest(options.headers);
                }
            }
            
            return originalFetch.call(this, url, options);
        };
        
        console.log('Security auto-attachment enabled');
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', async () => {
    window.automatedRegistration = new AutomatedRegistration();
    await window.automatedRegistration.init();
    
    // Auto-attach to fetch for all subsequent requests
    await window.automatedRegistration.attachSecurityToFetch();
    
    // Hook into registration form
    const registerForm = document.querySelector('form[action*="register"]');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // Collect form data
            const formData = {
                username: document.getElementById('username')?.value,
                email: document.getElementById('email')?.value,
                password: document.getElementById('password')?.value,
                full_name: document.getElementById('full_name')?.value
            };
            
            // Use automated registration
            const result = await window.automatedRegistration.handleRegistration(formData);
            
            if (result.success) {
                alert('Registration successful! You can now login.');
                window.location.href = '/login';
            } else {
                alert('Registration failed: ' + result.error);
            }
        });
    }
});