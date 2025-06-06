// ====================
// MODULAR ARCHITECTURE
// ====================

// 1. STATE MANAGEMENT
class AppState {
    constructor() {
        this.keyPair = null;
        this.isReady = false;
        this.listeners = {};
    }

    setKeyPair(keyPair) {
        this.keyPair = keyPair;
        this.isReady = !!keyPair;
        this.notify('keysChanged', { keyPair, isReady: this.isReady });
    }

    getKeyPair() {
        return this.keyPair;
    }

    isKeysReady() {
        return this.isReady;
    }

    // Simple event system for state changes
    on(event, callback) {
        if (!this.listeners[event]) {
            this.listeners[event] = [];
        }
        this.listeners[event].push(callback);
    }

    notify(event, data) {
        if (this.listeners[event]) {
            this.listeners[event].forEach(callback => callback(data));
        }
    }
}

// 2. CRYPTO OPERATIONS (Pure functions)
class CryptoOps {
    static async waitForOpenPGP() {
        return new Promise((resolve, reject) => {
            let attempts = 0;
            const maxAttempts = 50;
            function check() {
                attempts++;
                if (typeof openpgp !== 'undefined') {
                    resolve();
                } else if (attempts >= maxAttempts) {
                    reject(new Error('OpenPGP library failed to load'));
                } else {
                    setTimeout(check, 100);
                }
            }
            check();
        });
    }

    static async generateKeyPair(name, email, passphrase) {
        const keyPair = await openpgp.generateKey({
            userIDs: [{ name, email }],
            passphrase,
            curve: 'ed25519',
            format: 'armored'
        });
        return {
            publicKey: keyPair.publicKey,
            privateKey: keyPair.privateKey
        };
    }

    static async signMessage(message, privateKeyArmored, passphrase) {
        let privateKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
        
        if (!privateKeyObj.isDecrypted()) {
            privateKeyObj = await openpgp.decryptKey({
                privateKey: privateKeyObj,
                passphrase
            });
        }

        const messageObj = await openpgp.createMessage({ text: message });
        
        return await openpgp.sign({
            message: messageObj,
            signingKeys: privateKeyObj,
            detached: false,
            format: 'armored'
        });
    }

    static async verifyMessage(signedMessage, publicKeyArmored) {
        const signedMessageObj = await openpgp.readMessage({ armoredMessage: signedMessage });
        const publicKeyObj = await openpgp.readKey({ armoredKey: publicKeyArmored });

        const verificationResult = await openpgp.verify({
            message: signedMessageObj,
            verificationKeys: publicKeyObj,
            format: 'utf8'
        });

        const { data: originalMessage, signatures } = verificationResult;
        
        let isValid = false;
        const verificationDetails = [];
        
        for (const signature of signatures) {
            try {
                const signatureResult = await signature.verified;
                verificationDetails.push({
                    valid: signatureResult === true,
                    keyID: signature.keyID ? signature.keyID.toHex() : 'Unknown'
                });
                
                if (signatureResult === true) {
                    isValid = true;
                }
            } catch (error) {
                verificationDetails.push({
                    valid: false,
                    keyID: signature.keyID ? signature.keyID.toHex() : 'Unknown',
                    error: error.message
                });
            }
        }

        return { originalMessage, isValid, verificationDetails };
    }

    static async encryptMessage(message, publicKeyArmored) {
        const publicKeyObj = await openpgp.readKey({ armoredKey: publicKeyArmored });
        const messageObj = await openpgp.createMessage({ text: message });

        return await openpgp.encrypt({
            message: messageObj,
            encryptionKeys: publicKeyObj,
            format: 'armored'
        });
    }

    static async decryptMessage(encryptedMessage, privateKeyArmored, passphrase) {
        let privateKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
        
        if (!privateKeyObj.isDecrypted()) {
            privateKeyObj = await openpgp.decryptKey({
                privateKey: privateKeyObj,
                passphrase
            });
        }

        const encryptedMessageObj = await openpgp.readMessage({ armoredMessage: encryptedMessage });

        const { data: decryptedMessage } = await openpgp.decrypt({
            message: encryptedMessageObj,
            decryptionKeys: privateKeyObj,
            format: 'utf8'
        });

        return decryptedMessage;
    }

    static sanitizeKey(keyText) {
        return keyText
            .trim()
            .replace(/\r\n/g, '\n')
            .replace(/[\u200B-\u200D\uFEFF]/g, '');
    }
}

// 3. UI OPERATIONS (Separated from business logic)
class UIManager {
    static updateStatus(elementId, status, text) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = text;
            element.className = `status ${status}`;
        }
    }

    static showOutput(elementId, content, type = 'success') {
        const element = document.getElementById(elementId);
        if (element) {
            element.style.display = 'block';
            element.className = `output ${type}`;
            element.innerHTML = content;
        }
    }

    static hideOutput(elementId) {
        const element = document.getElementById(elementId);
        if (element) {
            element.style.display = 'none';
        }
    }

    static setButtonState(elementId, disabled, text) {
        const button = document.getElementById(elementId);
        if (button) {
            button.disabled = disabled;
            if (text) button.textContent = text;
        }
    }

    static setLoadingState(elementId, isLoading, loadingText, normalText) {
        const button = document.getElementById(elementId);
        if (button) {
            button.disabled = isLoading;
            button.innerHTML = isLoading 
                ? `<span class="loading"></span> ${loadingText}`
                : normalText;
        }
    }

    static toggleSection(sectionId) {
        const section = document.getElementById(sectionId);
        if (section) {
            section.classList.toggle('active');
        }
    }

    static addCopyButton(outputElement, textToCopy, buttonText = 'Copy') {
        // Remove existing copy buttons
        const existingButtons = outputElement.querySelectorAll('.copy-btn');
        existingButtons.forEach(btn => btn.remove());

        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn copy-btn';
        copyBtn.textContent = buttonText;
        copyBtn.onclick = () => UIManager.copyToClipboard(textToCopy, copyBtn);
        outputElement.appendChild(copyBtn);
    }

    static async copyToClipboard(text, buttonElement) {
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
            } else {
                // Fallback for older browsers
                const textArea = document.createElement("textarea");
                textArea.value = text;
                textArea.style.position = "fixed";
                textArea.style.top = "0";
                textArea.style.left = "0";
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }
            
            const originalText = buttonElement.textContent;
            buttonElement.textContent = '✅ Copied!';
            setTimeout(() => {
                buttonElement.textContent = originalText;
            }, 2000);
        } catch (err) {
            console.error('Copy failed:', err);
        }
    }

    static getValue(elementId) {
        const element = document.getElementById(elementId);
        return element ? element.value.trim() : '';
    }

    static setValue(elementId, value) {
        const element = document.getElementById(elementId);
        if (element) {
            element.value = value;
        }
    }

    static clearValue(elementId) {
        const element = document.getElementById(elementId);
        if (element) {
            element.value = '';
        }
    }

    static showError(elementId, message) {
        this.showOutput(elementId, `❌ Error: ${message}`, 'error');
    }

    static showSuccess(elementId, message) {
        this.showOutput(elementId, `✅ ${message}`, 'success');
    }
}

// 4. FILE OPERATIONS
class FileManager {
    static saveKeyPair(keyPair) {
        const keyData = {
            publicKey: keyPair.publicKey,
            privateKey: keyPair.privateKey,
            timestamp: new Date().toISOString(),
            version: '1.0'
        };

        const dataStr = JSON.stringify(keyData, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        
        const link = document.createElement('a');
        link.href = URL.createObjectURL(dataBlob);
        link.download = 'pgp-keypair.json';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(link.href);
    }

    static loadKeyPair(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = function(e) {
                try {
                    const keyData = JSON.parse(e.target.result);
                    
                    if (!keyData.publicKey || !keyData.privateKey) {
                        throw new Error('Invalid key file format');
                    }

                    resolve({
                        publicKey: keyData.publicKey,
                        privateKey: keyData.privateKey,
                        timestamp: keyData.timestamp
                    });
                } catch (error) {
                    reject(error);
                }
            };
            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
    }
}

// 5. APPLICATION CONTROLLER
class PGPApp {
    constructor() {
        this.state = new AppState();
        this.isVerifyModeActive = false;
        this.isDecryptModeActive = false;
        this.useCustomKey = false;
        this.init();
    }

    async init() {
        try {
            await CryptoOps.waitForOpenPGP();
            this.setupEventListeners();
            this.setupStateListeners();
            this.initializeUI();
            console.log('PGP App initialized successfully');
        } catch (error) {
            console.error('Failed to initialize PGP App:', error);
            alert('Failed to load OpenPGP library');
        }
    }

    initializeUI() {
        // Set initial states
        UIManager.updateStatus('keyStatus', 'pending', 'No Keys');
        UIManager.updateStatus('signStatus', 'pending', 'Keys Required');
        UIManager.updateStatus('cryptStatus', 'pending', 'Keys Required');
        
        // Hide toggle sections initially
        document.getElementById('verifySection').style.display = 'none';
        document.getElementById('decryptSection').style.display = 'none';
        document.getElementById('customKeySection').style.display = 'none';
    }

    setupStateListeners() {
        this.state.on('keysChanged', (data) => {
            this.updateUIForKeyState(data.isReady);
        });
    }

    updateUIForKeyState(isReady) {
        const status = isReady ? 'ready' : 'pending';
        const text = isReady ? 'Ready' : 'Keys Required';

        UIManager.updateStatus('keyStatus', isReady ? 'ready' : 'pending', isReady ? 'Ready' : 'No Keys');
        UIManager.updateStatus('signStatus', status, text);
        UIManager.updateStatus('cryptStatus', status, text);

        // Enable/disable buttons
        const buttonsRequiringKeys = ['signBtn', 'verifyBtn', 'encryptBtn', 'decryptBtn', 'saveBtn'];
        buttonsRequiringKeys.forEach(id => {
            UIManager.setButtonState(id, !isReady);
        });
    }

    setupEventListeners() {
        // Key Management
        document.getElementById('generateBtn').addEventListener('click', () => this.generateKeys());
        document.getElementById('saveBtn').addEventListener('click', () => this.saveKeys());
        document.getElementById('loadBtn').addEventListener('click', () => this.loadKeys());
        document.getElementById('keyFile').addEventListener('change', (e) => this.handleFileLoad(e));

        // Sign & Verify
        document.getElementById('signBtn').addEventListener('click', () => this.signMessage());
        document.getElementById('verifyBtn').addEventListener('click', () => this.verifyMessage());
        document.getElementById('verifyToggle').addEventListener('click', () => this.toggleVerifyMode());
        document.getElementById('useCustomKey').addEventListener('click', () => this.toggleCustomKey());

        // Encrypt & Decrypt
        document.getElementById('encryptBtn').addEventListener('click', () => this.encryptMessage());
        document.getElementById('decryptBtn').addEventListener('click', () => this.decryptMessage());
        document.getElementById('decryptToggle').addEventListener('click', () => this.toggleDecryptMode());
    }

    async generateKeys() {
        try {
            UIManager.setLoadingState('generateBtn', true, 'Generating...', 'Generate Key Pair');
            UIManager.hideOutput('keyOutput');

            const name = UIManager.getValue('userName');
            const email = UIManager.getValue('userEmail');
            const passphrase = UIManager.getValue('passphrase');

            if (!name || !email || !passphrase) {
                throw new Error('Please fill in all fields');
            }

            const keyPair = await CryptoOps.generateKeyPair(name, email, passphrase);
            this.state.setKeyPair(keyPair);

            const outputContent = `✅ Key pair generated successfully!<br><br>
                <strong>Public Key:</strong><pre>${keyPair.publicKey}</pre>
                <strong>Private Key:</strong><pre>${keyPair.privateKey}</pre>`;

            UIManager.showOutput('keyOutput', outputContent, 'success');
            
            const outputElement = document.getElementById('keyOutput');
            UIManager.addCopyButton(outputElement, keyPair.publicKey, 'Copy Public Key');

        } catch (error) {
            UIManager.showError('keyOutput', error.message);
        } finally {
            UIManager.setLoadingState('generateBtn', false, '', 'Generate Key Pair');
        }
    }

    saveKeys() {
        try {
            const keyPair = this.state.getKeyPair();
            if (!keyPair) {
                throw new Error('No keys to save');
            }
            FileManager.saveKeyPair(keyPair);
        } catch (error) {
            UIManager.showError('keyOutput', error.message);
        }
    }

    loadKeys() {
        document.getElementById('keyFile').click();
    }

    async handleFileLoad(event) {
        const file = event.target.files[0];
        if (!file) return;

        try {
            const keyData = await FileManager.loadKeyPair(file);
            this.state.setKeyPair(keyData);

            // Clear passphrase field for security
            UIManager.clearValue('passphrase');
            document.getElementById('passphrase').placeholder = 'Enter passphrase for loaded keys';

            const outputContent = `✅ Key pair loaded successfully!<br><br>
                <strong>Loaded from:</strong> ${file.name}<br>
                <strong>Timestamp:</strong> ${keyData.timestamp || 'Unknown'}<br>
                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 4px;">
                    <strong>⚠️ Important:</strong> Please enter the correct passphrase for these loaded keys.
                </div>
                <strong>Public Key:</strong><pre>${keyData.publicKey}</pre>
                <strong>Private Key:</strong><pre>${keyData.privateKey}</pre>`;

            UIManager.showOutput('keyOutput', outputContent, 'success');
            
            const outputElement = document.getElementById('keyOutput');
            UIManager.addCopyButton(outputElement, keyData.publicKey, 'Copy Public Key');

        } catch (error) {
            UIManager.showError('keyOutput', `Key loading failed: ${error.message}`);
        } finally {
            // Clear file input
            event.target.value = '';
        }
    }

    async signMessage() {
        try {
            UIManager.setLoadingState('signBtn', true, 'Signing...', 'Sign Message');
            UIManager.hideOutput('signOutput');

            const message = UIManager.getValue('signMessage');
            const passphrase = UIManager.getValue('passphrase');

            if (!message) throw new Error('Please enter a message to sign');
            if (!passphrase) throw new Error('Passphrase required');

            const keyPair = this.state.getKeyPair();
            const signedMessage = await CryptoOps.signMessage(message, keyPair.privateKey, passphrase);

            const outputContent = `✅ Message signed successfully!<br><br><pre>${signedMessage}</pre>`;
            UIManager.showOutput('signOutput', outputContent, 'success');
            
            const outputElement = document.getElementById('signOutput');
            UIManager.addCopyButton(outputElement, signedMessage, 'Copy Signed Message');

        } catch (error) {
            let errorMessage = error.message;
            if (error.message.includes('Incorrect key passphrase')) {
                errorMessage += '\n\n💡 If you loaded keys from a file, make sure you entered the correct passphrase for those keys.';
            }
            UIManager.showError('signOutput', errorMessage);
        } finally {
            UIManager.setLoadingState('signBtn', false, '', 'Sign Message');
        }
    }

    async verifyMessage() {
        try {
            UIManager.setLoadingState('verifyBtn', true, 'Verifying...', 'Verify Message');
            UIManager.hideOutput('signOutput');

            const signedMessage = UIManager.getValue('verifyMessage');
            if (!signedMessage) throw new Error('Please enter a signed message');

            let publicKey;
            if (this.useCustomKey) {
                publicKey = CryptoOps.sanitizeKey(UIManager.getValue('customPublicKey'));
                if (!publicKey) throw new Error('Please enter a custom public key');
            } else {
                const keyPair = this.state.getKeyPair();
                publicKey = keyPair.publicKey;
            }

            const result = await CryptoOps.verifyMessage(signedMessage, publicKey);

            if (result.isValid) {
                const outputContent = `✅ Message verification successful!<br><br>
                    <strong>Signature Status:</strong> Valid<br>
                    <strong>Verification Details:</strong> ${result.verificationDetails.length} signature(s) checked, ${result.verificationDetails.filter(d => d.valid).length} valid<br>
                    <strong>Original Message:</strong><pre>${result.originalMessage}</pre>`;
                UIManager.showOutput('signOutput', outputContent, 'success');
                
                const outputElement = document.getElementById('signOutput');
                UIManager.addCopyButton(outputElement, result.originalMessage, 'Copy Original Message');
            } else {
                let errorDetails = '';
                if (result.verificationDetails.length > 0) {
                    errorDetails = '<br><br><strong>Verification Details:</strong><br>';
                    result.verificationDetails.forEach((detail, index) => {
                        errorDetails += `Signature ${index + 1}: ${detail.valid ? 'Valid' : 'Invalid'} (Key ID: ${detail.keyID})`;
                        if (detail.error) {
                            errorDetails += ` - Error: ${detail.error}`;
                        }
                        errorDetails += '<br>';
                    });
                }
                
                const outputContent = `❌ Message verification failed!<br><br>
                    <strong>Reason:</strong> The signature is invalid, the message has been tampered with, or you're using the wrong public key.${errorDetails}`;
                UIManager.showOutput('signOutput', outputContent, 'error');
            }

        } catch (error) {
            let errorMessage = `Verification failed: ${error.message}`;
            if (error.message.includes('Error reading')) {
                errorMessage += '<br><br>💡 Possible issues:<br>• The signed message format is invalid<br>• The public key format is invalid<br>• Copy-paste errors (check for missing characters)';
            }
            UIManager.showOutput('signOutput', errorMessage, 'error');
        } finally {
            UIManager.setLoadingState('verifyBtn', false, '', 'Verify Message');
        }
    }

    async encryptMessage() {
        try {
            UIManager.setLoadingState('encryptBtn', true, 'Encrypting...', 'Encrypt Message');
            UIManager.hideOutput('cryptOutput');

            const message = UIManager.getValue('cryptMessage');
            if (!message) throw new Error('Please enter a message to encrypt');

            const keyPair = this.state.getKeyPair();
            const encryptedMessage = await CryptoOps.encryptMessage(message, keyPair.publicKey);

            const outputContent = `✅ Message encrypted successfully!<br><br><pre>${encryptedMessage}</pre>`;
            UIManager.showOutput('cryptOutput', outputContent, 'success');
            
            const outputElement = document.getElementById('cryptOutput');
            UIManager.addCopyButton(outputElement, encryptedMessage, 'Copy Encrypted Message');

        } catch (error) {
            UIManager.showError('cryptOutput', error.message);
        } finally {
            UIManager.setLoadingState('encryptBtn', false, '', 'Encrypt Message');
        }
    }

    async decryptMessage() {
        try {
            UIManager.setLoadingState('decryptBtn', true, 'Decrypting...', 'Decrypt Message');
            UIManager.hideOutput('cryptOutput');

            const encryptedMessage = UIManager.getValue('decryptMessage');
            const passphrase = UIManager.getValue('passphrase');

            if (!encryptedMessage) throw new Error('Please enter an encrypted message');
            if (!passphrase) throw new Error('Passphrase required');

            const keyPair = this.state.getKeyPair();
            const decryptedMessage = await CryptoOps.decryptMessage(encryptedMessage, keyPair.privateKey, passphrase);

            const outputContent = `✅ Message decrypted successfully!<br><br>
                <strong>Decrypted Message:</strong><pre>${decryptedMessage}</pre>`;
            UIManager.showOutput('cryptOutput', outputContent, 'success');
            
            const outputElement = document.getElementById('cryptOutput');
            UIManager.addCopyButton(outputElement, decryptedMessage, 'Copy Decrypted Message');

        } catch (error) {
            let errorMessage = `Decryption failed: ${error.message}`;
            if (error.message.includes('Incorrect key passphrase')) {
                errorMessage += '\n\n💡 If you loaded keys from a file, ensure you entered the correct passphrase for those loaded keys.';
            }
            UIManager.showError('cryptOutput', errorMessage);
        } finally {
            UIManager.setLoadingState('decryptBtn', false, '', 'Decrypt Message');
        }
    }

    toggleVerifyMode() {
        this.isVerifyModeActive = !this.isVerifyModeActive;
        const verifySection = document.getElementById('verifySection');
        const toggleButton = document.getElementById('verifyToggle');
        
        if (this.isVerifyModeActive) {
            verifySection.style.display = 'block';
            toggleButton.textContent = 'Switch to Sign Mode';
        } else {
            verifySection.style.display = 'none';
            toggleButton.textContent = 'Switch to Verify Mode';
            // Hide custom key section when switching back
            if (this.useCustomKey) {
                this.toggleCustomKey();
            }
        }
    }

    toggleDecryptMode() {
        this.isDecryptModeActive = !this.isDecryptModeActive;
        const decryptSection = document.getElementById('decryptSection');
        const toggleButton = document.getElementById('decryptToggle');
        
        if (this.isDecryptModeActive) {
            decryptSection.style.display = 'block';
            toggleButton.textContent = 'Switch to Encrypt Mode';
        } else {
            decryptSection.style.display = 'none';
            toggleButton.textContent = 'Switch to Decrypt Mode';
        }
    }

    toggleCustomKey() {
        this.useCustomKey = !this.useCustomKey;
        const customKeySection = document.getElementById('customKeySection');
        const toggleButton = document.getElementById('useCustomKey');
        
        if (this.useCustomKey) {
            customKeySection.style.display = 'block';
            toggleButton.textContent = 'Use Generated Public Key';
        } else {
            customKeySection.style.display = 'none';
            toggleButton.textContent = 'Use Custom Public Key';
        }
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.pgpApp = new PGPApp();
});
