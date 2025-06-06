 
        // Global state management
        const AppState = {
            currentKeyPair: null,
            isGenerating: false,
            advancedConfig: {
                algorithm: 'ecc',
                keySize: null,
                expiration: 63072000, // 2 years in seconds
                usage: {
                    sign: true,
                    encrypt: true,
                    certify: true
                },
                comment: ''
            }
        };

        // Utility functions
        const Utils = {
            // Validate required form fields
            validateRequiredFields() {
                const name = document.getElementById('userName').value.trim();
                const email = document.getElementById('userEmail').value.trim();
                const passphrase = document.getElementById('passphrase').value;

                if (!name) {
                    throw new Error('Name is required');
                }
                if (!email) {
                    throw new Error('Email is required');
                }
                if (!this.isValidEmail(email)) {
                    throw new Error('Please enter a valid email address');
                }
                if (!passphrase) {
                    throw new Error('Passphrase is required');
                }
                if (passphrase.length < 8) {
                    throw new Error('Passphrase must be at least 8 characters long');
                }

                return { name, email, passphrase };
            },

            // Email validation
            isValidEmail(email) {
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                return emailRegex.test(email);
            },

            // Format fingerprint with spaces
            formatFingerprint(fingerprint) {
                return fingerprint.replace(/(.{4})/g, '$1 ').trim().toUpperCase();
            },

            // Format date
            formatDate(date) {
                return new Date(date).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                });
            },

            // Show loading state on button
            setButtonLoading(button, isLoading, originalText = null) {
                if (isLoading) {
                    button.dataset.originalText = button.textContent;
                    button.textContent = 'Generating...';
                    button.classList.add('loading');
                    button.disabled = true;
                } else {
                    button.textContent = originalText || button.dataset.originalText || 'Generate Key Pair';
                    button.classList.remove('loading');
                    button.disabled = false;
                }
            },

            // Update status indicator
            updateStatus(status, text) {
                const statusEl = document.getElementById('keyStatus');
                statusEl.className = `status ${status}`;
                statusEl.textContent = text;
            },

            // Show output with styling
            showOutput(content, type = 'success') {
                const output = document.getElementById('keyOutput');
                output.className = `output ${type}`;
                output.textContent = content;
                output.style.display = 'block';
            },

            // Copy text to clipboard
            async copyToClipboard(text) {
                try {
                    await navigator.clipboard.writeText(text);
                    return true;
                } catch (err) {
                    console.error('Failed to copy to clipboard:', err);
                    return false;
                }
            }
        };

        // OpenPGP operations
        const PGPOperations = {
            // Generate key pair with advanced options
            async generateKeyPair(userInfo, config) {
                try {
                    // Build user ID
                    const userId = config.comment 
                        ? `${userInfo.name} (${config.comment}) <${userInfo.email}>`
                        : `${userInfo.name} <${userInfo.email}>`;

                    // Prepare key generation options
                    const keyOptions = {
                        type: config.algorithm === 'ecc' ? 'ecc' : 'rsa',
                        userIDs: [{ name: userInfo.name, email: userInfo.email, comment: config.comment }],
                        passphrase: userInfo.passphrase,
                        format: 'armored'
                    };

                    // Set algorithm-specific options
                    if (config.algorithm === 'ecc') {
                        keyOptions.curve = 'curve25519';
                    } else {
                        keyOptions.rsaBits = config.keySize;
                    }

                    // Set expiration
                    if (config.expiration > 0) {
                        keyOptions.keyExpirationTime = config.expiration;
                    }

                    console.log('Generating key with options:', keyOptions);

                    // Generate the key pair
                    const { privateKey, publicKey } = await openpgp.generateKey(keyOptions);

                    // Parse keys for metadata
                    const privateKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKey });
                    const publicKeyObj = await openpgp.readKey({ armoredKey: publicKey });

                    return {
                        privateKey,
                        publicKey,
                        privateKeyObj,
                        publicKeyObj,
                        metadata: {
                            keyId: publicKeyObj.getKeyIDs()[0].toHex().toUpperCase(),
                            fingerprint: publicKeyObj.getFingerprint(),
                            algorithm: config.algorithm.toUpperCase(),
                            created: publicKeyObj.getCreationTime(),
                            userIds: publicKeyObj.getUserIDs()
                        }
                    };
                } catch (error) {
                    console.error('Key generation failed:', error);
                    throw new Error(`Key generation failed: ${error.message}`);
                }
            },

            // Create downloadable key backup
            createKeyBackup(keyPair, userInfo, config) {
                const backup = {
                    version: '1.0',
                    created: new Date().toISOString(),
                    userInfo: {
                        name: userInfo.name,
                        email: userInfo.email
                    },
                    config: {
                        algorithm: config.algorithm,
                        keySize: config.keySize,
                        comment: config.comment
                    },
                    keys: {
                        private: keyPair.privateKey,
                        public: keyPair.publicKey
                    },
                    metadata: keyPair.metadata
                };

                return JSON.stringify(backup, null, 2);
            }
        };

        // UI Management
        const UIManager = {
            // Update key information display
            updateKeyInfo(metadata) {
                document.getElementById('keyId').textContent = metadata.keyId;
                document.getElementById('keyFingerprint').textContent = Utils.formatFingerprint(metadata.fingerprint);
                document.getElementById('keyAlgorithm').textContent = metadata.algorithm;
                document.getElementById('keyCreated').textContent = Utils.formatDate(metadata.created);
                document.getElementById('keyInfo').style.display = 'block';
            },

            // Show/hide advanced options modal
            showAdvancedModal() {
                const modal = document.getElementById('advancedOptionsModal');
                const currentSettings = document.getElementById('currentSettingsDisplay');
                
                currentSettings.style.display = 'block';
                AdvancedOptions.updateCurrentSettingsDisplay();
                AdvancedOptions.loadCurrentSettingsIntoModal();
                
                modal.classList.add('active');
                document.body.style.overflow = 'hidden';
            },

            hideAdvancedModal() {
                const modal = document.getElementById('advancedOptionsModal');
                const checkbox = document.getElementById('enableAdvancedOptions');
                
                modal.classList.remove('active');
                document.body.style.overflow = '';
                checkbox.checked = false;
            },

            // Enable/disable key actions
            enableKeyActions(enabled) {
                document.getElementById('saveKeyBtn').disabled = !enabled;
            }
        };

        // Advanced Options Management
        const AdvancedOptions = {
            // Update the current settings display
            updateCurrentSettingsDisplay() {
                const config = AppState.advancedConfig;
                const algorithmSpan = document.getElementById('currentAlgorithm');
                const expirationSpan = document.getElementById('currentExpiration');
                const usageSpan = document.getElementById('currentUsage');

                // Update algorithm display
                switch(config.algorithm) {
                    case 'ecc':
                        algorithmSpan.textContent = 'ECC (Curve25519)';
                        break;
                    case 'rsa2048':
                        algorithmSpan.textContent = 'RSA 2048-bit';
                        break;
                    case 'rsa4096':
                        algorithmSpan.textContent = 'RSA 4096-bit';
                        break;
                    default:
                        algorithmSpan.textContent = 'ECC (Curve25519)';
                }

                // Update expiration display
                const expiration = parseInt(config.expiration);
                if (expiration === 0) {
                    expirationSpan.textContent = 'Never expires';
                } else {
                    const years = Math.round(expiration / 31536000);
                    expirationSpan.textContent = `${years} year${years !== 1 ? 's' : ''}`;
                }

                // Update usage display
                const usages = [];
                if (config.usage.sign) usages.push('Sign');
                if (config.usage.encrypt) usages.push('Encrypt');
                if (config.usage.certify) usages.push('Certify');
                usageSpan.textContent = usages.join(', ') || 'None selected';
            },

            // Load current settings into modal
            loadCurrentSettingsIntoModal() {
                const config = AppState.advancedConfig;
                
                document.querySelector(`input[name="algorithm"][value="${config.algorithm}"]`).checked = true;
                document.getElementById('keyExpiration').value = config.expiration.toString();
                document.getElementById('usageSign').checked = config.usage.sign;
                document.getElementById('usageEncrypt').checked = config.usage.encrypt;
                document.getElementById('usageCertify').checked = config.usage.certify;
                document.getElementById('keyComment').value = config.comment;
            },

            // Apply settings from modal
            applyAdvancedSettings() {
                const config = AppState.advancedConfig;
                
                // Get algorithm
                const selectedAlgorithm = document.querySelector('input[name="algorithm"]:checked').value;
                config.algorithm = selectedAlgorithm;

                // Get key size based on algorithm
                switch(selectedAlgorithm) {
                    case 'rsa2048':
                        config.keySize = 2048;
                        break;
                    case 'rsa4096':
                        config.keySize = 4096;
                        break;
                    default:
                        config.keySize = null; // ECC doesn't need key size
                }

                // Get expiration
                config.expiration = parseInt(document.getElementById('keyExpiration').value);

                // Get usage
                config.usage = {
                    sign: document.getElementById('usageSign').checked,
                    encrypt: document.getElementById('usageEncrypt').checked,
                    certify: document.getElementById('usageCertify').checked
                };

                // Get comment
                config.comment = document.getElementById('keyComment').value.trim();

                // Validate at least one usage is selected
                if (!config.usage.sign && !config.usage.encrypt && !config.usage.certify) {
                    alert('Please select at least one key usage option.');
                    return false;
                }

                // Update the display
                this.updateCurrentSettingsDisplay();

                // Hide the modal
                UIManager.hideAdvancedModal();

                console.log('Applied advanced settings:', config);
                return true;
            }
        };

        // File Operations
        const FileOperations = {
            // Save key pair to file
            saveKeyPair() {
                if (!AppState.currentKeyPair) {
                    alert('No key pair to save. Please generate a key pair first.');
                    return;
                }

                try {
                    const userInfo = Utils.validateRequiredFields();
                    const backup = PGPOperations.createKeyBackup(
                        AppState.currentKeyPair, 
                        userInfo, 
                        AppState.advancedConfig
                    );

                    const blob = new Blob([backup], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    
                    a.href = url;
                    a.download = `pgp-keys-${userInfo.name.replace(/\s+/g, '-').toLowerCase()}-${Date.now()}.json`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);

                    Utils.showOutput('Key pair saved successfully!', 'success');
                } catch (error) {
                    console.error('Save failed:', error);
                    Utils.showOutput(`Save failed: ${error.message}`, 'error');
                }
            },

            // Load key pair from file
            loadKeyPair(file) {
                return new Promise((resolve, reject) => {
                    const reader = new FileReader();
                    
                    reader.onload = async (e) => {
                        try {
                            const backup = JSON.parse(e.target.result);
                            
                            // Validate backup structure
                            if (!backup.keys || !backup.keys.private || !backup.keys.public) {
                                throw new Error('Invalid key file format');
                            }

                            // Parse keys
                            const privateKeyObj = await openpgp.readPrivateKey({ armoredKey: backup.keys.private });
                            const publicKeyObj = await openpgp.readKey({ armoredKey: backup.keys.public });

                            const keyPair = {
                                privateKey: backup.keys.private,
                                publicKey: backup.keys.public,
                                privateKeyObj,
                                publicKeyObj,
                                metadata: backup.metadata || {
                                    keyId: publicKeyObj.getKeyIDs()[0].toHex().toUpperCase(),
                                    fingerprint: publicKeyObj.getFingerprint(),
                                    algorithm: 'LOADED',
                                    created: publicKeyObj.getCreationTime(),
                                    userIds: publicKeyObj.getUserIDs()
                                }
                            };

                            // Update UI with loaded key info
                            if (backup.userInfo) {
                                document.getElementById('userName').value = backup.userInfo.name || '';
                                document.getElementById('userEmail').value = backup.userInfo.email || '';
                            }

                            resolve(keyPair);
                        } catch (error) {
                            reject(new Error(`Failed to load key file: ${error.message}`));
                        }
                    };

                    reader.onerror = () => reject(new Error('Failed to read file'));
                    reader.readAsText(file);
                });
            }
        };

        // Main Application Logic
        const App = {
            // Initialize the application
            init() {
                this.setupEventListeners();
                AdvancedOptions.updateCurrentSettingsDisplay();
                Utils.updateStatus('pending', 'No Keys');
                console.log('OpenPGP.js Demo initialized');
            },

            // Setup all event listeners
            setupEventListeners() {
                // Generate button
                document.getElementById('generateBtn').addEventListener('click', this.handleGenerateClick.bind(this));

                // Advanced options
                document.getElementById('enableAdvancedOptions').addEventListener('change', this.handleAdvancedOptionsToggle.bind(this));
                document.getElementById('modalClose').addEventListener('click', UIManager.hideAdvancedModal);
                document.getElementById('modalCancel').addEventListener('click', UIManager.hideAdvancedModal);
                document.getElementById('modalApply').addEventListener('click', this.handleAdvancedOptionsApply.bind(this));

                // File operations
                document.getElementById('saveKeyBtn').addEventListener('click', FileOperations.saveKeyPair);
                document.getElementById('loadKeyBtn').addEventListener('click', () => {
                    document.getElementById('keyFileInput').click();
                });
                document.getElementById('keyFileInput').addEventListener('change', this.handleFileLoad.bind(this));

                // Modal overlay click
                document.getElementById('advancedOptionsModal').addEventListener('click', (e) => {
                    if (e.target.id === 'advancedOptionsModal') {
                        UIManager.hideAdvancedModal();
                    }
                });

                // Escape key to close modal
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape' && document.getElementById('advancedOptionsModal').classList.contains('active')) {
                        UIManager.hideAdvancedModal();
                    }
                });
            },

            // Handle generate key button click
            async handleGenerateClick() {
                if (AppState.isGenerating) return;

                const generateBtn = document.getElementById('generateBtn');
                
                try {
                    AppState.isGenerating = true;
                    Utils.setButtonLoading(generateBtn, true);
                    Utils.updateStatus('pending', 'Generating...');

                    // Validate input
                    const userInfo = Utils.validateRequiredFields();

                    // Generate key pair
                    console.log('Starting key generation...');
                    const keyPair = await PGPOperations.generateKeyPair(userInfo, AppState.advancedConfig);
                    
                    // Store the key pair
                    AppState.currentKeyPair = keyPair;

                    // Update UI
                    Utils.updateStatus('ready', 'Keys Ready');
                    UIManager.updateKeyInfo(keyPair.metadata);
                    UIManager.enableKeyActions(true);

                    // Show success message
                    const message = `Key pair generated successfully!\n\nKey ID: ${keyPair.metadata.keyId}\nFingerprint: ${Utils.formatFingerprint(keyPair.metadata.fingerprint)}`;
                    Utils.showOutput(message, 'success');

                    console.log('Key generation completed successfully');

                } catch (error) {
                    console.error('Key generation failed:', error);
                    
                    // Show error message with troubleshooting tips
                    let errorMessage = `Key generation failed: ${error.message}\n\nTroubleshooting tips:\n`;
                    errorMessage += '• Check that all required fields are filled\n';
                    errorMessage += '• Ensure your passphrase is at least 8 characters\n';
                    errorMessage += '• Try refreshing the page if the error persists\n';
                    errorMessage += '• Check browser console for detailed error information';
                    
                    Utils.showOutput(errorMessage, 'error');
                    Utils.updateStatus('error', 'Generation Failed');
                } finally {
                    AppState.isGenerating = false;
                    Utils.setButtonLoading(generateBtn, false);
                }
            },

            // Handle advanced options toggle
            handleAdvancedOptionsToggle(e) {
                if (e.target.checked) {
                    UIManager.showAdvancedModal();
                } else {
                    UIManager.hideAdvancedModal();
                }
            },

            // Handle advanced options apply
            handleAdvancedOptionsApply() {
                if (AdvancedOptions.applyAdvancedSettings()) {
                    console.log('Advanced settings applied successfully');
                }
            },

            // Handle file load
            async handleFileLoad(e) {
                const file = e.target.files[0];
                if (!file) return;

                try {
                    Utils.updateStatus('pending', 'Loading...');
                    
                    const keyPair = await FileOperations.loadKeyPair(file);
                    AppState.currentKeyPair = keyPair;

                    // Update UI
                    Utils.updateStatus('ready', 'Keys Loaded');
                    UIManager.updateKeyInfo(keyPair.metadata);
                    UIManager.enableKeyActions(true);

                    Utils.showOutput('Key pair loaded successfully!', 'success');
                    console.log('Key pair loaded from file');

                } catch (error) {
                    console.error('File load failed:', error);
                    Utils.showOutput(`Load failed: ${error.message}`, 'error');
                    Utils.updateStatus('error', 'Load Failed');
                } finally {
                    // Clear the file input
                    e.target.value = '';
                }
            }
        };

        // Initialize the application when DOM is ready
        document.addEventListener('DOMContentLoaded', () => {
            // Check if OpenPGP.js is loaded
            if (typeof openpgp === 'undefined') {
                console.error('OpenPGP.js library not loaded');
                Utils.showOutput('Error: OpenPGP.js library not loaded. Please refresh the page.', 'error');
                return;
            }

            console.log('OpenPGP.js version:', openpgp.version || 'Unknown');
            App.init();
        });

        // Global error handling
        window.addEventListener('error', (e) => {
            console.error('Global error:', e.error);
            if (AppState.isGenerating) {
                AppState.isGenerating = false;
                Utils.setButtonLoading(document.getElementById('generateBtn'), false);
                Utils.updateStatus('error', 'Error Occurred');
            }
        });

        // Expose some functions for debugging
        window.OpenPGPDemo = {
            state: AppState,
            utils: Utils,
            pgp: PGPOperations
        };
  
