import { copyToClipboard } from './utils.js';
import { getKeyPair } from './keyManagement.js';

export function toggleEncryptCustomPublicKey() {
    const container = document.getElementById('encryptCustomPublicKeyContainer');
    const button = document.getElementById('toggleEncryptPublicKeyBtn');
    if (container.style.display === 'none') {
        container.style.display = 'block';
        button.textContent = 'Use Generated Public Key';
    } else {
        container.style.display = 'none';
        button.textContent = 'Use Custom Public Key';
    }
}

export function toggleVerifyCustomPublicKey() {
    const container = document.getElementById('verifyCustomPublicKeyContainer');
    const button = document.getElementById('toggleVerifyPublicKeyBtn');
    if (container.style.display === 'none') {
        container.style.display = 'block';
        button.textContent = 'Use Generated Public Key';
    } else {
        container.style.display = 'none';
        button.textContent = 'Use Custom Public Key';
    }
}

export async function verifyMessage() {
    const verifyBtn = document.getElementById('verifyBtn');
    const verifyOutput = document.getElementById('verifyOutput');

    try {
        verifyBtn.disabled = true;
        verifyBtn.innerHTML = '<span class="loading"></span> Verifying...';
        verifyOutput.style.display = 'none';

        const signedMessageText = document.getElementById('signedMessageToVerify').value.trim();
        let customPublicKey = document.getElementById('verifyCustomPublicKey').value.trim();
        const useCustomKey = document.getElementById('verifyCustomPublicKeyContainer').style.display === 'block';

        if (!signedMessageText) throw new Error('Please enter a signed message to verify');

        let publicKeyToUse = '';

        if (useCustomKey) {
            // Sanitize the custom public key input
            customPublicKey = customPublicKey
                .replace(/\r\n/g, '\n') // Normalize Windows newlines to Unix newlines
                .replace(/[\u200B-\u200D\uFEFF]/g, ''); // Remove zero-width characters

            if (!customPublicKey) throw new Error('Please enter a custom public key or switch to use the generated key.');
            publicKeyToUse = customPublicKey;
        } else {
            const keyPair = getKeyPair();
            if (!keyPair || !keyPair.publicKey) throw new Error('Generated public key not available. Generate keys first or provide a custom key.');
            publicKeyToUse = keyPair.publicKey;
        }

        // Read the signed message
        const signedMessageObj = await openpgp.readMessage({ armoredMessage: signedMessageText });
        
        // Read the public key
        const publicKeyObj = await openpgp.readKey({ armoredKey: publicKeyToUse });

        // Verify the message
        const verificationResult = await openpgp.verify({
            message: signedMessageObj,
            verificationKeys: publicKeyObj,
            format: 'utf8'
        });

        // Extract the original message and verification status
        const { data: originalMessage, signatures } = verificationResult;
        
        // FIXED: Properly check signature validity
        let isValid = false;
        let verificationDetails = [];
        
        // Check each signature properly
        for (const signature of signatures) {
            try {
                // Await the signature verification if it's a Promise
                const signatureResult = await signature.verified;
                
                verificationDetails.push({
                    valid: signatureResult === true,
                    keyID: signature.keyID ? signature.keyID.toHex() : 'Unknown',
                    signature: signature
                });
                
                if (signatureResult === true) {
                    isValid = true;
                }
            } catch (sigError) {
                console.error('Signature verification error:', sigError);
                verificationDetails.push({
                    valid: false,
                    keyID: signature.keyID ? signature.keyID.toHex() : 'Unknown',
                    error: sigError.message || sigError
                });
            }
        }
        
        verifyOutput.style.display = 'block';
        
        if (isValid) {
            verifyOutput.className = 'output success';
            verifyOutput.innerHTML = `✅ Message verification successful!<br><br>
                                     <strong>Signature Status:</strong> Valid<br>
                                     <strong>Verification Details:</strong> ${verificationDetails.length} signature(s) checked, ${verificationDetails.filter(d => d.valid).length} valid<br>
                                     <strong>Original Message:</strong><pre>${originalMessage}</pre>`;

            // Add copy button for the original message
            const existingCopyBtn = verifyOutput.querySelector('.copy-btn');
            if (existingCopyBtn) existingCopyBtn.remove();

            const copyBtn = document.createElement('button');
            copyBtn.className = 'btn copy-btn';
            copyBtn.textContent = 'Copy Original Message';
            copyBtn.onclick = (event) => copyToClipboard(originalMessage, event.target);
            verifyOutput.appendChild(copyBtn);
        } else {
            verifyOutput.className = 'output error';
            
            let errorDetails = '';
            if (verificationDetails.length > 0) {
                errorDetails = '<br><br><strong>Verification Details:</strong><br>';
                verificationDetails.forEach((detail, index) => {
                    errorDetails += `Signature ${index + 1}: ${detail.valid ? 'Valid' : 'Invalid'} (Key ID: ${detail.keyID})`;
                    if (detail.error) {
                        errorDetails += ` - Error: ${detail.error}`;
                    }
                    errorDetails += '<br>';
                });
            }
            
            verifyOutput.innerHTML = `❌ Message verification failed!<br><br>
                                     <strong>Reason:</strong> The signature is invalid, the message has been tampered with, or you're using the wrong public key.${errorDetails}`;
        }

    } catch (error) {
        console.error('Verification error:', error);
        verifyOutput.style.display = 'block';
        verifyOutput.className = 'output error';
        
        let errorMessage = `❌ Verification Error: ${error.message || error}`;
        
        // Add helpful debugging information
        if (error.message && error.message.includes('Error reading')) {
            errorMessage += '<br><br>💡 Possible issues:<br>• The signed message format is invalid<br>• The public key format is invalid<br>• Copy-paste errors (check for missing characters)';
        } else if (error.message && error.message.includes('No signatures')) {
            errorMessage += '<br><br>💡 This message doesn\'t appear to contain any signatures.';
        }
        
        verifyOutput.innerHTML = errorMessage;
    } finally {
        verifyBtn.disabled = false;
        verifyBtn.textContent = 'Verify Message';
    }
}

export async function signMessage() {
    const signBtnNew = document.getElementById('signBtnNew');
    const signOutputNew = document.getElementById('signOutputNew');
    const messageText = document.getElementById('messageToSignNew').value;

    try {
        signBtnNew.disabled = true;
        signBtnNew.innerHTML = '<span class="loading"></span> Signing...';
        signOutputNew.style.display = 'none';

        const localPassphrase = document.getElementById('passphrase').value;
        const keyPair = getKeyPair();

        if (!messageText) throw new Error('Please enter a message to sign');
        if (!keyPair || !keyPair.privateKey) throw new Error('Private key not available. Generate keys first.');
        if (!localPassphrase) throw new Error('Passphrase is required to sign');

        const privateKeyArmored = keyPair.privateKey;
        let privateKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });

        if (!privateKeyObj.isDecrypted()) {
            privateKeyObj = await openpgp.decryptKey({
                privateKey: privateKeyObj,
                passphrase: localPassphrase
            });
        }

        const message = await openpgp.createMessage({ text: messageText });

        const signedMessage = await openpgp.sign({
            message,
            signingKeys: privateKeyObj,
            detached: false,
            format: 'armored'
        });

        signOutputNew.style.display = 'block';
        signOutputNew.className = 'output success';
        signOutputNew.innerHTML = `✅ Message signed successfully!<br><br><pre>${signedMessage}</pre>`;

        const existingCopyBtn = signOutputNew.querySelector('.copy-btn');
        if (existingCopyBtn) existingCopyBtn.remove();

        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn copy-btn';
        copyBtn.textContent = 'Copy Signed Message';
        copyBtn.onclick = (event) => copyToClipboard(signedMessage, event.target);
        signOutputNew.appendChild(copyBtn);

    } catch (error) {
        console.error('Signing error:', error);
        signOutputNew.style.display = 'block';
        signOutputNew.className = 'output error';
        
        let errorMessage = `❌ Signing Error: ${error.message || error}`;
        if (error.message && error.message.includes('Incorrect key passphrase')) {
            errorMessage += `\n\n💡 Troubleshooting:\n- If you loaded keys from a file, make sure you entered the correct passphrase for those keys\n- The passphrase field was cleared when you loaded the keys\n- Try entering the passphrase that was used when the keys were originally generated`;
        }
        
        signOutputNew.textContent = errorMessage;
    } finally {
        signBtnNew.disabled = false;
        signBtnNew.textContent = 'Sign Message';
    }
} 