import { waitForOpenPGP } from './utils.js';

// Key Management Module
// Exports: generateKeyPair, saveKeyPair, loadKeyPair, handleKeyFileLoad

export async function generateKeyPair() {
    const generateBtn = document.getElementById('generateBtn');
    const keyOutput = document.getElementById('keyOutput');
    const keyStatus = document.getElementById('keyStatus');

    try {
        await waitForOpenPGP();
        generateBtn.disabled = true;
        generateBtn.innerHTML = '<span class="loading"></span> Generating...';
        keyStatus.textContent = 'Generating...';
        keyStatus.className = 'status pending';

        const name = document.getElementById('userName').value;
        const email = document.getElementById('userEmail').value;
        const localPassphrase = document.getElementById('passphrase').value;

        if (!name || !email || !localPassphrase) {
            throw new Error('Please fill in all fields for key generation');
        }

        const generatedKeyPair = await openpgp.generateKey({
            userIDs: [{ name, email }],
            passphrase: localPassphrase,
            curve: 'ed25519',
            format: 'armored'
        });
        keyPair = {
            publicKey: generatedKeyPair.publicKey,
            privateKey: generatedKeyPair.privateKey
        };

        keyOutput.style.display = 'block';
        keyOutput.className = 'output success';
        keyOutput.innerHTML = `✅ Key pair generated successfully!<br><br>
                                <strong>Public Key:</strong><pre>${keyPair.publicKey}</pre>
                                <strong>Private Key:</strong><pre>${keyPair.privateKey}</pre>`;

        keyStatus.textContent = 'Ready';
        keyStatus.className = 'status ready';

        // Enable all buttons that need keys
        document.getElementById('signBtn').disabled = false;
        document.getElementById('signBtnNew').disabled = false; // Fixed: Enable the new sign button
        document.getElementById('encryptBtn').disabled = false;
        document.getElementById('decryptBtn').disabled = false;
        document.getElementById('verifyBtn').disabled = false; // Fixed: Enable verify button
        document.getElementById('saveKeyBtn').disabled = false;
        
        // Update all status indicators
        ['signVerifyStatus', 'encryptStatus', 'decryptStatus'].forEach(id => {
            const el = document.getElementById(id);
            el.textContent = 'Ready';
            el.className = 'status ready';
        });

        const existingCopyBtns = keyOutput.querySelectorAll('.copy-btn');
        existingCopyBtns.forEach(btn => btn.remove());

        const copyPubBtn = document.createElement('button');
        copyPubBtn.className = 'btn copy-btn';
        copyPubBtn.textContent = 'Copy Public Key';
        copyPubBtn.onclick = (event) => copyToClipboard(keyPair.publicKey, event.target);
        keyOutput.appendChild(copyPubBtn);

        const copyPrivBtn = document.createElement('button');
        copyPrivBtn.className = 'btn copy-btn';
        copyPrivBtn.style.marginLeft = '10px';
        copyPrivBtn.textContent = 'Copy Private Key';
        copyPrivBtn.onclick = (event) => copyToClipboard(keyPair.privateKey, event.target);
        keyOutput.appendChild(copyPrivBtn);

    } catch (error) {
        console.error('Key generation error:', error);
        keyOutput.style.display = 'block';
        keyOutput.className = 'output error';
        keyOutput.textContent = `❌ Key Generation Error: ${error.message || error}`;
        keyStatus.textContent = 'Error';
        keyStatus.className = 'status error';
    } finally {
        generateBtn.disabled = false;
        generateBtn.textContent = 'Generate Key Pair';
    }
}

export function saveKeyPair() {
    if (!keyPair) {
        alert('No key pair to save. Generate keys first.');
        return;
    }

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

export function loadKeyPair() {
    document.getElementById('keyFileInput').click();
}

export function handleKeyFileLoad(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const keyData = JSON.parse(e.target.result);
            
            // Validate the loaded data
            if (!keyData.publicKey || !keyData.privateKey) {
                throw new Error('Invalid key file format. Missing public or private key.');
            }

            // Set the loaded keys
            keyPair = {
                publicKey: keyData.publicKey,
                privateKey: keyData.privateKey
            };

            // Clear the passphrase field since loaded keys may have a different passphrase
            document.getElementById('passphrase').value = '';
            document.getElementById('passphrase').placeholder = 'Enter passphrase for loaded keys';

            // Update UI to show keys are loaded
            const keyOutput = document.getElementById('keyOutput');
            const keyStatus = document.getElementById('keyStatus');
            
            keyOutput.style.display = 'block';
            keyOutput.className = 'output success';
            keyOutput.innerHTML = `✅ Key pair loaded successfully!<br><br>
                                    <strong>Loaded from:</strong> ${file.name}<br>
                                    <strong>Timestamp:</strong> ${keyData.timestamp || 'Unknown'}<br>
                                    <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 4px;">
                                        <strong>⚠️ Important:</strong> Please enter the correct passphrase for these loaded keys in the passphrase field above before signing or decrypting messages.
                                    </div>
                                    <strong>Public Key:</strong><pre>${keyPair.publicKey}</pre>
                                    <strong>Private Key:</strong><pre>${keyPair.privateKey}</pre>`;

            keyStatus.textContent = 'Ready';
            keyStatus.className = 'status ready';

            // Enable all buttons that need keys
           document.getElementById('signBtn').disabled = false;
            document.getElementById('signBtnNew').disabled = false; // Fixed: Enable the new sign button
            document.getElementById('encryptBtn').disabled = false;
            document.getElementById('decryptBtn').disabled = false;
            document.getElementById('verifyBtn').disabled = false; // Fixed: Enable verify button
            document.getElementById('saveKeyBtn').disabled = false;
            
            // Update all status indicators
            ['signVerifyStatus', 'encryptStatus', 'decryptStatus'].forEach(id => {
                const el = document.getElementById(id);
                el.textContent = 'Ready';
                el.className = 'status ready';
            });

            // Add copy buttons
            const existingCopyBtns = keyOutput.querySelectorAll('.copy-btn');
            existingCopyBtns.forEach(btn => btn.remove());

            const copyPubBtn = document.createElement('button');
            copyPubBtn.className = 'btn copy-btn';
            copyPubBtn.textContent = 'Copy Public Key';
            copyPubBtn.onclick = (event) => copyToClipboard(keyPair.publicKey, event.target);
            keyOutput.appendChild(copyPubBtn);

            const copyPrivBtn = document.createElement('button');
            copyPrivBtn.className = 'btn copy-btn';
            copyPrivBtn.style.marginLeft = '10px';
            copyPrivBtn.textContent = 'Copy Private Key';
            copyPrivBtn.onclick = (event) => copyToClipboard(keyPair.privateKey, event.target);
            keyOutput.appendChild(copyPrivBtn);

        } catch (error) {
            console.error('Key loading error:', error);
            const keyOutput = document.getElementById('keyOutput');
            keyOutput.style.display = 'block';
            keyOutput.className = 'output error';
            keyOutput.textContent = `❌ Key Loading Error: ${error.message || error}`;
        }
    };
    
    reader.readAsText(file);
    // Clear the input so the same file can be loaded again if needed
    event.target.value = '';
} 