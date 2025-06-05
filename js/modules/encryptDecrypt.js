import { copyToClipboard } from './utils.js';
import { getKeyPair } from './keyManagement.js';

// Internal encryption function
async function _internalEncryptMessage(publicKeyArmored, messageText) {
    try {
        const publicKeyObj = await openpgp.readKey({ armoredKey: publicKeyArmored });
        const message = await openpgp.createMessage({ text: messageText });

        const encryptedMessage = await openpgp.encrypt({
            message,
            encryptionKeys: publicKeyObj,
            format: 'armored'
        });
        return encryptedMessage;
    } catch (error) {
        throw error;
    }
}

export async function encryptMessage() {
    const encryptBtn = document.getElementById('encryptBtn');
    const encryptOutput = document.getElementById('encryptOutput');
    const messageText = document.getElementById('messageToEncrypt').value;
    let customPublicKey = document.getElementById('encryptCustomPublicKey').value; // Get the raw value
    const useCustomKey = document.getElementById('encryptCustomPublicKeyContainer').style.display === 'block';

    try {
        encryptBtn.disabled = true;
        encryptBtn.innerHTML = '<span class="loading"></span> Encrypting...';
        encryptOutput.style.display = 'none';

        if (!messageText) throw new Error('Please enter a message to encrypt');

        let publicKeyToUse = '';

        if (useCustomKey) {
            // Sanitize the custom public key input
            customPublicKey = customPublicKey
                .trim() // Remove leading/trailing whitespace
                .replace(/\r\n/g, '\n') // Normalize Windows newlines to Unix newlines
                .replace(/[\u200B-\u200D\uFEFF]/g, ''); // Remove zero-width characters (ZWSP, ZWNJ, ZWJ, BOM/ZWNBSP)

            if (!customPublicKey) throw new Error('Please enter a custom public key or switch to use the generated key.');
            publicKeyToUse = customPublicKey; // Use the sanitized key
        } else {
            const keyPair = getKeyPair();
            if (!keyPair || !keyPair.publicKey) throw new Error('Generated public key not available. Generate keys first or provide a custom key.');
            publicKeyToUse = keyPair.publicKey;
        }

        const encryptedMessage = await _internalEncryptMessage(publicKeyToUse, messageText);

        encryptOutput.style.display = 'block';
        encryptOutput.className = 'output success';
        encryptOutput.innerHTML = `✅ Message encrypted successfully!<br><br><pre>${encryptedMessage}</pre>`;

        const existingCopyBtn = encryptOutput.querySelector('.copy-btn');
        if (existingCopyBtn) existingCopyBtn.remove();

        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn copy-btn';
        copyBtn.textContent = 'Copy Encrypted Message';
        copyBtn.onclick = (event) => copyToClipboard(encryptedMessage, event.target);
        encryptOutput.appendChild(copyBtn);

    } catch (error) {
        console.error('Encryption error:', error);
        encryptOutput.style.display = 'block';
        encryptOutput.className = 'output error';
        encryptOutput.textContent = `❌ Encryption Error: ${error.message || error}`;
    } finally {
        encryptBtn.disabled = false;
        encryptBtn.textContent = 'Encrypt Message';
    }
}

export async function decryptMessage() {
    const decryptBtn = document.getElementById('decryptBtn');
    const decryptOutput = document.getElementById('decryptOutput');

    try {
        decryptBtn.disabled = true;
        decryptBtn.innerHTML = '<span class="loading"></span> Decrypting...';
        decryptOutput.style.display = 'none';

        const encryptedText = document.getElementById('messageToDecrypt').value.trim();
        const localPassphrase = document.getElementById('passphrase').value;
        const keyPair = getKeyPair();

        if (!encryptedText) throw new Error('Please enter an encrypted message to decrypt');
        if (!keyPair || !keyPair.privateKey) throw new Error('Private key not available. Generate keys first.');
        if (!localPassphrase) throw new Error('Passphrase is required to decrypt');

        const privateKeyArmored = keyPair.privateKey;
        let privateKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });

        if (!privateKeyObj.isDecrypted()) {
            privateKeyObj = await openpgp.decryptKey({
                privateKey: privateKeyObj,
                passphrase: localPassphrase
            });
        }

        const encryptedMessageObj = await openpgp.readMessage({ armoredMessage: encryptedText });

        const { data: decryptedMessage } = await openpgp.decrypt({
            message: encryptedMessageObj,
            decryptionKeys: privateKeyObj,
            format: 'utf8'
        });

        let outputText = `✅ Message decrypted successfully!<br><br><strong>Decrypted Message:</strong><pre>${decryptedMessage}</pre>`;

        decryptOutput.style.display = 'block';
        decryptOutput.className = 'output success';
        decryptOutput.innerHTML = outputText;

        const existingCopyBtn = decryptOutput.querySelector('.copy-btn');
        if (existingCopyBtn) existingCopyBtn.remove();

        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn copy-btn';
        copyBtn.textContent = 'Copy Decrypted Message';
        copyBtn.onclick = (event) => copyToClipboard(decryptedMessage, event.target);
        decryptOutput.appendChild(copyBtn);

    } catch (error) {
        console.error('Decryption error:', error);
        decryptOutput.style.display = 'block';
        decryptOutput.className = 'output error';
        
        let errorMessage = `❌ Decryption Error: ${error.message || error}\n\nDebugging info:\n- Make sure you're using the same key pair that encrypted the message.\n- Check that the PGP message block is complete and properly formatted.\n- Verify the passphrase is correct.`;
        
        if (error.message && error.message.includes('Incorrect key passphrase')) {
            errorMessage += `\n- If you loaded keys from a file, ensure you entered the correct passphrase for those loaded keys.\n- The passphrase field was cleared when you loaded the keys.`;
        }
        
        decryptOutput.textContent = errorMessage;
    } finally {
        decryptBtn.disabled = false;
        decryptBtn.textContent = 'Decrypt Message';
    }
} 