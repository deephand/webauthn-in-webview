document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const statusContainer = document.getElementById('status-checks');
    const getAssertionBtn = document.getElementById('get-assertion-btn');
    const createCredentialBtn = document.getElementById('create-credential-btn');
    const usernameInput = document.getElementById('username-input');
    const logDisplay = document.getElementById('log-display');
    const credentialsListDiv = document.getElementById('credentials-list');
    const clearStorageBtn = document.getElementById('clear-storage-btn');

    // --- Utility Functions ---

    /**
     * Decodes a Base64URL string into an ArrayBuffer.
     * @param {string} str The Base64URL string to decode.
     * @returns {ArrayBuffer}
     */
    const base64urlToBuffer = (str) => {
        const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        const binaryStr = atob(base64);
        const len = binaryStr.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryStr.charCodeAt(i);
        }
        return bytes.buffer;
    };

    /**
     * Encodes an ArrayBuffer into a Base64URL string.
     * @param {ArrayBuffer} buffer The ArrayBuffer to encode.
     * @returns {string}
     */
    const bufferToBase64url = (buffer) => {
        const bytes = new Uint8Array(buffer);
        const binaryStr = String.fromCharCode.apply(null, bytes);
        return btoa(binaryStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    };

    /**
     * Logs messages to the on-screen console.
     * @param {string} title The title of the log entry.
     * @param {any} data The data to log (will be stringified).
     * @param {'success' | 'error' | 'info'} type The type of log entry for color coding.
     */
    const log = (title, data = '', type = 'info') => {
        const now = new Date().toLocaleTimeString();
        let color = 'text-gray-400';
        if (type === 'success') color = 'text-green-400';
        if (type === 'error') color = 'text-red-400';
        
        const dataStr = data ? `\n${JSON.stringify(data, null, 2)}` : '';
        const currentLog = logDisplay.innerHTML;
        logDisplay.innerHTML = `[${now}] <span class="${color}">${title}</span>${dataStr}\n\n${currentLog}`;
    };

    /**
     * Renders a status item in the UI.
     * @param {string} label The text label for the check.
     * @param {boolean} success Whether the check passed.
     * @param {string} [notes=''] Optional notes to display below the status.
     */
    const renderStatus = (label, success, notes = '') => {
        const status = success ? 'success' : 'failure';
        const badgeText = success ? 'Available' : 'Unavailable';
        const noteHtml = notes ? `<p class="text-xs text-gray-500 mt-1">${notes}</p>` : '';

        statusContainer.innerHTML += `
            <div class="status-item">
                <div>
                    <span class="status-label">${label}</span>
                    ${noteHtml}
                </div>
                <span class="status-badge ${status}">${badgeText}</span>
            </div>
        `;
    };

    // --- WebAuthn Logic ---

    /**
     * Converts an ASN.1 DER-encoded signature to a raw (r,s) format.
     * @param {ArrayBuffer} derSignature The DER-encoded signature.
     * @returns {ArrayBuffer|null} The raw signature or null if parsing fails.
     */
    const derToRawSignature = (derSignature) => {
        try {
            const signature = new Uint8Array(derSignature);
            
            // Minimal parser for a DER sequence of two integers (r and s)
            if (signature[0] !== 0x30) throw new Error("Not a DER sequence.");
            
            let offset = 2; // Skip sequence and length
            
            // Parse r
            if (signature[offset] !== 0x02) throw new Error("Expected integer for r.");
            offset++;
            let rLength = signature[offset++];
            if (signature[offset] === 0x00) { // Handle leading zero
                offset++;
                rLength--;
            }
            const r = signature.slice(offset, offset + rLength);
            offset += rLength;

            // Parse s
            if (signature[offset] !== 0x02) throw new Error("Expected integer for s.");
            offset++;
            let sLength = signature[offset++];
            if (signature[offset] === 0x00) { // Handle leading zero
                offset++;
                sLength--;
            }
            const s = signature.slice(offset, offset + sLength);

            // Concatenate r and s to form a raw 64-byte signature
            const rawSignature = new Uint8Array(64);
            rawSignature.set(r, 32 - r.length);
            rawSignature.set(s, 64 - s.length);
            
            return rawSignature.buffer;
        } catch(e) {
            log('Failed to parse DER signature', {name: e.name, message: e.message}, 'error');
            return null;
        }
    };


    /**
     * Checks the environment for required APIs and features.
     */
    const performInitialChecks = async () => {
        log('Starting environment checks...');

        // 1. Check for Local Storage (only show a message on failure)
        let localStorageAvailable = false;
        try {
            localStorage.setItem('__test', 'test');
            localStorage.removeItem('__test');
            localStorageAvailable = true;
        } catch (e) {
            localStorageAvailable = false;
        }
        if (!localStorageAvailable) {
            renderStatus('Local Storage', false, 'Required for this demo to store passkeys.');
            log('Local Storage is not available. This demo will not be able to save credentials.', null, 'error');
        }

        // 2. Check for WebAuthn API (PublicKeyCredential)
        const webAuthnAvailable = !!window.PublicKeyCredential;
        renderStatus('WebAuthn API', webAuthnAvailable, 'Checks for <code>window.PublicKeyCredential</code>. If this fails on Android, you may need to call <code>WebSettingsCompat.setWebAuthenticationSupport()</code> in your app.');
        if (!webAuthnAvailable) {
            log('WebAuthn API not found. This browser/WebView does not support WebAuthn.', null, 'error');
        }

        // 3. Check for Conditional Mediation (Passkey Autofill)
        let conditionalMediationAvailable = false;
        if (webAuthnAvailable && PublicKeyCredential.isConditionalMediationAvailable) {
            conditionalMediationAvailable = await PublicKeyCredential.isConditionalMediationAvailable();
        }
        renderStatus('Conditional Mediation', conditionalMediationAvailable, 'Also known as "Passkey Autofill". May not be implemented in Chromium WebView yet, but the underlying WebAuthn support is still available.');
        
        log('Environment checks complete.');
        loadCredentialsFromStorage();
    };

    /**
     * Loads credentials from local storage and displays them in the options panel.
     */
    const loadCredentialsFromStorage = () => {
        const creds = JSON.parse(localStorage.getItem('webauthn-credentials') || '[]');
        credentialsListDiv.innerHTML = ''; 

        if (creds.length === 0) {
            credentialsListDiv.innerHTML = '<p class="text-gray-500">No passkeys created yet.</p>';
            return;
        }

        creds.forEach(cred => {
            const el = document.createElement('label');
            el.className = 'credential-item';
            el.innerHTML = `
                <input type="checkbox" class="credential-checkbox" value="${cred.id}">
                <div class="credential-info">
                    <span class="username">${cred.username}</span>
                    <br>
                    ID: ${cred.id.substring(0, 20)}...
                </div>
            `;
            credentialsListDiv.appendChild(el);
        });
    };
    
    /**
     * Saves a credential to local storage.
     * @param {{username: string, id: string, rawId: string, pubKey: string, alg: number}} cred The credential object.
     */
    const saveCredential = (cred) => {
        const creds = JSON.parse(localStorage.getItem('webauthn-credentials') || '[]');
        if (!creds.some(c => c.id === cred.id)) {
            creds.push(cred);
            localStorage.setItem('webauthn-credentials', JSON.stringify(creds));
        }
    };
    
    /**
     * Handles the creation of a new passkey.
     */
    const handleCreateCredential = async () => {
        const username = usernameInput.value;
        if (!username) {
            log('Username cannot be empty.', null, 'error');
            alert('Please enter a username.');
            return;
        }
        log(`Creating passkey for username: ${username}...`);

        try {
            const challenge = crypto.getRandomValues(new Uint8Array(32));

            const createOptions = {
                challenge,
                rp: { name: 'WebAuthn WebView Demo', id: window.location.hostname },
                user: { id: crypto.getRandomValues(new Uint8Array(16)), name: username, displayName: username },
                pubKeyCredParams: [ { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 } ],
                authenticatorSelection: {
                    // authenticatorAttachment: 'platform', // By omitting this, we allow both platform and cross-platform authenticators.
                    userVerification: 'required',
                    residentKey: 'required' // 'residentKey' is now an alias for 'discoverableCredential'
                },
                timeout: 60000,
                attestation: 'none'
            };

            const loggableOptions = {
                ...createOptions,
                challenge: bufferToBase64url(createOptions.challenge),
                user: { ...createOptions.user, id: bufferToBase64url(createOptions.user.id) },
            };
            log('Calling navigator.credentials.create() with options:', loggableOptions);

            const credential = await navigator.credentials.create({ publicKey: createOptions });
            log('navigator.credentials.create() successful!', credential, 'success');

            log('--- Verifying new credential (simulated server-side) ---');
            const clientDataJSON = JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON));
            
            const challengeReceived = clientDataJSON.challenge;
            const challengeSent = bufferToBase64url(challenge);
            if (challengeReceived !== challengeSent) {
                throw new Error(`Challenge mismatch! \nExpected: ${challengeSent} \nReceived: ${challengeReceived}`);
            }
            log('✅ Challenge verified');

            const expectedOrigin = window.location.origin;
            if (clientDataJSON.origin !== expectedOrigin) {
                throw new Error(`Origin mismatch! \nExpected: ${expectedOrigin} \nReceived: ${clientDataJSON.origin}`);
            }
            log('✅ Origin verified');
            
            if (clientDataJSON.type !== 'webauthn.create') {
                throw new Error(`Type mismatch! \nExpected: 'webauthn.create' \nReceived: '${clientDataJSON.type}'`);
            }
            log('✅ Type verified');
            
            const newCred = {
                username: username,
                id: bufferToBase64url(credential.rawId),
                rawId: bufferToBase64url(credential.rawId),
                pubKey: bufferToBase64url(credential.response.getPublicKey()),
                alg: credential.response.getPublicKeyAlgorithm()
            };
            saveCredential(newCred);
            log('✅ Credential stored in local storage.', newCred, 'success');
            usernameInput.value = '';
            loadCredentialsFromStorage();

        } catch (err) {
            log('Error during credential creation', { name: err.name, message: err.message }, 'error');
        }
    };

    /**
     * Handles the login flow (getAssertion).
     */
    const handleGetAssertion = async () => {
        log('Starting passkey login...');

        try {
            const selectedCreds = Array.from(document.querySelectorAll('.credential-checkbox:checked'))
                .map(cb => ({ type: 'public-key', id: base64urlToBuffer(cb.value) }));
            
            const challenge = crypto.getRandomValues(new Uint8Array(32));

            const getOptions = {
                challenge,
                timeout: 60000,
                userVerification: 'required',
                rpId: window.location.hostname,
            };

            if (selectedCreds.length > 0) {
                getOptions.allowCredentials = selectedCreds;
            }
            
            const loggableOptions = {
                ...getOptions,
                challenge: bufferToBase64url(getOptions.challenge),
                ...(getOptions.allowCredentials && {
                    allowCredentials: getOptions.allowCredentials.map(cred => ({ ...cred, id: bufferToBase64url(cred.id) }))
                })
            };
            log('Calling navigator.credentials.get() with options:', loggableOptions);

            const assertion = await navigator.credentials.get({ publicKey: getOptions });
            log('navigator.credentials.get() successful!', assertion, 'success');

            log('--- Verifying assertion (simulated server-side) ---');

            const allCreds = JSON.parse(localStorage.getItem('webauthn-credentials') || '[]');
            const credToVerify = allCreds.find(c => c.id === bufferToBase64url(assertion.rawId));

            if (!credToVerify) {
                throw new Error(`Could not find credential with ID ${bufferToBase64url(assertion.rawId)} in storage.`);
            }
            log('Found matching credential in storage for verification.', credToVerify);

            const clientDataJSON = JSON.parse(new TextDecoder().decode(assertion.response.clientDataJSON));
            
            const challengeReceived = clientDataJSON.challenge;
            const challengeSent = bufferToBase64url(challenge);
            if (challengeReceived !== challengeSent) {
                throw new Error(`Challenge mismatch! \nExpected: ${challengeSent} \nReceived: ${challengeReceived}`);
            }
            log('✅ Challenge verified');

            const expectedOrigin = window.location.origin;
            if (clientDataJSON.origin !== expectedOrigin) {
                throw new Error(`Origin mismatch! \nExpected: ${expectedOrigin} \nReceived: ${clientDataJSON.origin}`);
            }
            log('✅ Origin verified');

            const authenticatorData = assertion.response.authenticatorData;
            const clientDataHash = await crypto.subtle.digest('SHA-256', assertion.response.clientDataJSON);
            const signatureBase = new Uint8Array([...new Uint8Array(authenticatorData), ...new Uint8Array(clientDataHash)]);
            
            const publicKey = await crypto.subtle.importKey(
                'spki', 
                base64urlToBuffer(credToVerify.pubKey),
                { name: 'ECDSA', namedCurve: 'P-256' }, 
                true, 
                ['verify']
            );
            
            log('Imported public key for verification.');

            const rawSignature = derToRawSignature(assertion.response.signature);
            if (!rawSignature) {
                throw new Error("Failed to parse signature from authenticator.");
            }

            const signatureIsValid = await crypto.subtle.verify(
                { name: 'ECDSA', hash: { name: 'SHA-256' } },
                publicKey,
                rawSignature,
                signatureBase
            );
            
            if (signatureIsValid) {
                log('✅ SIGNATURE VERIFIED!', null, 'success');
                log(`Welcome back, ${credToVerify.username}!`, null, 'success');
            } else {
                throw new Error("Signature verification failed!");
            }

        } catch (err) {
            log('Error during assertion', { name: err.name, message: err.message }, 'error');
        }
    };

    /**
     * Handles the logic for the clear storage button.
     */
    let isConfirmingClear = false;
    let clearConfirmTimeout;

    const resetClearButtonState = () => {
        clearStorageBtn.textContent = 'Clear All Stored Passkeys';
        clearStorageBtn.classList.remove('bg-yellow-500', 'hover:bg-yellow-600', 'focus:ring-yellow-300');
        clearStorageBtn.classList.add('bg-red-600', 'hover:bg-red-700', 'focus:ring-red-300');
        isConfirmingClear = false;
    };

    const handleClearStorage = () => {
        if (!isConfirmingClear) {
            clearStorageBtn.textContent = 'Are you sure? Click again to clear';
            clearStorageBtn.classList.remove('bg-red-600', 'hover:bg-red-700', 'focus:ring-red-300');
            clearStorageBtn.classList.add('bg-yellow-500', 'hover:bg-yellow-600', 'focus:ring-yellow-300');
            isConfirmingClear = true;

            clearConfirmTimeout = setTimeout(() => {
                resetClearButtonState();
                log('Clear storage action timed out.', '', 'info');
            }, 4000); 
        } else {
            clearTimeout(clearConfirmTimeout);
            localStorage.removeItem('webauthn-credentials');
            log('Local storage cleared.', '', 'success');
            loadCredentialsFromStorage();
            resetClearButtonState();
        }
    };

    // --- Event Listeners ---
    createCredentialBtn.addEventListener('click', handleCreateCredential);
    getAssertionBtn.addEventListener('click', handleGetAssertion);
    clearStorageBtn.addEventListener('click', handleClearStorage);

    // --- Initialisation ---
    performInitialChecks();
});
