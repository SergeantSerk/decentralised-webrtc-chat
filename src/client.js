// --- Signaling Server (VERY BASIC, for demonstration only) ---
const SIGNALING_SERVER_URL = `ws://${window.location.hostname}:8080`;
let ws;
let localPeerId = '';
let remotePeerId = '';
let isPeerOnline = false; // Track remote peer's online status, based *only* on explicit checks

// --- WebRTC Setup ---
let pc = null;
let dataChannel = null;
const configuration = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun3.l.google.com:19302' },
        { urls: 'stun:stun4.l.google.com:19302' },
        { urls: 'stun:freestun.net:3478' },
        { urls: 'turn:freestun.net:3478', username: 'free', credential: 'free' }
    ]
};

// --- E2EE Key Management ---
let localKey = null;
let remotePublicKey = null;
let sharedSecret = null;
let encryptionKey = null;

async function generateDhKeys() {
    localKey = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits", "deriveKey"]
    );
    console.log('Generated local ECDH key pair.');
    return localKey;
}

async function exportPublicKey(key) {
    const exported = await crypto.subtle.exportKey('jwk', key.publicKey);
    return exported;
}

async function importPublicKey(jwk) {
    remotePublicKey = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
    );
    console.log('Imported remote public key.');
}

async function deriveSharedSecret() {
    if (!localKey || !remotePublicKey) {
        console.error('Local key or remote public key missing for shared secret derivation.');
        return;
    }
    sharedSecret = await crypto.subtle.deriveBits(
        { name: 'ECDH', namedCurve: 'P-256', public: remotePublicKey },
        localKey.privateKey,
        256
    );
    console.log('Derived shared secret.');

    encryptionKey = await crypto.subtle.importKey(
        'raw',
        sharedSecret,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
    console.log('Derived AES-GCM encryption key.');

    displaySafetyCode();
}

async function encryptMessage(message) {
    if (!encryptionKey) {
        throw new Error('Encryption key not available. Keys not exchanged or derived.');
    }
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        encryptionKey,
        data
    );
    return { iv: Array.from(iv), ciphertext: Array.from(new Uint8Array(ciphertext)) };
}

async function decryptMessage(encryptedData) {
    if (!encryptionKey) {
        throw new Error('Encryption key not available. Keys not exchanged or derived.');
    }
    const decoder = new TextDecoder();
    const iv = new Uint8Array(encryptedData.iv);
    const ciphertext = new Uint8Array(encryptedData.ciphertext);
    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            encryptionKey,
            ciphertext
        );
        return decoder.decode(plaintext);
    } catch (e) {
        console.error('Decryption failed:', e);
        return '[Decryption Failed]';
    }
}

async function displaySafetyCode() {
    if (!sharedSecret) {
        console.warn('Shared secret not available to generate safety code.');
        return;
    }
    const hashBuffer = await crypto.subtle.digest('SHA-256', sharedSecret);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const safetyCode = hashArray.slice(0, 4).map(b => b.toString(16).padStart(2, '0')).join('');

    document.getElementById('safety-code').textContent = `Safety Code: ${safetyCode.toUpperCase()}`;
    appendMessage('System', `**Compare this Safety Code with your peer: ${safetyCode.toUpperCase()}**`);
    appendMessage('System', 'If codes match, your connection is secure and not tampered with.');
}

// --- Signaling Server WebSocket Logic ---
function setupWebSocket() {
    ws = new WebSocket(SIGNALING_SERVER_URL);

    ws.onopen = () => {
        console.log('Connected to signaling server');
        updateStatus('Connected to signaling server');
        if (localPeerId) {
            ws.send(JSON.stringify({ type: 'register', id: localPeerId }));
        }
    };

    ws.onmessage = async (event) => {
        const message = JSON.parse(event.data);
        console.log('Signaling message received:', message);

        switch (message.type) {
            case 'registered':
                if (message.success) {
                    updateStatus(`Registered as ${localPeerId}`);
                    sendPendingMessages();
                } else {
                    updateStatus(`Registration failed: ${message.reason}`);
                }
                break;
            // REMOVED: case 'peer-online':
            case 'peer-offline': // Still useful if a peer connected to us goes offline
                if (message.id === remotePeerId) {
                    isPeerOnline = false;
                    appendMessage('System', `${message.id} went offline.`);
                    updateSendButtonState(); // Update send button if remote goes offline
                } else {
                    // For other peers that might go offline, but not our current conversation
                    appendMessage('System', `${message.id} disconnected from signaling server.`);
                }
                break;
            case 'online-check-response':
                isPeerOnline = message.isOnline;
                if (isPeerOnline) {
                    appendMessage('System', `${message.id} is online. Initiating call...`);
                    initiateCallProceed();
                } else {
                    appendMessage('System', `${message.id} is offline. Message will be queued (if enabled) or not sent.`);
                    alert(`${message.id} is offline.`);
                    updateSendButtonState(); // Update send button state after check
                    document.getElementById('connect-button').disabled = false;
                }
                break;
            case 'offer':
                // Allow new offer if we are not currently connected or if it's from current remoteId
                if (remotePeerId && message.from !== remotePeerId && pc && pc.connectionState !== 'closed') {
                    console.warn(`Ignoring offer from ${message.from}. Already connected to ${remotePeerId}.`);
                    ws.send(JSON.stringify({
                        type: 'reject-offer',
                        to: message.from,
                        reason: `Busy, already connected to ${remotePeerId}`,
                        from: localPeerId
                    }));
                    return;
                }

                remotePeerId = message.from;
                document.getElementById('remote-peer-id').value = remotePeerId;
                appendMessage('System', `Incoming call from ${remotePeerId}.`);
                document.getElementById('accept-call-button').style.display = 'inline-block';
                document.getElementById('decline-call-button').style.display = 'inline-block';
                document.getElementById('connect-button').style.display = 'none';
                document.getElementById('connection-actions').style.display = 'none';

                // Automatically accept for this demo, but user interaction is better
                await acceptIncomingCall(message);
                break;
            case 'answer':
                await pc.setRemoteDescription(new RTCSessionDescription(message.answer));
                await sendDhPublicKey();
                break;
            case 'candidate':
                if (message.candidate) {
                    try {
                        await pc.addIceCandidate(new RTCIceCandidate(message.candidate));
                    } catch (e) {
                        console.error('Error adding received ICE candidate:', e);
                    }
                }
                break;
            case 'dh-public-key':
                await importPublicKey(message.key);
                await deriveSharedSecret();
                break;
            case 'peer-disconnected': // This is for when the other peer explicitly disconnects
                // Check if the disconnected peer is our current active remotePeerId
                if (message.id === remotePeerId) {
                    handlePeerDisconnect();
                } else {
                    appendMessage('System', `${message.id} disconnected from signaling server.`);
                }
                break;
            case 'offer-rejected':
                appendMessage('System', `${message.from} rejected your call: ${message.reason}`);
                resetConnectionState();
                break;
        }
    };

    ws.onclose = () => {
        console.log('Disconnected from signaling server');
        updateStatus('Disconnected from signaling server');
        isPeerOnline = false;
        resetConnectionState();
    };

    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateStatus('WebSocket error. Check console.');
    };
}

// --- WebRTC Setup ---
async function createPeerConnection() {
    pc = new RTCPeerConnection(configuration);

    pc.onicecandidate = (event) => {
        if (event.candidate) {
            console.log('Sending ICE candidate:', event.candidate);
            ws.send(JSON.stringify({
                type: 'candidate',
                to: remotePeerId,
                candidate: event.candidate
            }));
        }
    };

    pc.onconnectionstatechange = (event) => {
        console.log('RTC Connection State:', pc.connectionState);
        updateStatus(`RTC Connection: ${pc.connectionState}`);
        if (pc.connectionState === 'connected') {
            appendMessage('System', 'WebRTC connection established!');
            document.getElementById('connect-button').style.display = 'none';
            document.getElementById('connection-actions').style.display = 'block';
        } else if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed') {
            appendMessage('System', 'WebRTC connection disconnected or failed.');
            if (remotePeerId) handlePeerDisconnect();
        }
        updateSendButtonState();
    };

    pc.ondatachannel = (event) => {
        dataChannel = event.channel;
        setupDataChannelEvents();
        console.log('Received data channel:', dataChannel.label);
        appendMessage('System', 'Data channel opened by remote peer.');
        sendDhPublicKey();
    };

    console.log('PeerConnection created');
    return pc;
}

function setupDataChannelEvents() {
    dataChannel.onopen = (event) => {
        console.log('DataChannel opened!');
        updateStatus('DataChannel: Open');
        updateSendButtonState();
        sendPendingMessagesForPeer(remotePeerId);
    };

    dataChannel.onmessage = async (event) => {
        console.log('Encrypted message received:', event.data);
        try {
            const decryptedMessage = await decryptMessage(JSON.parse(event.data));
            appendMessage(remotePeerId, decryptedMessage);
            storeMessage({ from: remotePeerId, to: localPeerId, content: decryptedMessage, timestamp: Date.now(), status: 'received' });
        } catch (e) {
            appendMessage('System', `[Error decrypting message: ${e.message}]`);
            console.error('Message decryption error:', e);
        }
    };

    dataChannel.onclose = () => {
        console.log('DataChannel closed!');
        updateStatus('DataChannel: Closed');
        updateSendButtonState();
    };

    dataChannel.onerror = (error) => {
        console.error('DataChannel error:', error);
        updateStatus('DataChannel error. Check console.');
    };
}

async function sendDhPublicKey() {
    if (!localKey) await generateDhKeys();
    const publicKeyJwk = await exportPublicKey(localKey);
    ws.send(JSON.stringify({
        type: 'dh-public-key',
        to: remotePeerId,
        key: publicKeyJwk
    }));
    appendMessage('System', 'Sent ECDH public key to peer.');
}

async function initiateCall() {
    remotePeerId = document.getElementById('remote-peer-id').value.trim();
    if (!remotePeerId) {
        alert('Please enter a remote Peer ID.');
        return;
    }
    if (remotePeerId === localPeerId) {
        alert('Cannot connect to yourself.');
        return;
    }
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        alert('Not connected to signaling server. Please set your Peer ID first.');
        return;
    }

    document.getElementById('connect-button').disabled = true;
    appendMessage('System', `Checking if ${remotePeerId} is online...`);
    ws.send(JSON.stringify({
        type: 'check-online',
        to: remotePeerId,
        from: localPeerId
    }));
}

async function initiateCallProceed() {
    if (!pc) await createPeerConnection();

    dataChannel = pc.createDataChannel('chat');
    setupDataChannelEvents();
    console.log('Created data channel: chat');

    await generateDhKeys();

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    ws.send(JSON.stringify({
        type: 'offer',
        to: remotePeerId,
        offer: offer
    }));
    updateStatus(`Offering connection to ${remotePeerId}`);
    updateSendButtonState();
}

async function acceptIncomingCall(message) {
    document.getElementById('accept-call-button').style.display = 'none';
    document.getElementById('decline-call-button').style.display = 'none';
    document.getElementById('connect-button').style.display = 'none';
    document.getElementById('connection-actions').style.display = 'block';

    if (!pc) await createPeerConnection();

    await generateDhKeys();

    await pc.setRemoteDescription(new RTCSessionDescription(message.offer));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    ws.send(JSON.stringify({
        type: 'answer',
        to: message.from,
        answer: answer
    }));
    updateStatus(`Accepted call from ${message.from}`);
    appendMessage('System', `Accepted call from ${message.from}. Exchanging encryption keys...`);
    updateSendButtonState();
}

function declineIncomingCall() {
    appendMessage('System', `Declined call from ${remotePeerId}.`);
    ws.send(JSON.stringify({
        type: 'reject-offer',
        to: remotePeerId,
        reason: 'Declined by user',
        from: localPeerId
    }));
    resetConnectionState();
}

function disconnectPeer() {
    if (pc) {
        pc.close();
        pc = null;
    }
    if (dataChannel) {
        dataChannel.close();
        dataChannel = null;
    }
    // Notify signaling server about explicit disconnect
    if (ws && ws.readyState === WebSocket.OPEN && remotePeerId) {
        ws.send(JSON.stringify({ type: 'disconnect', from: localPeerId, to: remotePeerId }));
    }
    handlePeerDisconnect();
}

function handlePeerDisconnect() {
    appendMessage('System', `Connection with ${remotePeerId} closed.`);
    pc = null;
    dataChannel = null;
    encryptionKey = null;
    sharedSecret = null;
    remotePublicKey = null;
    isPeerOnline = false;
    updateStatus('Peer disconnected. Connection closed.');
    document.getElementById('safety-code').textContent = 'Safety Code: N/A';
    resetConnectionState();
}

function resetConnectionState() {
    // Only clear remotePeerId if it was the currently connected peer
    // This allows keeping the ID in the input if we just disconnected locally
    if (remotePeerId && !pc && !dataChannel) { // Check if connection truly closed
        remotePeerId = '';
        document.getElementById('remote-peer-id').value = '';
    }
    document.getElementById('accept-call-button').style.display = 'none';
    document.getElementById('decline-call-button').style.display = 'none';
    document.getElementById('connect-button').style.display = 'inline-block';
    document.getElementById('connection-actions').style.display = 'none';
    updateSendButtonState();
}

async function sendMessage() {
    const messageInput = document.getElementById('message-input');
    const message = messageInput.value;
    const queueOffline = document.getElementById('queue-offline-messages').checked;

    if (message.trim() === '') {
        return;
    }

    if (dataChannel && dataChannel.readyState === 'open' && encryptionKey) {
        try {
            const encryptedData = await encryptMessage(message);
            dataChannel.send(JSON.stringify(encryptedData));
            appendMessage(localPeerId, message);
            messageInput.value = '';
            storeMessage({
                from: localPeerId,
                to: remotePeerId,
                content: message,
                timestamp: Date.now(),
                status: 'sent'
            });
        } catch (e) {
            console.error('Error encrypting or sending message:', e);
            appendMessage('System', `Error sending message: ${e.message}`);
            alert('Failed to send message. See console for details.');
        }
    } else if (!isPeerOnline && queueOffline && remotePeerId) { // Ensure remotePeerId is set for queuing
        appendMessage('System', 'Peer is offline. Message will be queued.');
        await storeMessage({
            from: localPeerId,
            to: remotePeerId,
            content: message,
            timestamp: Date.now(),
            status: 'pending'
        });
        appendMessage(`${localPeerId} (Pending)`, message);
        messageInput.value = '';
    } else if (!isPeerOnline && !queueOffline && remotePeerId) { // Ensure remotePeerId is set for alert
        alert('Cannot send message: Peer is offline and queuing is disabled.');
    } else if (!encryptionKey && (dataChannel && dataChannel.readyState === 'open')) { // If connected but no key
        alert('Cannot send message: Encryption key not established yet. Waiting for secure connection.');
        console.warn('Encryption key not ready for message sending.');
    } else if (!dataChannel || dataChannel.readyState !== 'open') { // If not connected at all
        alert('Cannot send message: WebRTC data channel not open or ready. Connect to a peer first.');
        console.warn('DataChannel not open or ready.');
    } else {
        console.warn('Unhandled sendMessage state. isPeerOnline:', isPeerOnline, 'queueOffline:', queueOffline, 'remotePeerId:', remotePeerId, 'dataChannel:', dataChannel?.readyState, 'encryptionKey:', !!encryptionKey);
        alert('Cannot send message in current state. Check console.');
    }
}

function updateSendButtonState() {
    const queueOffline = document.getElementById('queue-offline-messages').checked;
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');

    // Enable if dataChannel is open AND encryptionKey is ready (for direct E2EE chat)
    // OR if queuing is enabled AND a remotePeerId is specified (to allow queuing for offline peers)
    if ((dataChannel && dataChannel.readyState === 'open' && encryptionKey) ||
        (queueOffline && remotePeerId && localPeerId && ws && ws.readyState === WebSocket.OPEN)) {
        sendButton.disabled = false;
        messageInput.disabled = false;
    } else {
        sendButton.disabled = true;
        messageInput.disabled = true;
    }
}

// --- UI Helpers ---
function updateStatus(message) {
    document.getElementById('status').textContent = message;
}

function appendMessage(sender, message) {
    const chatContainer = document.getElementById('chat-container');
    const msgElement = document.createElement('p');
    msgElement.innerHTML = `<strong>${sender}:</strong> ${message}`;
    chatContainer.appendChild(msgElement);
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

function setLocalPeerId() {
    const id = document.getElementById('local-peer-id').value.trim();
    if (id) {
        localPeerId = id;
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'register', id: localPeerId }));
        } else {
            setupWebSocket();
        }
        updateStatus(`Attempting to register as ${localPeerId}...`);
        document.getElementById('local-peer-id').disabled = true;
        if (remotePeerId) { // Load conversation if a remote peer is already specified
            loadMessages(localPeerId, remotePeerId);
        }
        updateSendButtonState(); // Update send button state after setting local ID
    } else {
        alert('Please enter a unique ID for yourself.');
    }
}

// --- IndexedDB for Message History & Offline Queue ---
const DB_NAME = 'decentralizedChatDB';
const DB_VERSION = 2;
const STORE_NAME = 'messages';
let db;

function openDb() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onupgradeneeded = (event) => {
            db = event.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                const objectStore = db.createObjectStore(STORE_NAME, { keyPath: 'id', autoIncrement: true });
                objectStore.createIndex('timestamp', 'timestamp', { unique: false });
                objectStore.createIndex('conversation', ['from', 'to'], { unique: false });
                objectStore.createIndex('status', 'status', { unique: false });
            }
        };

        request.onsuccess = (event) => {
            db = event.target.result;
            console.log('IndexedDB opened successfully');
            resolve(db);
        };

        request.onerror = (event) => {
            console.error('IndexedDB error:', event.target.errorCode);
            reject(event.target.error);
        };
    });
}

async function storeMessage(message) {
    if (!db) {
        await openDb();
    }
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    store.add(message);
    return new Promise((resolve, reject) => {
        transaction.oncomplete = () => {
            console.log('Message stored in IndexedDB');
            resolve();
        };
        transaction.onerror = (event) => {
            console.error('Error storing message:', event.target.error);
            reject(event.target.error);
        };
    });
}

async function loadMessages(peer1, peer2) {
    if (!db) {
        await openDb();
    }
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORE_NAME], 'readonly');
        const store = transaction.objectStore(STORE_NAME);
        const index = store.index('conversation');

        const messages = [];

        index.openCursor(IDBKeyRange.only([peer1, peer2])).onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
                messages.push(cursor.value);
                cursor.continue();
            }
        };

        index.openCursor(IDBKeyRange.only([peer2, peer1])).onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
                messages.push(cursor.value);
                cursor.continue();
            }
        };

        transaction.oncomplete = () => {
            messages.sort((a, b) => a.timestamp - b.timestamp);
            console.log('Loaded messages:', messages);
            document.getElementById('chat-container').innerHTML = '';
            messages.forEach(msg => {
                const sender = msg.from === localPeerId ? localPeerId : msg.from;
                appendMessage(sender, msg.content + (msg.status === 'pending' ? ' (Pending)' : ''));
            });
            resolve(messages);
        };

        transaction.onerror = (event) => {
            console.error('Error loading messages:', event.target.error);
            reject(event.target.error);
        };
    });
}

async function getPendingMessages() {
    if (!db) {
        await openDb();
    }
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORE_NAME], 'readonly');
        const store = transaction.objectStore(STORE_NAME);
        const index = store.index('status');
        const pendingMessages = [];

        index.openCursor(IDBKeyRange.only('pending')).onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
                pendingMessages.push(cursor.value);
                cursor.continue();
            }
        };

        transaction.oncomplete = () => {
            resolve(pendingMessages);
        };
        transaction.onerror = (event) => {
            console.error('Error getting pending messages:', event.target.error);
            reject(event.target.error);
        };
    });
}

async function updateMessageStatus(id, newStatus) {
    if (!db) {
        await openDb();
    }
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get(id);

    request.onsuccess = () => {
        const data = request.result;
        if (data) {
            data.status = newStatus;
            const updateRequest = store.put(data);
            updateRequest.onsuccess = () => {
                console.log(`Message ${id} status updated to ${newStatus}`);
            };
            updateRequest.onerror = (event) => {
                console.error(`Error updating message ${id} status:`, event.target.error);
            };
        }
    };
    request.onerror = (event) => {
        console.error(`Error retrieving message ${id}:`, event.target.error);
    };
}

async function sendPendingMessages(peerIdToSend = null) {
    const pendingMsgs = await getPendingMessages();
    if (!pendingMsgs.length) {
        console.log('No pending messages to send.');
        return;
    }

    console.log(`Attempting to send ${pendingMsgs.length} pending messages.`);

    for (const msg of pendingMsgs) {
        if (peerIdToSend && msg.to !== peerIdToSend) {
            continue;
        }

        if (dataChannel && dataChannel.readyState === 'open' && encryptionKey && msg.to === remotePeerId) {
            try {
                const encryptedData = await encryptMessage(msg.content);
                dataChannel.send(JSON.stringify(encryptedData));
                appendMessage(`${localPeerId} (Resent)`, msg.content);
                await updateMessageStatus(msg.id, 'sent');
            } catch (e) {
                console.error('Failed to resend pending message:', e);
                appendMessage('System', `Failed to resend pending message to ${msg.to}: ${msg.content.substring(0, 20)}...`);
            }
        } else {
            console.log(`Cannot send pending message to ${msg.to}. DataChannel not open or encryption key missing.`);
        }
    }
}

function sendPendingMessagesForPeer(peerId) {
    sendPendingMessages(peerId);
}

// Initial setup
window.onload = () => {
    document.getElementById('message-input').disabled = true;
    document.getElementById('send-button').disabled = true;
    document.getElementById('accept-call-button').style.display = 'none';
    document.getElementById('decline-call-button').style.display = 'none';
    document.getElementById('connection-actions').style.display = 'none';

    document.getElementById('connect-button').addEventListener('click', initiateCall);
    document.getElementById('disconnect-button').addEventListener('click', disconnectPeer);
    document.getElementById('accept-call-button').addEventListener('click', () => acceptIncomingCall({ from: remotePeerId }));
    document.getElementById('decline-call-button').addEventListener('click', declineIncomingCall);
    document.getElementById('queue-offline-messages').addEventListener('change', updateSendButtonState);
    document.getElementById('remote-peer-id').addEventListener('input', () => {
        // When remote ID changes, update button state and load history for new peer
        updateSendButtonState();
        const newRemoteId = document.getElementById('remote-peer-id').value.trim();
        if (localPeerId && newRemoteId) {
            loadMessages(localPeerId, newRemoteId);
        } else {
            document.getElementById('chat-container').innerHTML = ''; // Clear chat if no remote ID
        }
    });

    updateSendButtonState();
};