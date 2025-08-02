const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = 8080;

// Serve static files from the current directory
app.use(express.static(path.join(__dirname)));

// Serve index.html for the root path
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const clients = new Map(); // Map to store { peerId: ws_connection }

console.log('Starting signaling server...');

wss.on('connection', function connection(ws) {
    let currentPeerId = null;

    ws.on('message', function incoming(message) {
        const data = JSON.parse(message);
        console.log('Received signaling message:', data);

        switch (data.type) {
            case 'register':
                if (data.id && !clients.has(data.id)) {
                    clients.set(data.id, ws);
                    currentPeerId = data.id;
                    ws.send(JSON.stringify({ type: 'registered', success: true, id: data.id }));
                    console.log(`Peer ${data.id} registered.`);
                } else {
                    ws.send(JSON.stringify({ type: 'registered', success: false, reason: 'ID already taken or invalid' }));
                    console.log(`Failed to register ${data.id}.`);
                }
                break;

            case 'check-online':
                if (data.to && clients.has(data.to)) {
                    ws.send(JSON.stringify({
                        type: 'online-check-response',
                        from: data.to,
                        isOnline: true,
                        id: data.to
                    }));
                } else {
                    ws.send(JSON.stringify({
                        type: 'online-check-response',
                        from: data.to,
                        isOnline: false,
                        id: data.to
                    }));
                }
                break;

            case 'offer':
            case 'answer':
            case 'candidate':
            case 'dh-public-key':
                if (data.to && clients.has(data.to)) {
                    const recipientWs = clients.get(data.to);
                    recipientWs.send(JSON.stringify({ ...data, from: currentPeerId }));
                    console.log(`Relaying ${data.type} from ${currentPeerId} to ${data.to}`);
                } else {
                    ws.send(JSON.stringify({
                        type: 'peer-offline', // Inform sender that target is offline
                        id: data.to,
                        reason: `${data.to} is offline. Cannot relay ${data.type}.`
                    }));
                    console.warn(`Recipient ${data.to} not found for ${data.type} from ${currentPeerId}. Notifying sender.`);
                }
                break;

            case 'reject-offer':
                if (data.to && clients.has(data.to)) {
                    const recipientWs = clients.get(data.to);
                    recipientWs.send(JSON.stringify({
                        type: 'offer-rejected',
                        from: currentPeerId,
                        reason: data.reason || 'Offer rejected.'
                    }));
                    console.log(`Offer from ${currentPeerId} rejected by ${data.to}.`);
                }
                break;

            case 'disconnect':
                if (data.to && clients.has(data.to)) {
                    const recipientWs = clients.get(data.to);
                    recipientWs.send(JSON.stringify({
                        type: 'peer-disconnected',
                        id: currentPeerId,
                        reason: `Peer ${currentPeerId} explicitly disconnected.`
                    }));
                    console.log(`${currentPeerId} explicitly disconnected from ${data.to}.`);
                }
                break;

            default:
                console.warn('Unknown message type:', data.type);
        }
    });

    ws.on('close', () => {
        if (currentPeerId) {
            clients.delete(currentPeerId);
            console.log(`Peer ${currentPeerId} disconnected from signaling server.`);
        } else {
            console.log('Unnamed peer disconnected.');
        }
    });

    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
    });
});

server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
    console.log(`Signaling server also running on ws://localhost:${PORT}`);
});
