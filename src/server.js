import http from 'http';
import express from 'express';
import dotenv from 'dotenv';
import { WebSocketServer } from 'ws';
import axios from 'axios';
import fs from 'fs';
import https from 'https';
import cors from 'cors';
import * as jose from 'jose';
import { randomUUID } from 'crypto';
import { initializePayment, executeDomesticPayment } from './paymentService.js';
import { createCommitment, getCommitmentByHash, getAllCommitments, purgeCommitments } from './commitmentDb.js';
import { generatePubkeyParams, generateNoirInputs } from "@openbanking.nr/js-inputs";
import { extractPublicKey } from './jws.js';
import StateManager from './stateManager.js';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
dotenv.config();

// i added a comment

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);



let currentToken;

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(__dirname + 'static', { dotfiles: 'allow' }));
// Add basic request logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});

const stateManager = new StateManager();

// Serve static files from the src directory
app.use(express.static('src'));

// Create an HTTP server from the Express app
let server;
let port = 80;
if (process.env.PRODUCTION == 'true') {
    const sslPath = `/etc/letsencrypt/live/${process.env.SSL_DOMAIN}`;
    const key = fs.readFileSync(`${sslPath}/privkey.pem`, 'utf-8');
    const cert = fs.readFileSync(`${sslPath}/fullchain.pem`, 'utf-8');
    const credentials = { key, cert };
    server = https.createServer(credentials, app);
    port = 443;
} else {
    server = http.createServer(app);
}
// Create a WebSocket server that shares the same HTTP server
const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
    console.log('Client connected to WebSocket');

    // Send a welcome message
    ws.send(JSON.stringify({ message: 'Welcome! You are connected to the WebSocket server.' }));

    // Optionally, handle incoming messages from the client
    ws.on('message', (message) => {
        console.log('Received from client:', message);
    });
});

// Helper function to broadcast a message to all connected WebSocket clients
function broadcast(data) {
    const message = JSON.stringify(data);
    wss.clients.forEach((client) => {
        if (client.readyState === client.OPEN) {
            client.send(message);
        }
    });
}

// Simple ping endpoint to check if the server is alive
app.get('/ping', (req, res) => {
    res.json({ message: 'pong' });
});

// Health check endpoint to check if the server is healthy
app.get('/health', async (req, res) => {
    try {
        // Check critical service health (e.g., database, third-party APIs)
        // TODO: add database health tests
        const isDbHealthy = 1;
        if (!isDbHealthy) {
            return res.status(500).json({ status: 'error', message: 'Database is down' });
        }
        res.json({ status: 'ok', message: 'Server is healthy' });
    } catch (error) {
        res.status(500).json({ status: 'error', message: error.message });
    }
});

// POST endpoint to initialize payment
app.post('/api/initialize-payment', async (req, res) => {
    try {
        const paymentData = req.body;
        const result = await initializePayment(paymentData);
        const consentId = result.consentId;
        const state = result.state; // Use the state from the result

        // Store state with consentId and paymentData
        stateManager.store(state, {
            consentId,
            paymentData
        });

        // Log to verify storage
        const storedData = stateManager.get(state);
        console.log("Stored consentId:", storedData.consentId);
        console.log("Stored paymentData:", storedData.paymentData);

        res.json({ ...result, state }); // Include state in the response
    } catch (error) {
        console.error('Payment initiation error:', error);
        broadcast({ message: 'Payment initiation failed', error: error.message });
        res.status(500).json({ error: error.message });
    }
});

// POST endpoint to create a commitment
app.post('/commitment', async (req, res) => {
    try {
        // const { hash, accountNumber, sortCode, amount, salt } = req.body;
        const { commitment, sortCode } = req.body;
        await createCommitment({
            commitment,
            sortCode
        });
        res.status(201).send({ message: "Commitment created successfully" });
    } catch (error) {
        res.status(500).json({
            error: 'Failed to create commitment',
            details: error.message
        });
    }
});

// GET endpoint to retrieve a commitment by hash
app.get('/commitment/:hash', async (req, res) => {
    try {
        const commitment = await getCommitmentByHash(req.params.hash);
        if (!commitment) {
            return res.status(404).json({ error: 'Commitment not found' });
        }
        res.json(commitment);
    } catch (error) {
        res.status(500).json({
            error: 'Failed to retrieve commitment',
            details: error.message
        });
    }
});

// GET endpoint to retrieve all commitments
app.get('/commitments', async (_, res) => {
    try {
        const commitments = await getAllCommitments();
        console.log("commitments", commitments);
        res.json(commitments);
    } catch (error) {
        res.status(500).json({
            error: 'Failed to retrieve commitments',
            details: error.message
        });
    }
});


app.get('/commitments/purge', async (_, res) => {
    try {
        await purgeCommitments();
        res.status(204).json({ message: "All commitments purged successfully" });
    } catch (error) {
        res.status(500).json({ error: "Failed to purge commitments", details: error.message });
    }
});

// Main callback handler
app.get('/callback', async (req, res) => {
    console.log('Received callback request:', {
        query: req.query,
        headers: req.headers
    });
    res.sendFile('callback.html', { root: 'src' });
});



// Process the auth code
app.get('/process-auth', async (req, res) => {
    const { code, id_token, state } = req.query;

    console.log('\n=== Authorization Data ===');
    console.log('Code:', code);
    console.log('ID Token:', id_token);
    console.log('State:', state);
    console.log('========================\n');

    if (!code) {
        return res.json({ error: 'No authorization code received' });
    }

    try {
        const tokenResponse = await exchangeCodeForToken(code);
        console.log('\n=== Token Response ===');
        console.log(JSON.stringify(tokenResponse, null, 2));
        // Store token with state
        currentToken = tokenResponse;
        console.log('Token stored successfully');
        console.log('=====================\n');

        // Send WebSocket update for successful authorization
        broadcast({ message: 'Authorization successful', token: tokenResponse });

        // Retrieve the consentId and paymentData using the state
        const stateData = stateManager.get(state);
        if (!stateData) {
            return res.status(400).json({
                error: 'Invalid or expired state',
                message: 'Please reinitiate the payment flow'
            });
        }

        const { consentId, paymentData } = stateData;
        console.log("ConsentId:", consentId);
        console.log("PaymentData:", paymentData);

        const paymentResponse = await executeDomesticPayment(paymentData, consentId, tokenResponse.access_token);

        res.json(paymentResponse);
        // Send WebSocket update
        broadcast({ message: 'Payment initiated', paymentResponse });

    } catch (error) {
        console.error('Token exchange error:', error);
        broadcast({ message: 'Payment failed', error: error.message });
        res.status(500).json({
            error: `Failed to exchange code for token: ${error.message}`,
            details: error.response?.data
        });

    }
});

// Endpoint to retrieve stored token
app.get('/token', (req, res) => {
    const { state } = req.params;
    console.log('Retrieving token');

    if (!currentToken) {
        return res.status(404).json({
            error: 'Token not found',
            message: `No token found for state: ${state}`
        });
    }

    res.json(currentToken);
});

// Debug endpoint
app.get('/token-status', (req, res) => {
    res.json({
        hasToken: !!currentToken,
        tokenType: currentToken?.token_type,
        expiresIn: currentToken?.expires_in,
        accessTokenPreview: currentToken ? `${currentToken.access_token.substring(0, 20)}...` : null
    });
});

// New endpoint to initiate payment after auth
app.post('/execute-payment', async (req, res) => {
    try {
        const { paymentData, consentId } = req.body;
        const tokenData = currentToken; // Assuming token is already stored
        const paymentResponse = await executeDomesticPayment(paymentData, consentId, tokenData.access_token);

        res.json(paymentResponse);

    } catch (error) {
        console.error('Payment initiation error:', error);
        res.status(500).json({ error: error.message });
    }
});

async function exchangeCodeForToken(code) {
    const url = 'https://sandbox-oba-auth.revolut.com/token';
    const data = new URLSearchParams({
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': process.env.REDIRECT_URI
    });

    console.log('\n=== Token Exchange Request ===');
    console.log('URL:', url);
    console.log('Data:', Object.fromEntries(data));
    console.log('========================\n');

    try {
        const response = await axios.post(url, data, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            httpsAgent: new https.Agent({
                cert: fs.readFileSync('./keys/transport.pem'),
                key: fs.readFileSync('./keys/private.key'),
                rejectUnauthorized: false
            })
        });

        return response.data;
    } catch (error) {
        console.error('Detailed error:', {
            status: error.response?.status,
            statusText: error.response?.statusText,
            data: error.response?.data,
            message: error.message
        });
        throw error;
    }
}

// POST endpoint to extract public key in a format for noir input
app.post('/extract-public-key', async (req, res) => {
    try {
        const { signature } = req.body;
        if (!signature) {
            return res.status(400).json({ error: 'Signature is required' });
        }
        const publicKeyCert = await extractPublicKey(signature);

        res.json({ publicKey: generatePubkeyParams(publicKeyCert.publicKey) });
    } catch (error) {
        console.error('Error extracting public key:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST endpoint to generate Noir inputs
app.post('/noir-inputs', async (req, res) => {
    try {
        const { rawPayload, signature } = req.body;
        if (!signature || !rawPayload) {
            return res.status(400).json({ error: 'Signature and dataToVerify are required' });
        }
        console.log('body', req.body);
        const decodedSignature = jose.decodeProtectedHeader(signature);
        const encodedHeader = Buffer.from(JSON.stringify(decodedSignature)).toString('base64url');
        const dataToVerify = `${encodedHeader}.${rawPayload}`;
        console.log("dataToVerify", dataToVerify);

        // Extract public key
        const publicKeyCert = await extractPublicKey(signature);
        console.log('publicKeyCert', publicKeyCert.publicKey);

        // Generate Noir inputs
        const signatureBuffer = Buffer.from(signature.split('.')[2], 'base64url');
        const inputs = generateNoirInputs(dataToVerify, signatureBuffer.toString('hex'), publicKeyCert.publicKey);

        res.json({ inputs });
    } catch (error) {
        console.error('Error generating Noir inputs:', error);
        res.status(500).json({ error: error.message });
    }
});
// function retrieveConsentIdAndPaymentDataByState(state) {
//     return stateStore[state] || {};
// }

//const PORT = 3000;
server.listen(port, () => {
    console.log(`\n=== Server Started ===`);
    if (port == 80) {
        console.log('Started HTTP Server');
    } else {
        console.log('Started HTTPS Server');
    }
    console.log(`Callback URL: ${process.env.REDIRECT_URI}`);
    console.log(`\nTest endpoints:`);
    console.log(`1. Health check: curl http://localhost:${port}/health`);
    console.log(`2. Callback URL: ${process.env.REDIRECT_URI}`);
    console.log(`========================\n`);
});

// export for testing purposes
export default app;
