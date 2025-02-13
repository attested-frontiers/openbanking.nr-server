import http from 'http';
import express from 'express';
import dotenv from 'dotenv';
import { WebSocketServer } from 'ws';
import axios from 'axios';
import fs from 'fs';
import https from 'https';
import cors from 'cors';
import { initializePayment, executeDomesticPayment } from './paymentService.js';
import { createCommitment, getCommitmentByHash, getAllCommitments } from './commitmentDb.js';

dotenv.config();

let currentToken;
const stateStore = {}; 

const app = express();
app.use(express.json());
app.use(cors());

// Add basic request logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});

// Serve static files from the src directory
app.use(express.static('src'));

// Create an HTTP server from the Express app
const server = http.createServer(app);

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
        const state = crypto.randomUUID();
        stateStore[state] = {consentId, paymentData};
        res.json(result);
    } catch (error) {
        console.error('Payment initiation error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST endpoint to create a commitment
app.post('/commitment', async (req, res) => {
    try {
        const { hash, accountNumber, sortCode, amount, salt } = req.body;
        const commitment = await createCommitment({ 
            hash, 
            accountNumber, 
            sortCode, 
            amount, 
            salt 
        });
        res.status(201).json(commitment);
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
app.get('/commitments', async (req, res) => {
    try {
        const commitments = await getAllCommitments();
        res.json(commitments);
    } catch (error) {
        res.status(500).json({ 
            error: 'Failed to retrieve commitments', 
            details: error.message 
        });
    }
});

// Main callback handler
app.get('/callback', (req, res) => {
    console.log('Received callback request:', {
        query: req.query,
        headers: req.headers
    });

    res.sendFile('callback.html', { root: 'src' });
});


// Process the auth code
app.get('/process-auth', async (req, res) => {
    const { code, id_token } = req.query;
    
    console.log('\n=== Authorization Data ===');
    console.log('Code:', code);
    console.log('ID Token:', id_token);
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
        res.json(tokenResponse);
        // Send WebSocket update
        broadcast({ message: 'Authorization successful', token: tokenResponse });
        // Retrieve the consentId and paymentData using the state
        //const { consentId, paymentData } = retrieveConsentIdAndPaymentDataByState(state);
        const { consentId, paymentData } = stateStore[state];
        const paymentResponse = await executeDomesticPayment(paymentData, consentId, tokenResponse.access_token);
        res.json(paymentResponse);
        // Send WebSocket update
        broadcast({ message: 'Payment initiated', paymentResponse });

    } catch (error) {
        console.error('Token exchange error:', error);
        res.json({ 
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

// // New endpoint to initiate payment after auth
// app.post('/execute-payment', async (req, res) => {
//     try {
//         const { paymentData, consentId } = req.body;
//         const tokenData = currentToken; // Assuming token is already stored
//         const paymentResponse = await initiateDomesticPayment(paymentData, consentId, tokenData.access_token);
        
//         res.json(paymentResponse);

//         // Send WebSocket update
//         broadcast({ message: 'Payment initiated', paymentResponse });
//     } catch (error) {
//         console.error('Payment initiation error:', error);
//         res.status(500).json({ error: error.message });
//     }
// });

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

// function retrieveConsentIdAndPaymentDataByState(state) {
//     return stateStore[state] || {};
// }

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`\n=== Server Started ===`);
    console.log(`Local URL: http://localhost:${PORT}`);
    console.log(`Callback URL: ${process.env.REDIRECT_URI}`);
    console.log(`\nTest endpoints:`);
    console.log(`1. Health check: curl http://localhost:${PORT}/health`);
    console.log(`2. Callback URL: ${process.env.REDIRECT_URI}`);
    console.log(`========================\n`);
});

// export for testing purposes
export default app;