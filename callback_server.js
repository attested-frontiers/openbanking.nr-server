import express from 'express';
import axios from 'axios';
import fs from 'fs';
import https from 'https';
import dotenv from 'dotenv';
import { createCommitment, getCommitmentByHash } from './commitmentDb.js';

dotenv.config();

let currentToken; 

const app = express();

app.use(express.json());

// Add basic request logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        server: 'callback-server',
        redirect_uri: process.env.REDIRECT_URI
    });
});

// Main callback handler
app.get('/callback', async (req, res) => {
    console.log('Received callback request:', {
        query: req.query,
        headers: req.headers
    });

    res.send(`
        <html>
        <body>
            <h1>Processing Authorization...</h1>
            <div id="result"></div>
            <script>
                // Get the fragment parameters
                const hash = window.location.hash.substring(1);
                const params = new URLSearchParams(hash);
                
                // Log the parameters
                console.log('Code:', params.get('code'));
                console.log('State:', params.get('state'));
                console.log('ID Token:', params.get('id_token'));
                
                // Send to server
                fetch('/process-auth?' + hash)
                    .then(response => response.json())
                    .then(data => {
                        const resultDiv = document.getElementById('result');
                        if (data.error) {
                            resultDiv.innerHTML = '<h2>Error</h2><pre>' + data.error + '</pre>';
                        } else {
                            resultDiv.innerHTML = \`
                                <h2>Authorization Successful!</h2>
                                <p>Access Token Received</p>
                                <p>Token Type: \${data.token_type}</p>
                                <p>Expires in: \${data.expires_in} seconds</p>
                                <p>You can close this window now.</p>
                            \`;
                        }
                    })
                    .catch(error => {
                        document.getElementById('result').innerHTML = 
                            '<h2>Error</h2><pre>' + error.message + '</pre>';
                    });
            </script>
        </body>
        </html>
    `);
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