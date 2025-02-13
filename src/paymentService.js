//import dotenv from 'dotenv';
import fs from 'fs';
import axios from 'axios';
import https from 'https';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const KEYS_DIR = join(__dirname, '..', 'keys');


async function getAccessToken() {
    const clientId = process.env.CLIENT_ID; // Load from .env
    const cert = fs.readFileSync(join(KEYS_DIR, 'transport.pem'));
    const key = fs.readFileSync(join(KEYS_DIR, 'private.key'));

    const url = 'https://sandbox-oba-auth.revolut.com/token';
    const data = new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'payments',
        client_id: clientId
    });

    console.log('clientID', clientId);

    try {
        const response = await axios.post(url, data, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            httpsAgent: new https.Agent({
                cert: cert,
                key: key,
                rejectUnauthorized: false
            })
        });
        console.log('Access Token:', response.data.access_token);
        return response.data.access_token;
    } catch (error) {
        // Enhanced error handling
        if (error.response) {
            console.error('Error fetching access token:', error.response.data);
        } else if (error.request) {
            console.error('No response received:', error.request);
        } else {
            console.error('Error setting up request:', error.message);
        }
    }
}

function generateJWSSignature(payload) {
    try {
        const header = {
            alg: "PS256",
            kid: "2kiXQyo0tedjW2somjSgH7",
            crit: ["http://openbanking.org.uk/tan"],
            "http://openbanking.org.uk/tan": process.env.JWKS_ROOT_DOMAIN
        };
        //console.log('JWS Header:', JSON.stringify(header, null, 2));  
        // Base64URL encode header and payload
        const encodedHeader = Buffer.from(JSON.stringify(header))
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        const encodedPayload = Buffer.from(JSON.stringify(payload))
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        const dataToSign = `${encodedHeader}.${encodedPayload}`;

        // Read private key
        const privateKey = fs.readFileSync(join(KEYS_DIR, 'private.key'));;

        // Create signature using PS256 (SHA-256 with PSS padding)
        const signature = crypto.sign(
            'sha256',
            Buffer.from(dataToSign),
            {
                key: privateKey,
                padding: 6,
                saltLength: 32
            }
        );

        // Convert signature to Base64URL
        const encodedSignature = signature
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        // Return complete JWS
        return `${dataToSign}.${encodedSignature}`;
    } catch (error) {
        console.error('Error generating JWS signature:', error);
        throw error;
    }
}

async function createDomesticPaymentConsent(paymentData, accessToken, jwsSignature) {
    const url = 'https://sandbox-oba.revolut.com/domestic-payment-consents';

    try {
        const request = axios.post(url, paymentData, {
            headers: {
                'x-fapi-financial-id': process.env.FINANCIAL_ID, // Replace with your financial ID
                'Content-Type': 'application/json',
                'x-idempotency-key': crypto.randomUUID(),
                'Authorization': `Bearer ${accessToken}`,
                'x-jws-signature': jwsSignature
            },
            httpsAgent: new https.Agent({
                cert: fs.readFileSync(join(KEYS_DIR, 'transport.pem')),
                key: fs.readFileSync(join(KEYS_DIR, 'private.key')),
                rejectUnauthorized: false //TODO: need to enable this
            })
        });
        console.log('request', request);
        const response = await request; 



        console.log('Payment Consent Headers Response:', response.headers);
        console.log('Payment Consent Data Response:', response.data);
        console.log("jws_signture", response.headers['x-jws-signature']);

        const safeStringify = (obj) => {
            const seen = new WeakSet();
            return JSON.stringify(obj, (key, value) => {
                if (typeof value === 'object' && value !== null) {
                    if (seen.has(value)) {
                        return; // Remove circular references
                    }
                    seen.add(value);
                }
                return value;
            }, 2);
        };

        // Use JSON.stringify to convert the object to a string
        fs.writeFileSync('paymentConsentResponse.json', safeStringify(response));
        //fs.writeFileSync('paymentConsentResponse.json', JSON.stringify(response, null, 2));        
        // Retrieve the JWS signature from the response headers
        // const consentJwsSignature = response.headers['x-jws-signature'];
        // if (consentJwsSignature) {
        //     fs.writeFileSync('response_consent_jws', consentJwsSignature);
        //     console.log('Consent JWS signature saved to file: consent_jws');
        // } else {
        //     console.warn('No JWS signature found in response headers');
        // }
        return response.data;
    } catch (error) {
        console.error('Error creating payment consent', error.response ? error.response.data : error.message);
    }
}

//function to generate JWT for consent authorization
function generateAuthorizationJWT(consentId) {
    try {
        const header = {
            alg: "PS256",
            kid: process.env.KID
        };

        const payload = {
            response_type: "code id_token",
            client_id: process.env.CLIENT_ID,
            redirect_uri: process.env.REDIRECT_URI,
            scope: "payments",
            state: crypto.randomUUID(),
            claims: {
                id_token: {
                    openbanking_intent_id: {
                        value: consentId
                    }
                }
            }
        };

        // Base64URL encode header and payload
        const encodedHeader = Buffer.from(JSON.stringify(header))
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        const encodedPayload = Buffer.from(JSON.stringify(payload))
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        const dataToSign = `${encodedHeader}.${encodedPayload}`;

        const privateKey = fs.readFileSync(join(KEYS_DIR, 'private.key'));
        const signature = crypto.sign(
            'sha256',
            Buffer.from(dataToSign),
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: 32
            }
        );

        const encodedSignature = signature
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        return {
            jwt: `${dataToSign}.${encodedSignature}`,
            state: payload.state
        };
    } catch (error) {
        console.error('Error generating authorization JWT:', error);
        throw error;
    }
}

export async function initializePayment(paymentData) {
    // Get access token
    const accessToken = await getAccessToken();
    
    // Generate JWS signature
    const jwsSignature = generateJWSSignature(paymentData);
    
    // Create payment consent
    const consentResponse = await createDomesticPaymentConsent(paymentData, accessToken, jwsSignature);
    
    // Generate JWT and get state
    const { jwt, state } = generateAuthorizationJWT(consentResponse.Data.ConsentId);
    console.log('JWT state', state);
    
    // Generate authorization URL
    const authParams = new URLSearchParams({
        response_type: 'code id_token',
        scope: 'payments',
        redirect_uri: process.env.REDIRECT_URI,
        client_id: process.env.CLIENT_ID,
        request: jwt,
        response_mode: 'fragment'
    });

    const authUrl = `https://sandbox-oba.revolut.com/ui/index.html?${authParams.toString()}`;
    
    return {
        authUrl,
        state,
        consentId: consentResponse.Data.ConsentId
    };
}



// Function to create payment payload with consent ID
function createPaymentPayload(paymentData, consentId) {
    return {
        Data: {
            ConsentId: consentId,
            ...paymentData.Data
        },
        Risk: paymentData.Risk
    };
}

export async function executeDomesticPayment(paymentData, consentId, accessToken) {
    // Generate JWS signature for the payment payload
    //const jwsSignature = generateJWSSignature(paymentPayload);
    const paymentPayload = createPaymentPayload(paymentData, consentId);
    // Generate new JWS signature for payment payload
    const jwsSignature = generateJWSSignature(paymentPayload);

    try {
        const response = await axios.post(
            'https://sandbox-oba.revolut.com/domestic-payments',
            paymentPayload,
            {
                headers: {
                    'x-fapi-financial-id': process.env.FINANCIAL_ID,
                    'Content-Type': 'application/json',
                    'x-idempotency-key': crypto.randomUUID(),
                    'Authorization': `Bearer ${accessToken}`,
                    'x-jws-signature': jwsSignature
                },
                httpsAgent: new https.Agent({
                    cert: fs.readFileSync('./keys/transport.pem'),
                    key: fs.readFileSync('./keys/private.key'),
                    rejectUnauthorized: false
                })
            }
        );

        console.log('\n=== Payment Initiation Response ===');
        console.log(JSON.stringify(response.data, null, 2));
        console.log('================================\n');

        // Isolate components
        const responseHeaders = response.headers;
        const responseData = response.data;
        const responseJwsSignature = responseHeaders['x-jws-signature'];
        if (responseJwsSignature) {
            console.log('Response JWS Signature:', responseJwsSignature);
        } else {
            console.warn('No JWS signature found in response headers');
        }

        // Structure for saving to a file
        const responseToSave = {
            headers: responseHeaders,
            data: responseData,
            jwsSignature: responseJwsSignature
        };

        // Save to file
        const filePath = './paymentInitResponse.json';
        fs.writeFileSync(filePath, JSON.stringify(responseToSave, null, 2));
        console.log(`Response saved to ${filePath}`);
        //fs.writeFileSync('paymentInitResponse.json', JSON.stringify(response));
        return {...response.data, jwsSignature: responseJwsSignature};
    } catch (error) {
        console.error('Payment initiation error:', {
            status: error.response?.status,
            statusText: error.response?.statusText,
            data: error.response?.data,
            message: error.message
        });
        throw error;
    }
}

// Function to retrieve stored token
async function retrieveStoredToken() {
    try {
        const response = await axios.get('http://localhost:3000/token');
        console.log('Token status:', response.data);
        return response.data;
    } catch (error) {
        console.error('Error retrieving token:', error.response?.data || error.message);
        throw error;
    }
}







