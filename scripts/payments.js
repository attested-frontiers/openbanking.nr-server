import dotenv from 'dotenv';
import fs from 'fs';
import axios from 'axios';
import https from 'https';
import crypto from 'crypto';

// Load environment variables
dotenv.config({ path: '../.env' });

console.log(process.env.CLIENT_ID); 

async function getAccessToken() {
    const clientId = process.env.CLIENT_ID; // Load from .env
    const cert = fs.readFileSync('../keys/transport.pem');
    const key = fs.readFileSync('../keys/private.key');

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

async function createDomesticPaymentConsent(paymentData, accessToken, jwsSignature) {
    const url = 'https://sandbox-oba.revolut.com/domestic-payment-consents';

    try {
        const response = await axios.post(url, paymentData, {
            headers: {
                'x-fapi-financial-id': process.env.FINANCIAL_ID, // Replace with your financial ID
                'Content-Type': 'application/json',
                'x-idempotency-key': crypto.randomUUID(),
                'Authorization': `Bearer ${accessToken}`,
                'x-jws-signature': jwsSignature
            },
            httpsAgent: new https.Agent({
                cert: fs.readFileSync('../keys/transport.pem'),
                key: fs.readFileSync('../keys/private.key'),
                rejectUnauthorized: false //need to remove this for prod
            })
        });


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

// Placeholder function for generating JWS; replace with actual implementation

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
        const privateKey = fs.readFileSync('../keys/private.key');

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
// Run the function
//getAccessToken();

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

        const privateKey = fs.readFileSync('../keys/private.key');
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

async function initiateDomesticPayment(paymentData, consentId, accessToken) {
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
        return response.data;
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

function verifyJWS(jws, publicKey) {
    try {
        const [encodedHeader, encodedPayload, encodedSignature] = jws.split('.');

        console.log('verifyJWS: header', encodedHeader);
        console.log('verifyJWS: payload', encodedPayload);
        // Decode the signature
        const signature = Buffer.from(encodedSignature, 'base64');
        console.log('verifyJWS: signature', signature);


        // Reconstruct the data to verify
        const dataToVerify = `${encodedHeader}.${encodedPayload}`;

        // Verify the signature using the public key
        const isVerified = crypto.verify(
            'sha256',
            Buffer.from(dataToVerify),
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: 32
            },
            signature
        );

        console.log('JWS verification result:', isVerified);
        return isVerified;
    } catch (error) {
        console.error('Error verifying JWS:', error);
        return false;
    }
}

// Usage example

// Payment consent payload
const paymentData = {
    Data: {
        Initiation: {
            InstructionIdentification: "ID412",
            EndToEndIdentification: "E2E123",
            InstructedAmount: {
                Amount: "2.50",
                Currency: "GBP"
            },
            CreditorAccount: {
                SchemeName: "UK.OBIE.SortCodeAccountNumber",
                Identification: "11223321325698",
                Name: "Receiver Co."
            },
            RemittanceInformation: {
                Unstructured: "Shipment fee"
            }
        }
    },
    Risk: {
        PaymentContextCode: "EcommerceGoods",
        MerchantCategoryCode: "5967",
        MerchantCustomerIdentification: "1238808123123",
        DeliveryAddress: {
            AddressLine: ["7"],
            StreetName: "Apple Street",
            BuildingNumber: "1",
            PostCode: "E2 7AA",
            TownName: "London",
            Country: "UK"
        }
    }
};






(async () => {
    try {
        console.log('Starting payment consent process...');

        // Get access token
        const accessToken = await getAccessToken();
        if (!accessToken) {
            throw new Error('Failed to get access token');
        }
        console.log('Successfully obtained access token');

        // Generate JWS signature
        const jwsSignature = generateJWSSignature(paymentData);
        if (!jwsSignature) {
            throw new Error('Failed to generate JWS signature');
        }
        console.log('Successfully generated JWS signature');
        fs.writeFileSync('request_consent_jws', jwsSignature);
        console.log('Consent JWS signature saved to file: consent_jws');
        // check jws 
        const publicKey = fs.readFileSync('../keys/signing.pem', 'utf8');
        console.log('publicKey', publicKey);
        verifyJWS(jwsSignature, publicKey);

        // Create payment consent
        const consentResponse = await createDomesticPaymentConsent(paymentData, accessToken, jwsSignature);

        // Generate authorization JWT using the consent ID
        const { jwt, state } = generateAuthorizationJWT(consentResponse.Data.ConsentId);
        console.log('Authorization state (save this):', state);
        fs.writeFileSync('auth_jwt', jwt);
        console.log('Authorization JWT saved to file: auth_jwt');

        // Construct authorization URL with proper URL encoding
        const authParams = new URLSearchParams({
            response_type: 'code id_token',
            scope: 'payments',
            redirect_uri: process.env.REDIRECT_URI,
            client_id: process.env.CLIENT_ID,
            request: jwt,
            response_mode: 'fragment' // Optional but recommended for security
        });

        // Create the final authorization URL
        const authUrl = `https://sandbox-oba.revolut.com/ui/index.html?${authParams.toString()}`;
        console.log('\nAuthorization URL (redirect user to this URL):');
        console.log(authUrl);

        console.log('\nNote: The authorization code will be valid for only 2 minutes after user consent');
        console.log('Expected redirect format after user authorization:');
        console.log(`${process.env.REDIRECT_URI}/?code=<auth_code>&id_token=<JWT_token>&state=${state}`);


        // Add a prompt to continue after user completes authorization
        const readline = await import('readline');
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        // Wait for user to complete authorization
        await new Promise((resolve) => {
            rl.question('\nPress Enter after completing authorization...', () => {
                rl.close();
                resolve();
            });
        });

        // Retrieve the stored token
        console.log('\nRetrieving stored token...');
        const tokenData = await retrieveStoredToken();
        console.log('Retrieved token data:', tokenData);
        console.log('Token retrieved successfully');

        // Initiate the payment
        console.log('\nInitiating payment...');
        const paymentResponse = await initiateDomesticPayment(
            paymentData,
            consentResponse.Data.ConsentId,
            tokenData.access_token
        );
        console.log('\nPayment initiated successfully:');
        console.log('Payment ID:', paymentResponse.Data.DomesticPaymentId);
        console.log('Status:', paymentResponse.Data.Status);
        console.log('full response', paymentResponse);

    } catch (error) {
        console.error('Main execution error:', error.message);
        process.exit(1);
    }
})();
