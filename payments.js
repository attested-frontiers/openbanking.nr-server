require('dotenv').config();
const fs = require('fs');
const axios = require('axios');
const https = require('https');
const crypto = require('crypto');

async function getAccessToken() {
    const clientId = process.env.CLIENT_ID; // Load from .env
    const cert = fs.readFileSync('./keys/transport.pem');
    const key = fs.readFileSync('./keys/private.key');

    const url = 'https://sandbox-oba-auth.revolut.com/token';
    const data = new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'payments',
        client_id: clientId
    });

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
                cert: fs.readFileSync('./keys/transport.pem'),
                key: fs.readFileSync('./keys/private.key'),
                rejectUnauthorized: false //need to remove this for prod
            })
        });

        console.log('Payment Consent Response:', response.data);
        return response.data;
    } catch (error) {
        console.error('Error creating payment consent:', error.response ? error.response.data : error.message);
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
        console.log('JWS Header:', JSON.stringify(header, null, 2));  
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
        const privateKey = fs.readFileSync('./keys/private.key');

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


// Usage example

// Payment consent payload
const paymentData = {
    Data: {
        Initiation: {
            InstructionIdentification: "ID412",
            EndToEndIdentification: "E2E123",
            InstructedAmount: {
                Amount: "55.00",
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

        // Create payment consent
        const consentResponse = await createDomesticPaymentConsent(paymentData, accessToken, jwsSignature);
        console.log('Payment consent created successfully:', consentResponse);

    } catch (error) {
        console.error('Main execution error:', error.message);
        process.exit(1);
    }
})();
