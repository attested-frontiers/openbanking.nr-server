import fs from 'fs';
import axios from 'axios';
import https from 'https';
import dotenv from 'dotenv';


// Load environment variables
dotenv.config();

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


async function retrieveAndCheckPaymentStatus() {
    try {
        // Read saved payment response
        const savedResponse = JSON.parse(fs.readFileSync('./paymentInitResponse.json', 'utf8'));
        const paymentId = savedResponse.data.Data.DomesticPaymentId;

        // Get fresh access token
        const accessToken = await getAccessToken();

        // Check payment status with more comprehensive configuration
        const response = await axios.get(
            `https://sandbox-oba.revolut.com/domestic-payments/${paymentId}`,
            {
                headers: {
                    'x-fapi-financial-id': process.env.FINANCIAL_ID,
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/json'
                },
                httpsAgent: new https.Agent({
                    cert: fs.readFileSync('./keys/transport.pem'),
                    key: fs.readFileSync('./keys/private.key'),
                    rejectUnauthorized: false
                })
            }
        );
        // Log and save full response details
        console.log('=== Full Payment Status Response ===');
        console.log(JSON.stringify(response.data, null, 2));

        // Save response data to a file
        const responseDetails = {
            headers: response.headers,
            data: response.data,
            status: response.status
        };

        // Save full response
        fs.writeFileSync('paymentStatusResponse.json', JSON.stringify(responseDetails, null, 2));

        // Save signature if present in headers
        const signature = response.headers['x-jws-signature'];
        if (signature) {
            fs.writeFileSync('payment_status_signature', signature);
            console.log('Payment Status Signature saved to: payment_status_signature');
        }

        console.log('\nPayment Status:', response.data.Data.Status);
        return response.data;
    } catch (error) {
        console.error('Error checking payment status:', 
            error.response ? JSON.stringify(error.response.data, null, 2) : error.message
        );
        throw error;
    }
}

retrieveAndCheckPaymentStatus(); 

// // If run directly
// if (import.meta.url === `file://${process.argv[1]}`) {
//     retrieveAndCheckPaymentStatus()
//         .then(status => console.log(status))
//         .catch(error => console.error(error));
// }

// export { retrieveAndCheckPaymentStatus };