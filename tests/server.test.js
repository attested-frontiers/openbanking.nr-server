import supertest from 'supertest';
import { createServer } from 'http';
import app from '../src/server.js'; // Update this with your actual app import path
import { jest } from '@jest/globals';
import crypto from 'crypto';

const TEST_PORT = 3002;
const server = createServer(app);
let request;

// const serverUrl = 'http://localhost:3001'; // Replace with your live server URL
// const request = supertest(serverUrl);

// // Create a test server instance to use for testing
// let server;

beforeAll(async () => {
    await new Promise(resolve => {
      server.listen(TEST_PORT, () => {
        request = supertest(`http://localhost:${TEST_PORT}`);
        resolve();
      });
    });
});

afterAll(async () => {
    await new Promise(resolve => {
      server.close(() => {
        resolve();
      });
    });
});

describe('Server Tests', () => {

    const testData = {
        commitment: null  // Will store the commitment data after creation
    };


    it('should respond to /ping with "pong"', async () => {
        const response = await request.get('/ping');
        expect(response.status).toBe(200);
        expect(response.body.message).toBe('pong');
    });

    it('should respond to /health with server health status', async () => {
        const response = await request.get('/health');
        expect(response.status).toBe(200);
        expect(response.body.status).toBe('ok');
    });

    // it('should return 500 for /health if database is down', async () => {
    //     // Simulate DB failure by stubbing/checking `checkDbHealth` function here
    //     const response = await request.get('/health');
    //     expect(response.status).toBe(500);
    //     expect(response.body.status).toBe('error');
    //     expect(response.body.message).toBe('Database is down');
    // });

    it('should create a commitment with valid data', async () => {
        const salt = crypto.randomBytes(16).toString('hex');
        const commitmentData = {
          hash: crypto.createHash('sha256')
            .update(`12345678${salt}`)
            .digest('hex'),
          accountNumber: '12345678',
          sortCode: '12-34-56',
          amount: 100.50,
          salt: salt
        };
        // Store the commitment data for use in subsequent tests
        testData.commitment = commitmentData;
        const response = await request.post('/commitment')
            .send(commitmentData);
        
        expect(response.status).toBe(201);
        expect(response.body).toHaveProperty('hash', commitmentData.hash);
        expect(response.body).toHaveProperty('accountNumber', commitmentData.accountNumber);
        expect(response.body).toHaveProperty('sortCode', commitmentData.sortCode);
    });

    it('should retrieve a commitment by hash', async () => {
        // Make sure this hash exists in your database beforehand, or mock the DB call

        if (!testData.commitment) {
            console.log('Skipping test: no commitment data available');
            return;
        }
        const response = await request.get(`/commitment/${testData.commitment.hash}`);
        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('hash', testData.commitment.hash);
    });

    it('should return 404 if commitment not found by hash', async () => {
        const response = await request.get('/commitment/nonexistenthash');
        expect(response.status).toBe(404);
        expect(response.body.error).toBe('Commitment not found');
    });

    // it('should retrieve all commitments', async () => {
    //     const response = await request.get('/commitments');
    //     expect(response.status).toBe(200);
    //     expect(Array.isArray(response.body)).toBe(true);
    // });

    it('should respond to /api/initialize-payment with payment result', async () => {
        const paymentData = {
            "Data": {
                "Initiation": {
                    "InstructionIdentification": "ID412",
                    "EndToEndIdentification": "E2E123",
                    "InstructedAmount": {
                        "Amount": "2.50",
                        "Currency": "GBP"
                    },
                    "CreditorAccount": {
                        "SchemeName": "UK.OBIE.SortCodeAccountNumber",
                        "Identification": "11223321325698",
                        "Name": "Receiver Co."
                    },
                    "RemittanceInformation": {
                        "Unstructured": "Shipment fee"
                    }
                }
            },
            "Risk": {
                "PaymentContextCode": "EcommerceGoods",
                "MerchantCategoryCode": "5967",
                "MerchantCustomerIdentification": "1238808123123",
                "DeliveryAddress": {
                    "AddressLine": ["7"],
                    "StreetName": "Apple Street",
                    "BuildingNumber": "1",
                    "PostCode": "E2 7AA",
                    "TownName": "London",
                    "Country": "UK"
                }
            }
        };

        const response = await request
            .post('/api/initialize-payment')
            .set('Content-Type', 'application/json')
            .send(paymentData);
        
        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('authUrl');
    });

    // it('should return 500 for /api/initialize-payment if there is an error', async () => {
    //     // Simulate payment error by using invalid data or mocking failure
    //     const invalidPaymentData = { amount: -100 }; // Invalid data for example
    //     const response = await request.post('/api/initialize-payment')
    //         .send(invalidPaymentData);

    //     expect(response.status).toBe(500);
    //     expect(response.body.error).toBeDefined();
    // });
});

