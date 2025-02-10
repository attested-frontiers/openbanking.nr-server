import * as jose from 'jose';
import fs from 'fs';
import https from 'https';
import axios from 'axios';
import * as crypto from 'crypto';
import { Noir } from "@noir-lang/noir_js";

import {  
  OpenBankingDomesticCircuit,
  decodeNoirOutputs,
  generateNoirInputs, 
} from "@openbanking.nr/js-inputs";

// sandbox URI; source: 
const JWKS_URI = 'https://keystore.openbankingtest.org.uk/001580000103UAvAAM/001580000103UAvAAM.jwks';

// HTTPS agent to fetch the JWKS
const agent = new https.Agent({
    ca: [
      fs.readFileSync('./certificates/OB_SandBox_PP_Root CA.cer'),
      fs.readFileSync('./certificates/OB_SandBox_PP_Issuing CA.cer')
    ], 
    rejectUnauthorized: false // Temporarily disable SSL verification until the issue is fixed
  });

// Fetch JWKS
const jwksResponse = await axios.get(JWKS_URI, { httpsAgent: agent });
const jwks = jwksResponse.data;

console.log('jwks', jwks); 

// response data we want to verify. TODO: make it input variable in future to dynamicaly verify responses from revolut
const consentResponse = JSON.parse(fs.readFileSync('paymentInitResponse.json', 'utf8'));
const data = consentResponse.data;
const header = consentResponse.headers; 
const signature = consentResponse.headers['x-jws-signature'];

console.log('data1:', data); 
console.log('header2:', header); 
console.log('signature3:', signature); 


// retrieve kid identifier from the signature 
const decodedSignature = jose.decodeProtectedHeader(signature);
console.log('deocdedSignature: ', decodedSignature); 
const kid = decodedSignature.kid; 
console.log('kid', kid);
console.log('signature', signature);

// check the jwks for corresponding entry for the kid 
const matchingKey = jwks.keys.find(key => key.kid === kid);
console.log('matching keys', matchingKey); 

const x5u = matchingKey.x5u;
console.log('x5u', x5u); 

// Fetch the .pem public key corresponding to signature 
const publicKey = (await axios.get(x5u, { responseType: 'text', httpsAgent: agent })).data;
//const publicKeyObj = crypto.createPublicKey({ key: Buffer.from(publicKey.replace(/-----BEGIN CERTIFICATE-----|\n|-----END CERTIFICATE-----/g, ''), 'base64'), type: 'spki', format: 'der' });
console.log('public key', publicKey);


const encodedHeader = Buffer.from(JSON.stringify(decodedSignature)).toString('base64url');
const rawPayload = Buffer.from(JSON.stringify(data));
//const rawPayload = Buffer.from(JSON.stringify(data)).toString('base64url');


const dataToVerify = `${encodedHeader}.${rawPayload}`;
console.log('dataToVerify', dataToVerify); 


const signatureBuffer = Buffer.from(signature.split('.')[2], 'base64url');

// Verify the signature using the public key
const isVerified = crypto.verify(
    'sha256',
    Buffer.from(dataToVerify),
    {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32
    },
    signatureBuffer
);

console.log('JWS verification result with crypto library:', isVerified);

// start of using the ob circuit js api 
let { publicKey: cert } = new crypto.X509Certificate(publicKey);
console.log("public key", publicKey)
const inputs = generateNoirInputs(dataToVerify, signatureBuffer.toString('hex'), cert); 
const noir = new Noir(OpenBankingDomesticCircuit)
const result = await noir.execute({params: inputs });
const outputs = decodeNoirOutputs(result.returnValue);
console.log('JWS verification with Noir cicrcuits', outputs);


;