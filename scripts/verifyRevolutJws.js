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
import { parse } from 'path';

import ocsp from'ocsp'; 

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


const cert = new crypto.X509Certificate(publicKey); 
// Print ALL available information
console.log('Full Certificate Details:');
console.log(JSON.stringify(cert.toJSON(), null, 2));
// You can also access specific fields:
console.log('\nKey Properties:');
console.log({
    subject: cert.subject,
    issuer: cert.issuer,
    issuerCertificate: cert.issuerCertificate,
    validFrom: cert.validFrom,
    validTo: cert.validTo,
    serialNumber: cert.serialNumber,
    keyUsage: cert.keyUsage,
    extensions: cert.extensions,
    publicKey: cert.publicKey, 
    signature: cert.raw, 
    ca: cert.ca, 
    infoAccess: cert.infoAccess, 
    subjectAltName: cert.subjectAltName, 
});


const issuingCACert = await axios.get('http://ob.trustis.com/ob_pp_issuingca.crt', {
  responseType: 'arraybuffer'  // Important to get binary data
});
// Convert to certificate object
const issuerCert = new crypto.X509Certificate(issuingCACert.data);
console.log('Issuing CA Certificate Details:');
console.log({
  subject: issuerCert.subject,
  issuer: issuerCert.issuer,
  issuerCertificate: issuerCert.issuerCertificate,
  validFrom: issuerCert.validFrom,
  validTo: issuerCert.validTo,
  serialNumber: issuerCert.serialNumber,
  keyUsage: issuerCert.keyUsage,
  extensions: issuerCert.extensions,
  publicKey: issuerCert.publicKey, 
  signature: issuerCert.raw, 
  ca: issuerCert.ca, 
  infoAccess: issuerCert.infoAccess, 
  subjectAltName: issuerCert.subjectAltName, 
}); 

const infoAccessLines = issuerCert.infoAccess.split('\n');
const ocspLine = infoAccessLines.find(line => line.startsWith('OCSP - URI:'));
if (!ocspLine) {
  console.error('No OCSP URI found in the certificate.');
  process.exit(1);
}
const ocspURI = ocspLine.split('OCSP - URI:')[1].trim();
console.log('OCSP Responder URI:', ocspURI);

// --- 2. Generate the OCSP request ---
// The ocsp.request.generate() function needs the DER-encoded buffers of the target certificate and the issuer certificate.
const ocspReq = ocsp.request.generate(cert.raw, issuerCert.raw);

// --- 3. Send the OCSP request ---
const ocspOptions = {
  url: ocspURI,
  ocsp: ocspReq.data
  // Optionally, you can include a custom agent or other request options if necessary.
};

ocsp.request.send(ocspOptions, ocspReq.data, (reqErr, rawOCSPResponse) => {
  if (reqErr) {
    console.error('Error during OCSP request:', reqErr);
    return;
  }
  console.log('Received raw OCSP response');

  ocsp.verify(
    { request: ocspReq, response: rawOCSPResponse, issuer: issuerCert.raw },
    (verifyErr, ocspResult) => {
      if (verifyErr) {
        console.error('OCSP verification error:', verifyErr);
      } else {
        console.log('OCSP verification result:', ocspResult);
      }
    }
  );
});


// async function checkOCSP(cert, issuerCert) {
//     const ocspReq = crypto.createOCSPRequest({
//       cert: cert,          // Your certificate
//       issuer: issuerCert  // The CA certificate
//   });
//     // Send request to OCSP responder
//   const OCSPresponse = await axios.post('http://ob.trustis.com/ocsp', ocspReq, {
//     headers: {
//         'Content-Type': 'application/ocsp-request'
//     },
//     responseType: 'arraybuffer'
//   });

//   // Parse OCSP response
//   const ocspRes = crypto.parseOCSPResponse(OCSPresponse.data);
//   console.log('OCSP Response:', {
//     status: ocspRes.status,  // 'good', 'revoked', or 'unknown'
//     producedAt: ocspRes.producedAt,
//     thisUpdate: ocspRes.thisUpdate,
//     nextUpdate: ocspRes.nextUpdate,
//     revocationTime: ocspRes.revocationTime,  // if revoked
//     revocationReason: ocspRes.revocationReason  // if revoked
//   });
// }

// checkOCSP(cert, issuerCert); 




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

// // start of using the ob circuit js api 
// let { publicKey: cert } = new crypto.X509Certificate(publicKey);
// console.log("public key", publicKey)
// const inputs = generateNoirInputs(dataToVerify, signatureBuffer.toString('hex'), cert); 
// const noir = new Noir(OpenBankingDomesticCircuit)
// const result = await noir.execute({params: inputs });
// const outputs = decodeNoirOutputs(result.returnValue);
// console.log('JWS verification with Noir cicrcuits', outputs);


