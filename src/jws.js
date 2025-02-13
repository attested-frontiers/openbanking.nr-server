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
import ocsp from 'ocsp';

// Constants
const JWKS_URI = 'https://keystore.openbankingtest.org.uk/001580000103UAvAAM/001580000103UAvAAM.jwks';
const CERTIFICATES_PATH = './certificates/';

// Create HTTPS agent
export function createHttpsAgent() {
  return new https.Agent({
    ca: [
      fs.readFileSync(`${CERTIFICATES_PATH}OB_SandBox_PP_Root CA.cer`),
      fs.readFileSync(`${CERTIFICATES_PATH}OB_SandBox_PP_Issuing CA.cer`)
    ],
    rejectUnauthorized: false
  });
}

// Fetch JWKS
export async function fetchJwks(agent) {
  const response = await axios.get(JWKS_URI, { httpsAgent: agent });
  return response.data;
}

// Extract public key from signature
export async function extractPublicKey(signature) {
  const agent = createHttpsAgent();
  const jwks = await fetchJwks(agent);
  const decodedSignature = jose.decodeProtectedHeader(signature);
  const kid = decodedSignature.kid;
  const matchingKey = jwks.keys.find(key => key.kid === kid);
  const x5u = matchingKey.x5u;
  const publicKey = (await axios.get(x5u, { responseType: 'text', httpsAgent: agent })).data;
  return new crypto.X509Certificate(publicKey);
}

// TODO: add function verify JWS signature + generate noir proofs and circuit inputs + verify noir proofs

// // Verify JWS signature. Could this be done with verifySignature(JWS object) ? 
// function verifySignature(dataToVerify, signature, publicKey) {
//   const signatureBuffer = Buffer.from(signature.split('.')[2], 'base64url');
//   return crypto.verify(
//     'sha256',
//     Buffer.from(dataToVerify),
//     {
//       key: publicKey,
//       padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
//       saltLength: 32
//     },
//     signatureBuffer
//   );
// }

// // Prepare inputs for Noir circuit
// function prepareNoirInputs(dataToVerify, signatureBuffer, publicKey) {
//   const inputs = generateNoirInputs(dataToVerify, signatureBuffer.toString('hex'), publicKey);
//   const noir = new Noir(OpenBankingDomesticCircuit);
//   return noir.execute({ params: inputs });
// }

// // Main function to verify JWS and prepare inputs
// async function verifyAndPrepareInputs(signature, consentResponse) {
//   const agent = createHttpsAgent();
//   const jwks = await fetchJwks(agent);
//   const publicKeyCert = await extractPublicKey(signature, jwks, agent);

//   const data = consentResponse.data;
//   const encodedHeader = Buffer.from(JSON.stringify(jose.decodeProtectedHeader(signature))).toString('base64url');
//   const rawPayload = Buffer.from(JSON.stringify(data));
//   const dataToVerify = `${encodedHeader}.${rawPayload}`;

//   const isVerified = verifySignature(dataToVerify, signature, publicKeyCert.publicKey);
//   console.log('JWS verification result with crypto library:', isVerified);

//   if (isVerified) {
//     const signatureBuffer = Buffer.from(signature.split('.')[2], 'base64url');
//     const result = await prepareNoirInputs(dataToVerify, signatureBuffer, publicKeyCert.publicKey);
//     const outputs = decodeNoirOutputs(result.returnValue);
//     console.log('JWS verification with Noir circuits', outputs);
//   }
// }

// // Example usage
// const consentResponse = JSON.parse(fs.readFileSync('paymentInitResponse.json', 'utf8'));
// const signature = consentResponse.headers['x-jws-signature'];
// verifyAndPrepareInputs(signature, consentResponse);