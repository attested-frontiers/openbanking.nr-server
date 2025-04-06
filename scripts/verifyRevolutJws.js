import * as jose from 'jose';
import fs from 'fs';
import https from 'https';
import axios from 'axios';
import ocsp from'ocsp'; 
import forge from 'node-forge';
import * as crypto from 'crypto';
import { getCertStatus , getRawOCSPResponse} from 'easy-ocsp';
import { Noir } from "@noir-lang/noir_js";
import {  
  OpenBankingDomesticCircuit,
  decodeNoirOutputs,
  generateNoirInputs, 
} from "@openbanking.nr/js-inputs";


/******************************************************************************
 * CONFIGURATION
 ******************************************************************************/
const CONFIG = {
  jwksUri: 'https://keystore.openbankingtest.org.uk/001580000103UAvAAM/001580000103UAvAAM.jwks',
  agent: new https.Agent({
    rejectUnauthorized: false // for production, should be true and use certificates
  })
};

/******************************************************************************
 * UTILITY FUNCTIONS
 ******************************************************************************/

function extractCAIssuerURL(infoAccess) {
    // Split the string by newline and find the CA Issuers line
    const lines = infoAccess.split('\n');
    const caIssuerLine = lines.find(line => line.includes('CA Issuers - URI:'));
    
    if (caIssuerLine) {
        // Extract the URL after "CA Issuers - URI:"
        return caIssuerLine.split('CA Issuers - URI:')[1].trim();
    }
    
    return null;
}

// function extractTBSCertificate(cert) {
//     const certRaw = cert.raw;
//     const tbsCertificate = certRaw.slice(4, certRaw.length - 256); // Adjust slice indices as needed
//     return tbsCertificate;
// }

async function fetchJWKS(jwksUri, agent) {
  const jwksResponse = await axios.get(jwksUri, { httpsAgent: agent });
  return jwksResponse.data;
}

async function loadResponseFromFile(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}


/******************************************************************************
 * CERTIFICATE FUNCTIONS
 ******************************************************************************/

// Compare the issuing CA certificate in the JWS with the one from the OB website we have stored in /certificates. They should match.
async function compareIssuingCACertificates(onlineCertURL) {
    try {
        // Certificates come from this link: https://openbanking.atlassian.net/wiki/spaces/DZ/pages/252018873/OB+Root+and+Issuing+Certificates+for+Sandbox
        const storedCertData = fs.readFileSync("../certificates/OB_SandBox_PP_Issuing CA.cer");
        const storedCert = new crypto.X509Certificate(storedCertData);

        // Fetch the online certificate
        const onlineCertResponse = await axios.get(onlineCertURL, {
            responseType: 'arraybuffer'
        });
        const onlineCert = new crypto.X509Certificate(onlineCertResponse.data);

        // Compare critical certificate properties
        const comparisonResults = {
            subject: storedCert.subject === onlineCert.subject,
            issuer: storedCert.issuer === onlineCert.issuer,
            serialNumber: storedCert.serialNumber === onlineCert.serialNumber,
            validFrom: storedCert.validFrom === onlineCert.validFrom,
            validTo: storedCert.validTo === onlineCert.validTo,
            // Compare raw signatures
            signatureMatch: Buffer.from(storedCert.raw).equals(Buffer.from(onlineCert.raw)),
            rawMatch: Buffer.from(storedCert.raw).equals(Buffer.from(onlineCert.raw))

            // Compare public keys
            //publicKeyMatch: Buffer.from(storedCert.publicKey).equals(Buffer.from(onlineCert.publicKey))
        };

        // Detailed comparison information
        console.log('Certificate Comparison Results:', comparisonResults);

        // Log detailed information if certificates don't match
        if (!Object.values(comparisonResults).every(result => result === true)) {
            console.log('\nDetailed Certificate Information:');
            console.log('\nStored Certificate:');
            console.log({
                subject: storedCert.subject,
                issuer: storedCert.issuer,
                serialNumber: storedCert.serialNumber,
                validFrom: storedCert.validFrom,
                validTo: storedCert.validTo
            });

            console.log('\nOnline Certificate:');
            console.log({
                subject: onlineCert.subject,
                issuer: onlineCert.issuer,
                serialNumber: onlineCert.serialNumber,
                validFrom: onlineCert.validFrom,
                validTo: onlineCert.validTo
            });
        }

        // Return true if all comparisons pass
        return Object.values(comparisonResults).every(result => result === true);

    } catch (error) {
        console.error('Error comparing certificates:', error);
        throw error;
    }
}

async function extractCertificateFromResponse(response, jwks) {
  const responseInfo = await extractResponseInfo(response, jwks);
  return new crypto.X509Certificate(responseInfo.publicKey);
}

async function getIssuerCertificate(cert) {
  const certURL = extractCAIssuerURL(cert.infoAccess);
  const issuerCACertRaw = await axios.get(certURL, {
    responseType: 'arraybuffer'
  });
  return new crypto.X509Certificate(issuerCACertRaw.data);
}

// Function to verify that cert is signed by issuerCACert
function verifyCertificate(cert, issuerCACert) {
  try {
      // Extract the issuer's public key
      const issuerPublicKey = issuerCACert.publicKey;

      // Verify the signature
      const isValid = cert.verify(issuerPublicKey);

      console.log(`Certificate signature is valid: ${isValid}`);
      return isValid;
  } catch (error) {
      console.error('Error during verification:', error);
      return false;
  }
}

// 
function verifySignatureWithLowLevelCrypto(cert, issuerCACert) {
  const derString = cert.raw.toString('binary');
  const forgeBuffer = forge.util.createBuffer(derString);
  const asn1Obj = forge.asn1.fromDer(forgeBuffer);
  const certificate = forge.pki.certificateFromAsn1(asn1Obj);
  const tbsDer = forge.asn1.toDer(certificate.tbsCertificate).getBytes();
  const tbsBuffer = Buffer.from(tbsDer, 'binary');
  const certSignatureBuffer = Buffer.from(certificate.signature, 'binary');
  const issuerPublicKey = issuerCACert.publicKey;
  
  return crypto.verify(
    "RSA-SHA256",
    tbsBuffer,
    issuerPublicKey,
    certSignatureBuffer
  );
}


/******************************************************************************
 * JWS VERIFICATION FUNCTIONS
 ******************************************************************************/

// extract info from the JWS response and lookup the public key in the JWKS
async function extractResponseInfo(response, jwks) {

  // Extract data, header, and signature from the response
  const data = response.data;
  const header = response.headers;
  const signature = response.headers['x-jws-signature'];
  console.log('data1:', data);
  console.log('header2:', header);
  console.log('signature3:', signature);

  // Decode the JWS signature header
  const decodedSignature = jose.decodeProtectedHeader(signature);
  const kid = decodedSignature.kid;
  console.log('decodedSignature:', decodedSignature);
  console.log('kid:', kid);

  // Find the matching key in JWKS
  const matchingKey = jwks.keys.find(key => key.kid === kid);
  if (!matchingKey) {
      throw new Error(`No matching key found for kid: ${kid}`);
  }
  const x5u = matchingKey.x5u;
  console.log('matchingKey:', matchingKey);
  console.log('x5u:', x5u);

  // Fetch the public key
  const publicKey = (await axios.get(x5u, { responseType: 'text', httpsAgent: CONFIG.agent })).data;
  console.log('publicKey:', publicKey);

  return {
      publicKey: publicKey,
      data: data,
      header: header,
      signature: signature,
      decodedSignature: decodedSignature,
  };
}


async function verifyOBSignedResponse(response, jwks) {

  // get the data, header and signature from the response 
  const data = response.data;
  const header = response.headers; 
  const signature = response.headers['x-jws-signature'];
  console.log('data1:', data); 
  console.log('header2:', header); 
  console.log('signature3:', signature); 

  // retrieve kid identifier from the signature 
  const decodedSignature = jose.decodeProtectedHeader(signature);
  const kid = decodedSignature.kid; 
  console.log('deocdedSignature: ', decodedSignature); 
  console.log('kid', kid);

  // check the jwks for corresponding entry for the kid 
  const matchingKey = jwks.keys.find(key => key.kid === kid);
  const x5u = matchingKey.x5u;
  console.log('matching keys', matchingKey); 
  console.log('x5u', x5u); 

  // fetch the .pem public key corresponding to signature 
  const publicKey = (await axios.get(x5u, { responseType: 'text', httpsAgent: CONFIG.agent })).data;
  console.log('public key', publicKey);

  // prepare data for verification 
  const encodedHeader = Buffer.from(JSON.stringify(decodedSignature)).toString('base64url');
  const rawPayload = Buffer.from(JSON.stringify(data));
  const dataToVerify = `${encodedHeader}.${rawPayload}`;
  const signatureBuffer = Buffer.from(signature.split('.')[2], 'base64url');

  console.log('dataToVerify', dataToVerify);   

  // Verify the signature using crypto library 
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

  // OPTIONAL: verify the signature using the openbanking.nr library if you are working with noir circuits 
  let { publicKey: certd } = new crypto.X509Certificate(publicKey);
  console.log("public key", publicKey)
  const inputs = generateNoirInputs(dataToVerify, signatureBuffer.toString('hex'), certd); 
  const noir = new Noir(OpenBankingDomesticCircuit)
  const result = await noir.execute({params: inputs });
  const outputs = decodeNoirOutputs(result.returnValue);
  console.log('JWS verification with Noir cicrcuits', outputs);

  return isVerified;
}


/******************************************************************************
 * OCSP VERIFICATION FUNCTIONS
 ******************************************************************************/
async function verifyOCSPWithEasyLib(cert) {
  try {
    const ocspResult = await getCertStatus(cert);
    return {
      status: ocspResult.status,
      rawResponse: (await getRawOCSPResponse(cert)).rawResponse
    };
  } catch (error) {
    console.error("OCSP verification error:", error);
    return { status: "error", error };
  }
}

// /**
//  * Verify certificate status using OCSP library
//  * @param {X509Certificate} cert - The certificate to check
//  * @param {X509Certificate} issuerCACert - The issuer's certificate
//  * @returns {Promise<object>} - Full verification results including status and raw data
//  */
async function verifyOCSPWithOcspLib(cert, issuerCACert) {
  try {
    // 1. Extract OCSP URI from certificate
    const uri = cert.infoAccess
      .split('\n')
      .find(line => line.startsWith('OCSP - URI:'))
      ?.split('URI:')[1]
      ?.trim();

    if (!uri) {
      throw new Error('No OCSP URI found in certificate');
    }
    
    // 2. Generate OCSP request
    const request = ocsp.request.generate(cert, issuerCACert);

    // 3. Get raw OCSP response
    const raw = await new Promise((resolve, reject) => {
      ocsp.utils.getResponse(uri, request.data, (err, response) => {
        if (err) reject(err);
        else resolve(response);
      });
    });

    // 4. Verify OCSP response
    const verificationResult = await new Promise((resolve, reject) => {
      ocsp.verify({
        request,
        response: raw
      }, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    });

    console.log('verificationResult', verificationResult); 

    // 5. Parse the OCSP response for logging
    const parsedResponse = ocsp.utils.parseResponse(raw);
    console.log('parsedResponse', parsedResponse);
    const responseValue = parsedResponse.value;
    console.log('responseValue', responseValue);
    //const responderPublicKey = parsedResponse.certs[0].tbsCertificate.subjectPublicKeyInfo;
    //console.log('responderPublicKey', responderPublicKey);
    //console.log("Signature Algorithm:", responseValue.signatureAlgorithm.algorithm.join('.'));
    //console.log("Signature:", responseValue.signature.data);
    const producedAt =  new Date(responseValue.tbsResponseData.producedAt);
    const thisUpdate = new Date(responseValue.tbsResponseData.responses[0].thisUpdate);
    const nextUpdate = new Date(responseValue.tbsResponseData.responses[0].nextUpdate);
    console.log("Produced At:", producedAt);
    console.log("This Update:", thisUpdate);
    console.log("Next Update:", nextUpdate);
    //console.log("Raw TBS:", raw.slice(parsedResponse.start, parsedResponse.end));
    console.log("Certificate Status:", responseValue.tbsResponseData.responses[0].certStatus);

    return {
      verified:verificationResult,
      producedAt:producedAt, 
      thisUpdate:thisUpdate, 
      nextUpdate:nextUpdate
    }

  } catch (error) {
    console.error("OCSP verification error", error); 
  }
}

  

/******************************************************************************
 * MAIN VERIFICATION WORKFLOW
 ******************************************************************************/

async function performFullVerification(responseFilePath) {
  // 1. Load and prepare data 
  const consentResponse = await loadResponseFromFile(responseFilePath); 
  const jwks = await fetchJWKS(CONFIG.jwksUri ,CONFIG.agent); 

  // 2. JWS Verification
  const jwsVerificationResult = await verifyOBSignedResponse(consentResponse, jwks);
  console.log('JWS verification result:', jwsVerificationResult);

  // 3. Certificate Extraction & Validation
  const cert = await extractCertificateFromResponse(consentResponse, jwks);
  console.log('Certificate extracted successfully');  

  // 4. Issuer Certificate Validation
  const issuerCACert = await getIssuerCertificate(cert);
  console.log('Issuer certificate retrieved successfully');

  // 5. Certificate Chain Verification
  const certVerificationResult = verifyCertificate(cert, issuerCACert);
  const lowLevelVerificationResult = verifySignatureWithLowLevelCrypto(cert, issuerCACert);
  console.log('Certificate verification results:', {
    standardVerification: certVerificationResult,
    lowLevelVerification: lowLevelVerificationResult
  });
    
  // 6. OCSP Status Check
  const ocspResultWithEasyLib = await verifyOCSPWithEasyLib(cert);
  const ocspResultWithOcspLib = await verifyOCSPWithOcspLib(cert, issuerCACert); 
  console.log('OCSP verification results:', {
    simpleVerification: ocspResultWithEasyLib,
    lowLevelVerification: ocspResultWithOcspLib
  });


  return {
    jwsVerified: jwsVerificationResult,
    certificateVerified: certVerificationResult && lowLevelVerificationResult,
    //ocspStatus: ocspResult.status,
    cert,
    issuerCACert
  };
}


/******************************************************************************
 * MAIN FUNCTION
 ******************************************************************************/
async function main() {
  try {
    console.log("Starting verification process...");
    const results = await performFullVerification('paymentStatusResponse.json');
    console.log("All verification complete:", results);
    return results;
  } catch (error) {
    console.error("Verification process failed:", error);
    process.exit(1);
  }
}

main(); 




