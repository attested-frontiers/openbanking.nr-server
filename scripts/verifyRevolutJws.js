import * as jose from 'jose';
import fs from 'fs';
import https from 'https';
import axios from 'axios';
import ocsp from 'ocsp';
import forge from 'node-forge';
import * as crypto from 'crypto';
import { getCertStatus, getRawOCSPResponse } from 'easy-ocsp';

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
  const caIssuerLine = lines.find((line) => line.includes('CA Issuers - URI:'));

  if (caIssuerLine) {
    // Extract the URL after "CA Issuers - URI:"
    return caIssuerLine.split('CA Issuers - URI:')[1].trim();
  }

  return null;
}

function extractTBSCertificate(cert) {
  const certRaw = cert.raw;
  const tbsCertificate = certRaw.slice(4, certRaw.length - 256); // Adjust slice indices as needed
  return tbsCertificate;
}

async function compareIssuingCACertificates(onlineCertURL) {
  try {
    // Read the stored certificate
    const storedCertData = fs.readFileSync(
      '../certificates/OB_SandBox_PP_Issuing CA.cer'
    );
    const storedCert = new crypto.X509Certificate(storedCertData);

    // Fetch the online certificate
    const onlineCertResponse = await axios.get(onlineCertURL, {
      responseType: 'arraybuffer',
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
      signatureMatch: Buffer.from(storedCert.raw).equals(
        Buffer.from(onlineCert.raw)
      ),
      rawMatch: Buffer.from(storedCert.raw).equals(Buffer.from(onlineCert.raw)),

      // Compare public keys
      //publicKeyMatch: Buffer.from(storedCert.publicKey).equals(Buffer.from(onlineCert.publicKey))
    };

    // Detailed comparison information
    console.log('Certificate Comparison Results:', comparisonResults);

    // Log detailed information if certificates don't match
    if (!Object.values(comparisonResults).every((result) => result === true)) {
      console.log('\nDetailed Certificate Information:');
      console.log('\nStored Certificate:');
      console.log({
        subject: storedCert.subject,
        issuer: storedCert.issuer,
        serialNumber: storedCert.serialNumber,
        validFrom: storedCert.validFrom,
        validTo: storedCert.validTo,
      });

      console.log('\nOnline Certificate:');
      console.log({
        subject: onlineCert.subject,
        issuer: onlineCert.issuer,
        serialNumber: onlineCert.serialNumber,
        validFrom: onlineCert.validFrom,
        validTo: onlineCert.validTo,
      });
    }

    // Return true if all comparisons pass
    return Object.values(comparisonResults).every((result) => result === true);
  } catch (error) {
    console.error('Error comparing certificates:', error);
    throw error;
  }
}

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
  const matchingKey = jwks.keys.find((key) => key.kid === kid);
  if (!matchingKey) {
    throw new Error(`No matching key found for kid: ${kid}`);
  }
  const x5u = matchingKey.x5u;
  console.log('matchingKey:', matchingKey);
  console.log('x5u:', x5u);

  // Fetch the public key
  const publicKey = (
    await axios.get(x5u, { responseType: 'text', httpsAgent: agent })
  ).data;
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
  const matchingKey = jwks.keys.find((key) => key.kid === kid);
  const x5u = matchingKey.x5u;
  console.log('matching keys', matchingKey);
  console.log('x5u', x5u);

  // fetch the .pem public key corresponding to signature
  const publicKey = (
    await axios.get(x5u, { responseType: 'text', httpsAgent: agent })
  ).data;
  console.log('public key', publicKey);

  // prepare data for verification
  const encodedHeader = Buffer.from(JSON.stringify(decodedSignature)).toString(
    'base64url'
  );
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
      saltLength: 32,
    },
    signatureBuffer
  );
  console.log('JWS verification result with crypto library:', isVerified);

  // OPTIONAL: verify the signature using the openbanking.nr library if you are working with noir circuits 
  // let { publicKey: certd } = new crypto.X509Certificate(publicKey);
  // console.log("public key", publicKey)
  // const inputs = generateNoirInputs(dataToVerify, signatureBuffer.toString('hex'), certd); 
  // const noir = new Noir(OpenBankingDomesticCircuit)
  // const result = await noir.execute({params: inputs });
  // const outputs = decodeNoirOutputs(result.returnValue);
  // console.log('JWS verification with Noir cicrcuits', outputs);

  return isVerified;
}

// ########   1. jws verification ##############

// 1.1 using crypto library to verify the signature

// sandbox URI; source:
const JWKS_URI =
  'https://keystore.openbankingtest.org.uk/001580000103UAvAAM/001580000103UAvAAM.jwks';

//source of cerritifates: https://openbanking.atlassian.net/wiki/spaces/DZ/pages/80544075/OB+Root+and+Issuing+Certificates+for+Production
// HTTPS agent to fetch the JWKS. i believe this should be our certificate. will clean up later
const agent = new https.Agent({
  ca: [
    fs.readFileSync('../certificates/OB_SandBox_PP_Root CA.cer'),
    fs.readFileSync('../certificates/OB_SandBox_PP_Issuing CA.cer'),
  ],
  rejectUnauthorized: false, // Temporarily disable SSL verification until the issue is fixed
});

// Fetch JWKS
const jwksResponse = await axios.get(JWKS_URI, { httpsAgent: agent });
const jwks = jwksResponse.data;
console.log('jwks', jwks);

// response data we want to verify. TODO: make it input variable in future to dynamicaly verify responses from revolut
const consentResponse = JSON.parse(
  fs.readFileSync('paymentStatusResponse.json', 'utf8')
);

// verify the signature using the public key
//const isJWSVerified = await verifyOBSignedResponse(consentResponse, jwks);
const isJWSVerified = await verifyOBSignedResponse(consentResponse, jwks);
console.log('isJWSVerified', isJWSVerified);

// ########   2. certificate verification ##############

// 2.1. parse certificate and confirm issuer CA certificate

// cert is the bank's certificate

// extrtact info needed for noir verification & certificate verification
const reponseInfo = await extractResponseInfo(consentResponse, jwks);
const publicKey = reponseInfo.publicKey;

const cert = new crypto.X509Certificate(publicKey);
// Print ALL available information
console.log('Full Certificate Details:');
console.log(JSON.stringify(cert.toJSON(), null, 2));
// You can also access specific fields:
console.log('\nKey Properties:');
console.log({
  subject: cert.subject,
  issuer: cert.issuer,
  validFrom: cert.validFrom,
  validTo: cert.validTo,
  serialNumber: cert.serialNumber,
  keyUsage: cert.keyUsage,
  extensions: cert.extensions,
  publicKey: cert.publicKey,
  signature: cert.raw,
  isCA: cert.ca,
  infoAccess: cert.infoAccess,
  subjectAltName: cert.subjectAltName,
});

// check if the cert issuer CA is the same as the one we have stored from OB website.
// source: https://openbanking.atlassian.net/wiki/spaces/DZ/pages/80544075/OB+Root+and+Issuing+Certificates+for+Production
const certURL = extractCAIssuerURL(cert.infoAccess);
compareIssuingCACertificates(certURL)
  .then((matched) => {
    console.log('Certificates match:', matched);
  })
  .catch((error) => {
    console.error('Error:', error);
  });

const issuerCACertRaw = await axios.get(certURL, {
  responseType: 'arraybuffer', // Important to get binary data
});
// Convert to certificate object
const issuerCACert = new crypto.X509Certificate(issuerCACertRaw.data);
console.log('Issuing CA Certificate Details:');
console.log({
  subject: issuerCACert.subject,
  issuer: issuerCACert.issuer,
  issuerCertificate: issuerCACert.issuerCertificate,
  validFrom: issuerCACert.validFrom,
  validTo: issuerCACert.validTo,
  serialNumber: issuerCACert.serialNumber,
  keyUsage: issuerCACert.keyUsage,
  extensions: issuerCACert.extensions,
  publicKey: issuerCACert.publicKey,
  signature: issuerCACert.raw,
  isCA: issuerCACert.ca,
  infoAccess: issuerCACert.infoAccess,
  subjectAltName: issuerCACert.subjectAltName,
});

// ########   2.2. verify signature of the issuing CA certificate ##############

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

const isCertVerified = verifyCertificate(cert, issuerCACert);

// Function to manually verify a certificate's signature with low level crypto library

// Convert the raw DER (a Buffer) into a binary string
const derString = cert.raw.toString('binary');

// Create a forge ByteBuffer from the binary string
const forgeBuffer = forge.util.createBuffer(derString);

// Decode the DER using node-forge's asn1 module
const asn1Obj = forge.asn1.fromDer(forgeBuffer);
// Log the entire ASN.1 structure
//console.log(JSON.stringify(asn1Obj, null, 2));

// Parse the ASN.1 object into a forge certificate object
const certificate = forge.pki.certificateFromAsn1(asn1Obj);

const tbsDer = forge.asn1.toDer(certificate.tbsCertificate).getBytes();
const tbsBuffer = Buffer.from(tbsDer, 'binary');

// Convert the signature (currently a binary string) to a Buffer
const certSignatureBuffer = Buffer.from(certificate.signature, 'binary');

const issuerPublicKey = issuerCACert.publicKey;

//const certSignatureAlgorithm = certificate.signatureAlgorithm.algorithm;

// Now log certificate properties in a readable format:
//console.log('Subject:', certificate.subject.attributes);
//console.log('Issuer:', certificate.issuer.attributes);
//console.log('Valid From:', certificate.validity.notBefoe);
//console.log('Valid To:', certificate.validity.notAfter);
//console.log('Serial Number:', certificate.serialNumber);
// console.log('Signature Algorithm OID:', certificate.signatureOid);
// console.log('Signature (hex):', certificate.signature.toString('hex'));

// Verify the signature using the issuer's public key
const isCertValid = crypto.verify(
  'RSA-SHA256', // Algorithm used to sign
  tbsBuffer, // Data that was signed
  issuerPublicKey, // Issuer's public key
  certSignatureBuffer // Signature to verify
);

console.log(
  `\nCertificate signature with low level crypto library is valid: ${isCertValid}`
);

// ########   3. check ocsp response for the cert  ##############

// ********** 3.1 using the ocsp library to verify the certificate **********

// Simple ocsp check
ocsp.check(
  {
    cert: cert,
    issuer: issuerCACert,
  },
  function (err, res) {
    if (err) throw err;

    // res will contain the verified response
    // The raw response can be accessed and stored
    console.log('OCSP response', res.response); // Raw ASN.1 encoded response
    console.log('OCSP tbsResponseData', res.tbsResponseData); // The signed response data
    console.log('OCSP signatureAlgorithm', res.signatureAlgorithm);
    console.log('OCSP signature', res.signature);
  }
);

// Obtain OCSP signature
const request = ocsp.request.generate(cert, issuerCACert);
// Parse infoAccess string to get OCSP URI
const uri = cert.infoAccess
  .split('\n')
  .find((line) => line.startsWith('OCSP - URI:'))
  ?.split('URI:')[1]
  ?.trim();

if (!uri) {
  throw new Error('No OCSP URI found in certificate');
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

// Get the raw OCSP response to observe the signature
const { rawResponse } = await getRawOCSPResponse(cert);
console.log('Raw OCSP Response:', rawResponse);
console.log('Raw OCSP Response (Hex):', rawResponse.toString('hex'));

// will need to use the pki library to verify the signature

// ########   4. using the ob Noir circuit js api to verify the jws  ##############

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




