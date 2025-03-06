import * as jose from 'jose';
import fs from 'fs';
import https from 'https';
import axios from 'axios';
import ocsp from 'ocsp';
import forge from 'node-forge';
import * as crypto from 'crypto';
import { getCertStatus, getRawOCSPResponse } from 'easy-ocsp';

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

// async function verifySignature(response, jwks) {
//     try {
//         // Extract response info first
//         const { data, signature, decodedSignature, publicKey } = await extractResponseInfo(response, jwks);

//         // Prepare data for verification
//         const encodedHeader = Buffer.from(JSON.stringify(decodedSignature)).toString('base64url');
//         const rawPayload = Buffer.from(JSON.stringify(data));
//         const dataToVerify = `${encodedHeader}.${rawPayload}`;
//         const signatureBuffer = Buffer.from(signature.split('.')[2], 'base64url');

//         console.log('dataToVerify:', dataToVerify);

//         // Verify the signature using the public key
//         const isVerified = crypto.verify(
//             'sha256',
//             Buffer.from(dataToVerify),
//             {
//                 key: publicKey,
//                 padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
//                 saltLength: 32
//             },
//             signatureBuffer
//         );

//         console.log('JWS verification result:', isVerified);
//         return isVerified;
//     } catch (error) {
//         console.error('Error verifying signature:', error);
//         return false;
//     }
// }

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

  // // verify the signature using the noir library
  // let { publicKey: certd } = new crypto.X509Certificate(publicKey);
  // console.log("public key", publicKey)
  // const inputs = generateNoirInputs(dataToVerify, signatureBuffer.toString('hex'), certd);
  // const noir = new Noir(OpenBankingDomesticCircuit)
  // const result = await noir.execute({params: inputs });
  // const outputs = decodeNoirOutputs(result.returnValue);
  // console.log('JWS verification with Noir cicrcuits', outputs);

  // return isVerified;
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

console.log('OCSP URI', uri);

// Get raw response
const raw = await new Promise((resolve, reject) => {
  ocsp.utils.getResponse(uri, request.data, (err, response) => {
    if (err) reject(err);
    else resolve(response);
  });
});

console.log('raw', raw);

const verificationResult = await new Promise((resolve, reject) => {
  ocsp.verify(
    {
      request,
      response: raw,
    },
    (err, result) => {
      if (err) reject(err);
      else resolve(result);
    }
  );
});

console.log('verificationResult', verificationResult);

const parsedResponse = ocsp.utils.parseResponse(raw);
console.log('parsedResponse', parsedResponse);

// The main response data
const responseValue = parsedResponse.value;
console.log('responseValue', responseValue);

const responderPublicKey =
  parsedResponse.certs[0].tbsCertificate.subjectPublicKeyInfo;
console.log('responderPublicKey', responderPublicKey);

// async function fetchOCSPResponderCert() {
//   const response = await axios.get(responderX5u, { responseType: 'text' });
//   return response.data;
// }
// const ocspResponderCertPEM = await fetchOCSPResponderCert(parsedResponse.certs[0].x5u);
// console.log('ocspResponderCertPEM', ocspResponderCertPEM);
// const ocspResponderCert = crypto.createPublicKey(ocspResponderCertPEM);
// console.log('ocspResponderCert', ocspResponderCert);

// // Verify the OCSP response signature
const signatureAlgorithm = 'RSA-SHA256';
// const isValidSignature = crypto.verify(
//   signatureAlgorithm,
//   parsedResponse.value.tbsResponseData,
//   {
//     key: responderPublicKey,
//     padding: crypto.constants.RSA_PKCS1_PADDING,
//   },
//   parsedResponse.value.signature.data
// );

// if (!isValidSignature) {
//   console.error('OCSP response signature is invalid');
// }

console.log(
  'Signature Algorithm:',
  responseValue.signatureAlgorithm.algorithm.join('.')
);
console.log('Signature:', responseValue.signature.data);
console.log('Produced At:', new Date(responseValue.tbsResponseData.producedAt));
console.log(
  'This Update:',
  new Date(responseValue.tbsResponseData.responses[0].thisUpdate)
);
console.log(
  'Next Update:',
  new Date(responseValue.tbsResponseData.responses[0].nextUpdate)
);
console.log('Raw TBS:', raw.slice(parsedResponse.start, parsedResponse.end));
console.log(
  'Certificate Status:',
  responseValue.tbsResponseData.responses[0].certStatus
);

const rawTBS = raw.slice(parsedResponse.start, parsedResponse.end);
const OCSPsignature = responseValue.signature.data;
const certs = parsedResponse.certs; // Extract certificates from the response

// function getPublicKeyFromCert(cert) {
//     // Extract the raw public key data
//     const publicKeyInfo = cert.subjectPublicKeyInfo;

//     // Convert to a PEM-encoded public key
//     const publicKey = crypto.createPublicKey({
//         key: {
//             n: publicKeyInfo.subjectPublicKey.data, // The modulus (for RSA)
//             e: publicKeyInfo.parameters ? publicKeyInfo.parameters.data : Buffer.from([1, 0, 1]), // Default exponent (0x10001)
//         },
//         format: 'der',  // Using DER format
//         type: 'spki',   // Subject Public Key Info format
//     });

//     return publicKey.export({ format: 'pem', type: 'spki' });
// }

// const publicKeyPem = getPublicKeyFromCert(cert);
// console.log(`Public Key from Cert ${index}:\n`, publicKeyPem);

// function verifyOCSPSignature(rawTBS, signature, signatureAlgorithm, responderPublicKey) {
//   try {
//     // Create verifier with the signature algorithm
//     const verify = crypto.createVerify(signatureAlgorithm);
//     console.log('verify', verify);

//     // Add the data that was signed
//     verify.update(rawTBS);

//     // Verify the signature using the responder's public key
//     const isValid = verify.verify(responderPublicKey, signature);

//     return {
//       isValid,
//     };
//   } catch (error) {
//     throw new Error(`Signature verification failed: ${error.message}`);
//   }
// }

// const signatureVerificationResult = verifyOCSPSignature(rawTBS, OCSPsignature, signatureAlgorithm, responderPublicKey);
// console.log('signatureVerificationResult', signatureVerificationResult);

// // Function to verify CA certificate using ocsp.check
// async function verifyCACertificateWithOCSPCheck(caCert, issuerCert) {
//   return new Promise((resolve, reject) => {
//     ocsp.check({ cert: caCert.raw, issuer: issuerCert.raw }, (err, status) => {
//       if (err) {
//         return reject(err);
//       }
//       // // Debug log the entire status object structure
//       // console.log('Full status object:', JSON.stringify(status, (key, value) => {
//       //   // Handle Buffer objects specially
//       //   if (Buffer.isBuffer(value)) {
//       //     return value.toString('hex');
//       //   }
//       //   return value;
//       // }, 2));
//       console.log('status', status);
//       console.log('status.type', status.type);
//       console.log('Type of response:', typeof status);
//       console.log('Is Buffer:', Buffer.isBuffer(status));
//       const req  = ocsp.request.generate(cert, issuerCert);

//       console.log('req', req);

//       //const parsedResponse = ocsp.utils.parseResponse(status);
//       //console.log('status.raw', parsedResponse);

//       // console.log('OCSP Response Details:');
//       // console.log('Response Status:', parsedResponse.value.responseStatus);
//       // console.log('This Update:', parsedResponse.value.tbsResponseData.responses[0].thisUpdate);
//       // console.log('Next Update:', parsedResponse.value.tbsResponseData.responses[0].nextUpdate);
//       // console.log('Signature Algorithm:', parsedResponse.value.signatureAlgorithm.algorithm);
//       // console.log('Signature:', parsedResponse.value.signature.toString('hex'));

//       if (status.type === 'good') {
//         console.log('CA certificate is valid and not revoked.');
//         resolve(true);
//       } else {
//         console.log('CA certificate has been revoked.');
//         resolve(false);
//       }
//     });

//     const req  = ocsp.request.generate(cert, issuerCert);
//     console.log('req', req);
//   });
// }

// // Example usage
// (async () => {
//   try {
//     const isValid = await verifyCACertificateWithOCSPCheck(cert, issuerCert);
//     console.log('OCSP Verification Result for CA Certificate:', isValid);
//   } catch (error) {
//     console.error('OCSP verification error:', error);
//   }
// })();

// // Step 1: Generate OCSP request
// const request = ocsp.request.generate(cert, issuerCert);
// console.log('wait');
// console.log('OCSP Request:', JSON.stringify(request, null, 2));
// Function to get OCSP URI from a certificate

// ********** 3.2 using the easy-ocsp library to verify the certificate **********

const ocspResult = await getCertStatus(cert);
console.log('ocspResult', ocspResult);

if (ocspResult.status === 'revoked') {
  console.log('Certificate is revoked');
} else if (ocspResult.status === 'good') {
  console.log('Certificate is valid');
} else {
  console.log('Certificate status is unknown');
}

// Get the raw OCSP response to observe the signature
const { rawResponse } = await getRawOCSPResponse(cert);
console.log('Raw OCSP Response:', rawResponse);
console.log('Raw OCSP Response (Hex):', rawResponse.toString('hex'));

// will need to use the pki library to verify the signature

// ########   4. using the ob Noir circuit js api to verify the jws  ##############
