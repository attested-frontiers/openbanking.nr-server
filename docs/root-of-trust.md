# The Root of Trust: verifying openbanking transactions

1. **The root of trust**

a key feature of openbanking API standard is that payment endpoints are signed by the bank (ASPSP). These are first party signatures with trust of the openbanking directory (UK) or the trust anchor within the eiDAS framework (EU). 

The root of trust is the authority that vouches for the authenticity of the bank's signature. They are vouching that the signature actually comes from the bank and is registered in the directory with their legal name. 

The certificates are located in this link: https://openbanking.atlassian.net/wiki/spaces/DZ/pages/252018873/OB+Root+and+Issuing+Certificates+for+Sandbox

**Note: this is link for sandbox** 

and you can verify the certificates in our certificates/ folder matches this using the standard openssl command: 

```
openssl x509 -in "OB_SandBox_PP_Root CA.cer" -fingerprint -sha1 -noout
```

2. **JWS Signature verification**

The bank signs over a payment data object. This is the rsponse from this specific endpoint: https://openbankinguk.github.io/read-write-api-site3/v4.0/resources-and-data-models/pisp/domestic-payments.html#get-domestic-payments-domesticpaymentid-payment-details

which returns a status according to this iso specification: https://www.iso20022.org/catalogue-messages/additional-content-messages/external-code-sets



This is a sample of the response which contains the payment details with status of ` "AcceptedSettlementCompleted"` in addition to showing debtor and credit accounts, amount, currency, etc.  

```
{
  "headers": {
    "date": "Thu, 20 Feb 2025 18:41:26 GMT",
    "content-type": "application/json",
    "transfer-encoding": "chunked",
    "connection": "close",
    "vary": "Accept-Encoding",
    "x-jws-signature": "eyJraWQiOiJvSjQwLUcxVklxbUU2eUhuYnA4S1E1Qmk2bXciLCJhbGciOiJQUzI1NiIsImNyaXQiOlsiYjY0IiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9pYXQiLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lzcyIsImh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvdGFuIl0sImI2NCI6ZmFsc2UsImh0dHA6Ly9vcGVuYmFua2luZy5vcmcudWsvdGFuIjoib3BlbmJhbmtpbmcub3JnLnVrIiwiaHR0cDovL29wZW5iYW5raW5nLm9yZy51ay9pc3MiOiIwMDE1ODAwMDAxMDNVQXZBQU0iLCJodHRwOi8vb3BlbmJhbmtpbmcub3JnLnVrL2lhdCI6MTc0MDA3Njg4Nn0..TpbEDhY6rDhlDYDy22S9y09_vov0Vi3COMVV9DSSqZIV2J1M3JOjw1mfW2oVDCQ0W70tCde1AV7O4aiEmUTL8Wp_WmkuW0Botk__yO0k10o3nOc4AJRmOcI_vlet3zqIfikioEluWLu0BHkeT9js73Obg-OX_Pew2rlLi_vqcOcqsErE-SXjIX67C3rdliSt7SADv0WXoQ8Upb_5LN3lRierXgPeu4KyCQp0LDf1Q0zYqaE6qQhKMBAfFZT0HJYAD7cXGfnRhn1zmtxw-iq5r-2Tmhm19D6sAxLMp__fUgIOv4JwPaRUIK2MKPqRN-UlmCgY_It6I5EpiBU6OClNaQ",
    "request-id": "MK78268HRNW1",
    "strict-transport-security": "max-age=2592000; includeSubDomains; preload",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "x-xss-protection": "1; mode=block",
    "referrer-policy": "no-referrer",
    "via": "1.1 google",
    "cf-cache-status": "DYNAMIC",
    "set-cookie": [
      "__cf_bm=TH7duAAm4weekcuz7WkT8ssCa0FPN6BiD_VjYOnvNk4-1740076886-1.0.1.1-UJkny1H5uuxdnT_hDM3Y7h4A2bnt5qbquShke4SIqcO.2ZznkM44YsuGUp1OtWZkBHOmih2e4uHTBV2fHPtdww; path=/; expires=Thu, 20-Feb-25 19:11:26 GMT; domain=.revolut.com; HttpOnly; Secure; SameSite=None",
      "_cfuvid=Zy70NtUCQdLwlSYd2JELY.QDA9NkXdaWsWAbxRfPyrY-1740076886711-0.0.1.1-604800000; path=/; domain=.revolut.com; HttpOnly; Secure; SameSite=None"
    ],
    "server": "cloudflare",
    "cf-ray": "9150a17d5a90791b-CDG"
  },
  "data": {
    "Data": {
      "DomesticPaymentId": "67b35f52-04d9-a698-804c-d9226ab2acf4",
      "Status": "AcceptedSettlementCompleted",
      "StatusUpdateDateTime": "2025-02-17T16:17:17.27064Z",
      "CreationDateTime": "2025-02-17T16:09:54.389289Z",
      "ConsentId": "050d0fd2-21e2-46ed-b3da-54a5c83594c5",
      "Initiation": {
        "RemittanceInformation": {
          "Unstructured": "Shipment fee"
        },
        "DebtorAccount": {
          "SchemeName": "UK.OBIE.SortCodeAccountNumber",
          "Identification": "04290953215338",
          "Name": "Acme Corporation"
        },
        "EndToEndIdentification": "E2E123",
        "InstructionIdentification": "ID412",
        "CreditorAccount": {
          "Name": "Receiver Co.",
          "SchemeName": "UK.OBIE.SortCodeAccountNumber",
          "Identification": "11223321325698"
        },
        "InstructedAmount": {
          "Amount": "2.50",
          "Currency": "GBP"
        }
      }
    },
    "Links": {
      "Self": "https://sandbox-oba.revolut.com/domestic-payments/67b35f52-04d9-a698-804c-d9226ab2acf4"
    },
    "Meta": {
      "TotalPages": 1
    }
  },
  "status": 200
}
```

This is a detached JWS object as per specified in this RFC. Read about it more in [revolut docs]() and in the official [openbanking documentation for v4.0]()   

Using this information as input into our verification functionality. It has all we need to verify it. It has a JWS signature and it as data. 

This describes the practical steps of the function as implemented in  `verifyOBSignedResponse` in `verifyRevolutJws.js`

1. Get the data, header and signature from the response 
2. Extract the kid from the signature 
3. Use the kid to find the corresponding jwk from the jwks 
4. fetch the certificate 
5. Verify the signature using public key, payment data and signature. 

This just confirms there is a signature trail back to the issuingCA which we already know about and trust. 

3. **Certificate verification** 

Although the JWS signature is verified, we still need to be sure the CA that is given to the bank is a trusted CA. We will circle back to the root of trust in section 1. 

In the case of UK openbanking, the certificate is issued by the OBIE Root CA. However in the EU, the certificate is issued by different CAs as specified by eiDAS. This repo is for the UK case. In the /certificates folder you can find the OBIE Root CA certificate and the issuing certificate of the OBIE Root CA. 

The trust chain is as follows: 

OB Root signs -> Issuing CA signs -> Banks's certificate -> payment endpoint 

| Certificate Type | Duration | Issue Date | Expiry Date |
|------------------|----------|------------|-------------|
| OB Root CA       | 20 years | Sep 22 11:39:42 2017 GMT | Sep 22 12:09:42 2037 GMT |
| Issuing CA       | 10 years | Sep 22 12:46:57 2017 GMT | Sep 22 13:16:57 2027 GMT |
| Bank's Certificate | 1 year | Sep 18 14:20:02 2024 GMT | Oct 18 14:50:02 2025 GMT |


In certificate verification there are always two things we need to check. 
1. There is a signature verification trail back to the Root. Where each entity signs over the public key attesting to its validity. 
2. A bank's certificate has not been revoked some time between its issuance and now. A solution to this merged as the ocsp protocol which is a fast ping service to check validity of a given certificate. The root ceritificate also signs this certificate. 

OCSP protocol

Root -> OCSP Correspondor -> bank's certificate with `" status: good"`

offering an alternaive path to the root attesting to validity of a certificate. Its real time to the system that uses this endpoint. However the sync is happening on signed timestamps. Here is a response from OCSP service:

```
ocspResult {
  status: 'good',
  ocspUrl: 'http://ob.trustis.com/ocsp',
  producedAt: 2025-03-31T17:13:12.000Z,
  nextUpdate: 2025-04-03T15:49:03.000Z,
  thisUpdate: 2025-03-31T15:49:03.000Z
}
```

To use this in a smart contract, you will have to check against a timestamp to validate its valid within an acceptable time frame. There is also a signature attestation over this result by the ocsp corresponder certificate. 

In code, We used the [ocsp library](https://github.com/PeculiarVentures/node-ocsp) and the [easy-ocsp](https://github.com/PeculiarVentures/easy-ocsp) library. and obtain valid statuses using each library seperately. 

