# Openbanking Revolut Payment Initiation flow (as PISP) with JWS Verification 

## Features 

- simulate payment initiation flow with revolut openbanking api sandbox 
- retrieve signed payment initiation confirmation 
- retrieve public key from certificate 
- verify JWS of payment and consent 

## Prerequisites 

- create revolut developer account https://developer.revolut.com/portal/signin
- follow instructions here: https://developer.revolut.com/docs/guides/build-banking-apps/get-started/register-your-application-in-the-developer-portal to obtain the following values: 
    - private.key 
    - transport.pem 
    - client-id 
    - jwks url
    - kid 
- create revolut business sandbox account https://sandbox-business.revolut.com/signin

## Installation

1. create folder in root called keys and put these keys there:  
    a. private.key  
    b. transport.pem 
2. `npm install` 
3. run `ngrok http 3000` in a seperate terminal. Install ngrok if needed. 
4. copy Forwarding URL from ngrok into revolut portal as the Redirect URL and appending "/callback" at end like this:
![alt text](image.png)
5. `cp .env.example .env` and modify .env with variables obtained earlier


## Usage 

1. run the server `node callback_server.js`
2. run the payment flow with `node payments.js` 
3. open authorization url in browser, and auth with revolut test business sandbox account (the individual accounts have balance 0 and will not authorize for low balance)
4. once authorized, press enter in terminal where payments.js is running in. Two files should be saved `paymentInitResponse.json` and `paymentConsentResponse.json`
5. `node verifyRevolutJws.js` to verify the payment JWS



## Notes: 
kid is used to fetch the corresponding public key from the jwks.   

prod: https://oba.revolut.com/openid-configuration  
sandbox: https://sandbox-oba.revolut.com/openid-configuration  
https://github.com/echosergio/open-banking-message-signing  


verifying JWS: 
(source: https://openbankinguk.github.io/read-write-api-site3/v4.0/profiles/read-write-data-api-profile.html#process-for-verifying-a-signature)  

1. verify header   
    1.1 only specified claims (fields of signature)  
    1.2 verify typ = JOSE  
    1.3 verify cty =   
    1.4 verify alg = PS256  
    1.5 verify valid kid ; how? and public key is retrievable?   
    1.6 verify http://openbanking.org.uk/iat value in the past   
    1.7 verify http://openbanking.org.uk/iss matches expected psp   
    1.8 verify http://openbanking.org.uk/tan contains dns name of the trusted anchor   
    1.9 ensure crit has correct claims and nothing extra  

2. verify signature   
according to this: https://datatracker.ietf.org/doc/html/rfc7515#appendix-F  
Current implementation of signature verification needs to be made fully compliant?   

