1. create folder in root called keys and put keys there:
    a. private.key
    b. transport.pem 
2. install 
3. `ngrok http 3000` 
4. copy Forwarding URL from ngrok into revolut portal as callback URI in and in .env 
4. run the server `node callback_server.js`
5. `node payments.js` 
6. copy url to browser, and auth with revolut test account
7. press enter in terminal where payments.js is running in 


notes: 
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


how to modify for smart contract verification? 

