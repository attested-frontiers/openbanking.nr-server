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
