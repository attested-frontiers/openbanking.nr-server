// Get the fragment parameters
const hash = window.location.hash.substring(1);
const params = new URLSearchParams(hash);
console.log("params: ", params);

// Log the parameters
console.log('Code:', params.get('code'));
console.log('State:', params.get('state'));
console.log('ID Token:', params.get('id_token'));

// Send to server
fetch('/process-auth?' + hash)
    .then(response => {
        console.log("returned")
        return response.json()
    })
    .then(data => {
        const resultDiv = document.getElementById('result');
        if (data.error) {
            resultDiv.innerHTML = '<h2>Error</h2><pre>' + data.error + '</pre>';
        } else {
            resultDiv.innerHTML = `
                <h2>Authorization Successful!</h2>
                <p>Access Token Received</p>
                <p>Token Type: ${data.token_type}</p>
                <p>Expires in: ${data.expires_in} seconds</p>
                <p>You can close this window now.</p>
            `;

            // // Send WebSocket update
            // const ws = new WebSocket('ws://localhost:3000');
            // ws.onopen = () => {
            //     ws.send(JSON.stringify({ message: 'Authorization successful', token: data }));
            // };
        }
    })
    .catch(error => {
        document.getElementById('result').innerHTML = 
            '<h2>Error</h2><pre>' + error.message + '</pre>';
    });