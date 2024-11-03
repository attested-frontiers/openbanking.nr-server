import jwt
import datetime

header = {
    "alg": "PS256",
    "kid": "revolut-key-1"
}

body = {
    "response_type": "code id_token",
    "client_id": "24ff8692-103f-4d99-85d3-8a6c276ebfa8",
    "redirect_uri": "https://mohammed7s.github.io/dichondra-ob/callback.html",
    "scope": "accounts",
    "state": "<insert state>",
    "claims": {
        "id_token": {
            "openbanking_intent_id": {
                "value": "eyJraWQiOiJvSjQwLUcxVklxbUU2eUhuYnA4S1E1Qmk2bXciLCJhbGciOiJQUzI1NiJ9.eyJjbGllbnRJZCI6IjI0ZmY4NjkyLTEwM2YtNGQ5OS04NWQzLThhNmMyNzZlYmZhOCIsInNjb3BlcyI6WyJhY2NvdW50cyJdLCJleHAiOjE3MzA0NTMyOTh9.qsTZY6jAbkqD3t2tEVZiqbXNtt9cldvSntFwilA0TYUkaB0wzZX11-bH3FP0B-rXWO-joDfUK_GBrGTBpaKzYQyph22XxBg4wyiS2PY6twpVIvyHFnMdpDRdu_pNghTLLvNxH5hW117lUT8OdeMhr9QgFXA7I0q-OEzPaNJCNz1kP2MCvfbXWHG7vT2KhwZ6CHPYuBFWenFAjjUWLUFXq1OE06VQ55hTnS1m7GzDdF0yE3viTNxjZ3NJe_rj2dGrclI2EPsHFHiUPmz8P61HLp2fm89XadkCDc39QSdniX9c6CVLqNo46zSPpk-N-UXoZ4JX2PxOemzU2kNyK2EiyQ"
            }
        }
    },
    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5),  # Expiration time, e.g., 5 minutes
    "iat": datetime.datetime.utcnow()  # Issued at time
}

# Path to your signing certificate's private key
private_key_path = "private.key" 

with open(private_key_path, 'r') as key_file:
    private_key = key_file.read()

# Generate JWT
jwt_token = jwt.encode(body, private_key, algorithm="PS256", headers=header)
print(jwt_token)

with open("jwt_token_step3.txt", "w") as file: 
    file.write(jwt_token)
print("JWT token saved to jwt_token_step3.txt") 
