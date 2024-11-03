import urllib.parse

# Replace these with your actual values
client_id = "24ff8692-103f-4d99-85d3-8a6c276ebfa8"
redirect_uri = "https://mohammed7s.github.io/dichondra-ob/callback.html"

# read the jwt from the file 

with open("jwt_token_step3.txt", "r") as file: 
   jwt_token = file.read().strip()



# URL-encode the JWT
encoded_jwt = urllib.parse.quote(jwt_token)

# Construct the authorization URL
authorization_url = (
    "https://sandbox-oba.revolut.com/ui/index.html?"
    f"response_type=code%20id_token&"
    f"scope=accounts&"
    f"redirect_uri={urllib.parse.quote(redirect_uri)}&"
    f"client_id={client_id}&"
    f"request={encoded_jwt}"
)

print("Authorization URL:", authorization_url)

# You can then redirect the user or instruct them to visit this URL
