import uvicorn
import webbrowser
import requests as req
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from starlette.responses import RedirectResponse
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()  # Load environment variables from a .env file
config = Config('.env')
app = FastAPI()

# Add session middleware for session management
app.add_middleware(SessionMiddleware, secret_key=config("SECRET_KEY"))

# Microsoft OAuth2 configurations
MS_CLIENT_ID = config("MS_CLIENT_ID")
MS_CLIENT_SECRET = config("MS_CLIENT_SECRET")
MS_REDIRECT_URI = "http://localhost:8000/auth/callback"
MS_AUTHORIZATION_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
MS_TOKEN_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MS_SCOPES = "openid profile email offline_access https://graph.microsoft.com/Mail.Read"

@app.get("/login")
def login():
    if not MS_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Microsoft client ID is not configured.")
    
    ms_login_url = (
        f"{MS_AUTHORIZATION_ENDPOINT}?response_type=code"
        f"&client_id={MS_CLIENT_ID}"
        f"&redirect_uri={MS_REDIRECT_URI}"
        f"&scope={MS_SCOPES}"
        f"&response_mode=query"
        f"&access_type=offline"
        f"&prompt=consent"
    )
    return RedirectResponse(ms_login_url)

@app.get("/auth/callback")
async def auth_callback(code: str):
    """
    Handles the OAuth2 callback by exchanging the authorization code for tokens and getting the user's information.
    """
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not provided.")
    
    token_uri = MS_TOKEN_ENDPOINT
    data = {
        "code": code,
        "client_id": MS_CLIENT_ID,
        "client_secret": MS_CLIENT_SECRET,
        "redirect_uri": MS_REDIRECT_URI,
        "grant_type": "authorization_code",
        "scope": MS_SCOPES
    }

    try:
        response = req.post(token_uri, data=data)
        response.raise_for_status()  # Raise an exception for HTTP errors
    except req.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Failed to exchange authorization code for tokens: {str(e)}")
    
    response_json = response.json()

    # Ensure the access_token is present in the response
    if "access_token" not in response_json:
        raise HTTPException(status_code=400, detail="Authentication failed: Access token not found.")

    # Fetch user's information using Microsoft Graph API
    headers = {
        "Authorization": f"Bearer {response_json['access_token']}"
    }

    try:
        user_info_response = req.get("https://graph.microsoft.com/v1.0/me", headers=headers)
        user_info_response.raise_for_status()
    except req.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch user info: {str(e)}")

    user_info = user_info_response.json()

    # Return the user's information along with tokens
    return {
        "email": user_info.get("mail"),
        "name": user_info.get("displayName"),
        "access_token": response_json.get("access_token"),
        "id_token": response_json.get("id_token"),
        "refresh_token": response_json.get("refresh_token"),
        "expires_in": response_json.get("expires_in"),
        "token_type": response_json.get("token_type"),
        "scope": response_json.get("scope")
    }

# Call this function to run the server from the backend or you can also run it by running the main.py file if testing the auth model alone.
def run_server():
    webbrowser.open("http://localhost:8000/login")
    uvicorn.run(app, host="localhost", port=8000)

# Remove this if you are running the server from backend.
if __name__ == "__main__":
    run_server()
