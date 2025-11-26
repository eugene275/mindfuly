"""
Spotify API Integration - Standalone Implementation
===================================================

This file contains the complete Spotify OAuth login implementation.
It is NOT integrated into the main codebase - use this as a reference
or integrate it separately.

To use this:
1. Copy the routes to your routes/spotify.py file
2. Add the callback page to your main.py
3. Register the router in your api.py
4. Add environment variables to .env

Environment Variables Required:
- SPOTIFY_CLIENT_ID
- SPOTIFY_CLIENT_SECRET
- SPOTIFY_REDIRECT_URI (e.g., http://localhost:8200/spotify/callback)
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Dict
import httpx
import os
import base64
from nicegui import ui
from user_service_v2.models.user import get_user_repository_v2, UserRepositoryV2

router = APIRouter(prefix="/spotify", tags=["spotify"])

# Environment variables
SPOTIFY_CLIENT_ID = os.getenv("SPOTIFY_CLIENT_ID", "")
SPOTIFY_CLIENT_SECRET = os.getenv("SPOTIFY_CLIENT_SECRET", "")
SPOTIFY_REDIRECT_URI = os.getenv("SPOTIFY_REDIRECT_URI", "http://localhost:8200/spotify/callback")

# Token storage (in production, use Redis or database)
user_tokens: Dict[str, str] = {}


class AuthLoginRequest(BaseModel):
    username: str


class AuthCallbackRequest(BaseModel):
    code: str
    username: str


class AuthResponse(BaseModel):
    auth_url: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


def get_user_token(username: str) -> Optional[str]:
    """Get stored access token for user"""
    return user_tokens.get(username)


@router.post("/auth/login", response_model=AuthResponse)
async def spotify_login(
    request: AuthLoginRequest,
    user_repo: UserRepositoryV2 = Depends(get_user_repository_v2)
):
    """
    Initiate Spotify OAuth login flow.
    Returns authorization URL for user to visit.
    """
    if not SPOTIFY_CLIENT_ID or not SPOTIFY_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Spotify API credentials not configured"
        )
    
    # Verify user exists
    user = await user_repo.get_by_name(request.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Spotify OAuth scopes
    scopes = [
        "user-read-playback-state",
        "user-modify-playback-state",
        "user-read-currently-playing",
        "playlist-read-private",
        "playlist-read-collaborative",
        "user-library-read",
        "user-top-read"
    ]
    
    # Build authorization URL
    auth_url = (
        "https://accounts.spotify.com/authorize?"
        f"client_id={SPOTIFY_CLIENT_ID}&"
        f"response_type=code&"
        f"redirect_uri={SPOTIFY_REDIRECT_URI}&"
        f"scope={'+'.join(scopes)}&"
        f"state={request.username}"
    )
    
    return AuthResponse(auth_url=auth_url)


@router.post("/auth/callback", response_model=TokenResponse)
async def spotify_callback(
    request: AuthCallbackRequest,
    user_repo: UserRepositoryV2 = Depends(get_user_repository_v2)
):
    """
    Handle Spotify OAuth callback.
    Exchanges authorization code for access token.
    """
    if not SPOTIFY_CLIENT_ID or not SPOTIFY_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Spotify API credentials not configured"
        )
    
    # Verify user exists
    user = await user_repo.get_by_name(request.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Exchange code for token
    token_url = "https://accounts.spotify.com/api/token"
    
    # Prepare credentials for Basic Auth
    credentials = f"{SPOTIFY_CLIENT_ID}:{SPOTIFY_CLIENT_SECRET}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    
    data = {
        "grant_type": "authorization_code",
        "code": request.code,
        "redirect_uri": SPOTIFY_REDIRECT_URI
    }
    
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data, headers=headers)
            response.raise_for_status()
            token_data = response.json()
            
            # Store token (in production, use Redis or database)
            user_tokens[request.username] = token_data["access_token"]
            
            return TokenResponse(
                access_token=token_data["access_token"],
                token_type=token_data["token_type"],
                expires_in=token_data["expires_in"]
            )
    except httpx.HTTPStatusError as e:
        error_detail = "Failed to exchange code for token"
        if e.response.status_code == 400:
            error_detail = "Invalid authorization code"
        raise HTTPException(
            status_code=e.response.status_code,
            detail=error_detail
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to authenticate with Spotify: {str(e)}"
        )


# ============================================================================
# NICE GUI CALLBACK PAGE (Add to your main.py)
# ============================================================================

"""
Add this page handler to your main.py file:

@ui.page('/spotify/callback')
async def spotify_callback():
    \"\"\"
    Handle Spotify OAuth callback
    \"\"\"
    await ui.run_javascript('''
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state'); // username
        const error = urlParams.get('error');
        
        if (error) {
            document.body.innerHTML = '<div style="text-align: center; margin-top: 50px;"><h1>Authorization Failed</h1><p>' + error + '</p><p>You can close this window.</p></div>';
        } else if (code && state) {
            // Exchange code for token
            fetch('/spotify/auth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code, username: state })
            })
            .then(response => response.json())
            .then(data => {
                document.body.innerHTML = '<div style="text-align: center; margin-top: 50px;"><h1>✓ Successfully Connected to Spotify!</h1><p>You can now close this window and return to Mindfuly.</p></div>';
                // Close popup after 2 seconds
                setTimeout(() => window.close(), 2000);
            })
            .catch(error => {
                document.body.innerHTML = '<div style="text-align: center; margin-top: 50px;"><h1>Error</h1><p>Failed to complete authentication: ' + error.message + '</p></div>';
            });
        } else {
            document.body.innerHTML = '<div style="text-align: center; margin-top: 50px;"><h1>Invalid Callback</h1><p>Missing required parameters.</p></div>';
        }
    ''')
    
    with ui.column().classes('mx-auto items-center mt-20'):
        ui.spinner(size='lg')
        ui.label('Connecting to Spotify...').classes('text-xl mt-4')
"""


# ============================================================================
# INTEGRATION INSTRUCTIONS
# ============================================================================

"""
To integrate this into your application:

1. Create a file: src/mindfuly/routes/spotify.py
   - Copy the router and endpoint functions above

2. In your src/mindfuly/api.py:
   - Add: from src.mindfuly.routes import spotify
   - Add: app.include_router(spotify.router)

3. In your src/index/main.py:
   - Add the @ui.page('/spotify/callback') handler (see above)

4. In your .env file:
   - SPOTIFY_CLIENT_ID=your_client_id
   - SPOTIFY_CLIENT_SECRET=your_client_secret
   - SPOTIFY_REDIRECT_URI=http://localhost:8200/spotify/callback

5. In Spotify Developer Dashboard:
   - Add redirect URI: http://localhost:8200/spotify/callback
   - Copy Client ID and Client Secret to .env

6. Frontend usage:
   - Call POST /spotify/auth/login with {"username": "user"}
   - Open the returned auth_url in a popup
   - User authorizes, callback page handles token exchange
   - Token is stored and can be retrieved with get_user_token(username)
"""

