import json
import traceback
import os
import requests
import argparse
import logging
import time
from typing import List, Optional, Tuple
import tempfile
import re
from urllib.parse import urlparse

# OAuth and HTTP server imports for Zotify-style authentication
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import urlencode, urlparse, parse_qs

# PKCE imports
import secrets
import base64
import hashlib

# Librespot imports
from librespot.core import Session as LibrespotSession
from librespot.proto import Authentication_pb2
import librespot.core
from librespot.metadata import TrackId
from librespot.audio.decoders import AudioQuality as LibrespotAudioQualityEnum, VorbisOnlyAudioQuality
from librespot.core import TokenProvider as LibrespotTokenProvider 
from librespot.mercury import MercuryClient
import weakref

# Store reference to original LibrespotTokenProvider before any patching
_OriginalLibrespotTokenProvider = librespot.core.TokenProvider

# Attempt to import necessary types from utils.models for return types and enums
try:
    from utils.models import TrackInfo, Tags, TrackDownloadInfo, DownloadEnum, CodecEnum, QualityEnum, CodecOptions, DownloadTypeEnum, ArtistInfo, AlbumInfo, PlaylistInfo
except ImportError:
    logging.warning("spotify_api.py: Could not import from utils.models. Defining dummy types for method signatures if run standalone.")    
    class TrackInfo: pass
    class Tags: pass
    class ArtistInfo:
        def __init__(self, name=None, albums=None, **kwargs):
            self.name = name
            self.albums = albums if albums else []
            for k,v in kwargs.items(): setattr(self, k, v)
    class AlbumInfo:
        def __init__(self, name=None, tracks=None, **kwargs):
            self.name = name
            self.tracks = tracks if tracks else []
            for k,v in kwargs.items(): setattr(self, k, v)
    class PlaylistInfo:
        def __init__(self, name=None, tracks=None, **kwargs):
            self.name = name
            self.tracks = tracks if tracks else []
            for k,v in kwargs.items(): setattr(self, k, v)
    class QualityEnum: LOW=1; HIGH=2; HIFI=3
    class CodecEnum: VORBIS=1; AAC=2; FLAC=3; MP3=4
    class DownloadEnum: TEMP_FILE_PATH=1
    class DownloadTypeEnum: track="track"; album="album"; artist="artist"; playlist="playlist"; show="show"; episode="episode"
    class TrackDownloadInfo:
        def __init__(self, download_type=None, file_url=None, codec=None, **kwargs):
            self.download_type=download_type; self.file_url=file_url; self.codec=codec;
            for k,v in kwargs.items(): setattr(self, k, v)
    class CodecOptions: pass
    # For _save_stream_to_temp_file if codec_data is not available:
    class DummyContainer: name = 'ogg'
    class DummyCodecData: container = DummyContainer()
    codec_data_fallback = {CodecEnum.VORBIS: DummyCodecData(), CodecEnum.AAC: DummyCodecData(), CodecEnum.FLAC: DummyCodecData(), CodecEnum.MP3: DummyCodecData()}

# OAuth constants
API_URL = "https://api.spotify.com/v1/"
AUTH_URL = "https://accounts.spotify.com/"
REDIRECT_URI = "http://127.0.0.1:4381/login"
CLIENT_ID = "65b708073fc0480ea92a077233ca87bd"
OAUTH_SCOPES = [
    "app-remote-control",
    "playlist-modify",
    "playlist-modify-private",
    "playlist-modify-public",
    "playlist-read",
    "playlist-read-collaborative",
    "playlist-read-private",
    "streaming",
    "ugc-image-upload",
    "user-follow-modify",
    "user-follow-read",
    "user-library-modify",
    "user-library-read",
    "user-modify",
    "user-modify-playback-state",
    "user-modify-private",
    "user-personalized",
    "user-read-birthdate",
    "user-read-currently-playing",
    "user-read-email",
    "user-read-play-history",
    "user-read-playback-position",
    "user-read-playback-state",
    "user-read-private",
    "user-read-recently-played",
    "user-top-read"
]
DEFAULT_REQUEST_TIMEOUT = 15 # seconds
DESKTOP_CLIENT_ID = "65b708073fc0480ea92a077233ca87bd" 
SPOTIFY_TOKEN_URL = "https://api.spotify.com/api/token" 
CREDENTIALS_FILE_NAME = "credentials.json"

# --- PKCE Helper Functions ---
def generate_code_verifier(length=64) -> str:
    """Generate a high-entropy cryptographic random string for PKCE code verifier."""
    return secrets.token_urlsafe(length)[:length] 

def get_code_challenge(verifier: str) -> str:
    """Create a PKCE code challenge from a code verifier."""
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')

# --- OAuth Classes ---
class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """Handles the OAuth callback from Spotify."""
    def __init__(self, *args, **kwargs):
        self.access_code_payload = None
        self.error_payload = None
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        if "code=" in format % args or "error=" in format % args:
            logging.info(f"OAuthCallbackHandler: {format % args}")
        pass # Suppress other logs

    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        if 'code' in query_components:
            self.access_code_payload = query_components["code"][0]
            message = "<html><body><h1>Authentication Successful!</h1><p>You can close this window.</p></body></html>"
        elif 'error' in query_components:
            self.error_payload = query_components["error"][0]
            message = f"<html><body><h1>Authentication Failed</h1><p>Error: {self.error_payload}. You can close this window.</p></body></html>"
        else:
            message = "<html><body><h1>Waiting for Spotify...</h1><p>Please complete the authorization in your browser.</p></body></html>"
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))
        if self.access_code_payload:
            self.server.access_code_payload = self.access_code_payload
        if self.error_payload:
            self.server.error_payload = self.error_payload

class OAuth:
    """Handles the PKCE OAuth flow for Spotify."""
    def __init__(self, client_id: str, redirect_uri: str, scopes: List[str], logger_instance=None):
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scopes_list = scopes
        self.logger = logger_instance if logger_instance else logging.getLogger(__name__ + ".OAuth")
        parsed_uri = urlparse(redirect_uri)
        self.server_address = (parsed_uri.hostname, parsed_uri.port)
        self.http_server: Optional[HTTPServer] = None
        self.server_thread: Optional[Thread] = None
        self.code_verifier: Optional[str] = None
        self.access_code: Optional[str] = None
        self.error_message: Optional[str] = None

    def _start_http_server(self):
        self.http_server = HTTPServer(self.server_address, OAuthCallbackHandler)
        self.http_server.access_code_payload = None 
        self.http_server.error_payload = None
        self.server_thread = Thread(target=self.http_server.serve_forever, daemon=True)
        self.server_thread.start()
        self.logger.info(f"OAuth callback server started at {self.redirect_uri}")

    def _stop_http_server(self):
        if self.http_server:
            self.http_server.shutdown()
            self.http_server.server_close() 
            self.logger.info("OAuth callback server stopped.")
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=2)
            if self.server_thread.is_alive():
                self.logger.warning("OAuth server thread did not shut down cleanly.")

    def get_authorization_url(self) -> str:
        self.code_verifier = generate_code_verifier()
        code_challenge = get_code_challenge(self.code_verifier)
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': self.redirect_uri,
            'scope': ' '.join(self.scopes_list),
            'code_challenge_method': 'S256',
            'code_challenge': code_challenge,
        }
        return AUTH_URL + "authorize?" + urlencode(params)

    def exchange_code_for_token(self, code: str) -> Optional[dict]:
        if not self.code_verifier:
            self.logger.error("Code verifier is not set. Cannot exchange code.")
            return None
        payload = {
            'client_id': self.client_id,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'code_verifier': self.code_verifier,
        }
        try:
            response = requests.post(AUTH_URL + "api/token", data=payload, timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            token_data = response.json()
            self.logger.info("Successfully exchanged authorization code for token.")
            return token_data
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP error exchanging code for token: {e.response.status_code} - {e.response.text}")
            if e.response.status_code == 400:
                try:
                    error_details = e.response.json()
                    self.logger.error(f"Spotify API error: {error_details.get('error')}, Description: {error_details.get('error_description')}")
                    self.error_message = f"{error_details.get('error')}: {error_details.get('error_description')}" 
                except json.JSONDecodeError:
                    self.error_message = e.response.text
            else:
                 self.error_message = e.response.text
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request exception exchanging code for token: {e}")
            self.error_message = str(e)
            return None

    def refresh_access_token(self, refresh_token_str: str) -> Optional[dict]:
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token_str,
            'client_id': self.client_id,
        }
        try:
            response = requests.post(AUTH_URL + "api/token", data=payload, timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            new_token_data = response.json()
            if 'refresh_token' not in new_token_data and refresh_token_str:
                new_token_data['refresh_token'] = refresh_token_str 
            self.logger.info("Successfully refreshed access token.")
            return new_token_data
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP error refreshing token: {e.response.status_code} - {e.response.text}")
            self.error_message = e.response.text
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request exception refreshing token: {e}")
            self.error_message = str(e)
            return None

    def perform_full_oauth_flow(self) -> Optional[dict]: # Returns token data
        self._start_http_server()
        auth_url = self.get_authorization_url()
        self.logger.info(f"Please authorize in your browser: {auth_url}")
        print(f"\nOpening browser for Spotify authorization...\nURL: {auth_url}")
        print(f"If the browser does not open, please copy the URL above and paste it manually.")
        try:
            webbrowser.open(auth_url)
        except Exception as e_wb:
            self.logger.error(f"Could not open browser automatically: {e_wb}. Please open manually.")

        try:
            self.logger.info("Waiting for user authorization in browser...")
            timeout_seconds = 180 
            start_time = time.time()
            while self.http_server and not self.http_server.access_code_payload and not self.http_server.error_payload:
                if time.time() - start_time > timeout_seconds:
                    self.logger.warning("Timeout waiting for OAuth callback.")
                    self.error_message = "Timeout waiting for Spotify authorization."
                    break
                time.sleep(0.5) 
            
            self.access_code = self.http_server.access_code_payload if self.http_server else None
            self.error_message = self.http_server.error_payload if self.http_server else self.error_message 

        except KeyboardInterrupt:
            self.logger.warning("OAuth flow interrupted by user.")
            self.error_message = "User cancelled authorization."
            return None 
        finally:
            self._stop_http_server()

        if self.error_message:
            self.logger.error(f"OAuth flow failed: {self.error_message}")
            return None

        if self.access_code:
            self.logger.info(f"Received authorization code: {self.access_code[:20]}...")
            return self.exchange_code_for_token(self.access_code)
        else:
            self.logger.error("Did not receive an authorization code.")
            return None

# --- Exception Classes ---
class SpotifyApiError(Exception):
    """Custom exception for Spotify API errors."""
    pass

class SpotifyAuthError(SpotifyApiError):
    """Exception for authentication failures."""
    pass

class SpotifyConfigError(SpotifyApiError):
    """Exception for configuration errors."""
    pass

class SpotifyNeedsUserRedirectError(SpotifyAuthError):
    """Custom exception raised when user needs to authorize via URL."""
    def __init__(self, auth_url):
        self.auth_url = auth_url
        super().__init__(f"Spotify requires authorization. Please visit: {auth_url}")

class SpotifyLibrespotError(SpotifyAuthError):
    """Exception for errors during librespot interaction."""
    pass

class SpotifyTrackUnavailableError(SpotifyLibrespotError):
    """Raised when a track is unavailable."""
    pass

class SpotifyRateLimitDetectedError(SpotifyLibrespotError):
    """Raised when rate limit is detected."""
    pass

class SpotifyItemNotFoundError(SpotifyApiError):
    """Exception for when a specific item is not found."""
    pass

class SpotifyContentUnavailableError(SpotifyApiError):
    """Exception for content unavailable due to region restrictions."""
    pass

# Helper class (can be expanded if full PKCE flow is re-implemented elsewhere)
class PkceTokenDetails: # Simplified for current use if only access_token is managed by this script
    def __init__(self, access_token: str, expires_in: int = 3600, issued_at: Optional[int] = None):
        self.access_token = access_token
        self.expires_in = expires_in
        self.issued_at = issued_at if issued_at is not None else int(time.time())

    def is_expired(self, margin_seconds=60) -> bool:
        if not self.access_token or self.issued_at is None or self.expires_in is None:
            return True
        return (self.issued_at + self.expires_in - margin_seconds) < time.time()

class StoredToken: 
    """Token storage class compatible with librespot TokenProvider."""
    def __init__(self, token_data: dict):
        self.timestamp = int(time.time() * 1000)  # milliseconds
        self.expires_in = int(token_data.get("expires_in", 3600))
        self.access_token = token_data["access_token"]
        self.scopes = token_data.get("scope", "").split() if token_data.get("scope") else []
        self.refresh_token = token_data.get("refresh_token", "") 
        
    def expired(self, margin_seconds: int = 60) -> bool:
        current_time = int(time.time() * 1000)
        return (self.timestamp + (self.expires_in * 1000) - (margin_seconds * 1000)) < current_time

    def to_dict(self) -> dict: 
        return {
            "timestamp": self.timestamp,
            "expires_in": self.expires_in,
            "access_token": self.access_token,
            "scope": " ".join(self.scopes),
            "refresh_token": self.refresh_token
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'StoredToken':
        return cls(data)

# --- Custom Token Provider for Librespot (REINSTATING THIS SECTION) --- 
class LibrespotStoredTokenAdapter(LibrespotTokenProvider.StoredToken):
    """Adapts our StoredToken to what LibrespotTokenProvider.StoredToken expects."""
    def __init__(self, our_stored_token: StoredToken, logger_instance=None):
        self.logger = logger_instance if logger_instance else logging.getLogger(__name__ + ".LibrespotStoredTokenAdapter")
        if not our_stored_token:
            self.logger.error("CRITICAL_ADAPTER: our_stored_token is None during LibrespotStoredTokenAdapter init!")
            raise ValueError("our_stored_token cannot be None for LibrespotStoredTokenAdapter")
        
        self.timestamp = int(our_stored_token.timestamp / 1000) # Librespot expects seconds
        self.expires_in = our_stored_token.expires_in
        self.access_token = our_stored_token.access_token
        self.scopes = our_stored_token.scopes
        self.logger.debug(f"CRITICAL_ADAPTER: LibrespotStoredTokenAdapter initialized. AccessToken: {self.access_token[:20]}..., Timestamp (s): {self.timestamp}, ExpiresIn: {self.expires_in}")        

class SpotifyApiTokenProvider(LibrespotTokenProvider):
    """Custom TokenProvider that uses the OAuth token managed by SpotifyAPI."""
    _instance_counter = 0 # Class variable to count instances

    def __init__(self, session, spotify_api_instance: 'SpotifyAPI'):
        super().__init__(session) # Calls LibrespotTokenProvider.__init__(session)
        SpotifyApiTokenProvider._instance_counter += 1
        self.instance_id = SpotifyApiTokenProvider._instance_counter
        self._spotify_api_ref = weakref.ref(spotify_api_instance) 
        
        self.logger = spotify_api_instance.logger if spotify_api_instance else logging.getLogger(__name__ + ".SpotifyApiTokenProvider")
        self.logger.info(f"CUSTOM_TP_DEBUG (Instance {self.instance_id}): SpotifyApiTokenProvider initialized. Bound to SpotifyAPI ID: {id(spotify_api_instance)}, Librespot Session ID: {id(session)}")
        if spotify_api_instance: # ensure instance exists before trying to set attribute
            spotify_api_instance.last_custom_provider_id_created = self.instance_id

    def get_token(self, *scopes: str) -> _OriginalLibrespotTokenProvider.StoredToken:
        """
        Called by Librespot components when they need a token for the given scopes.
        Following Zotify's approach: return the OAuth token directly instead of 
        trying to fetch from keymaster.
        """
        spotify_api = self._spotify_api_ref()
        self.logger.info(f"CUSTOM_TP_DEBUG (Instance {self.instance_id}, API: {id(spotify_api)}): get_token CALLED for scopes: {scopes}")

        if not spotify_api or not hasattr(spotify_api, 'stored_token') or not spotify_api.stored_token:
            self.logger.error(f"CUSTOM_TP_DEBUG (Instance {self.instance_id}): SpotifyAPI instance or its stored_token is not available. Raising AuthError.")
            raise Exception("SpotifyAPI instance or stored_token not available") 

        pkce_token_info = spotify_api.stored_token
        if not pkce_token_info.access_token:
            self.logger.error(f"CUSTOM_TP_DEBUG (Instance {self.instance_id}): PKCE access_token is missing from SpotifyAPI.stored_token.")
            raise Exception("PKCE access_token is missing")

        self.logger.info(f"CUSTOM_TP_DEBUG (Instance {self.instance_id}): Returning OAuth token directly for scopes {' '.join(scopes)} (Zotify approach)")

        # Create a response that mimics what keymaster would return        
        oauth_token_response = {
            "accessToken": pkce_token_info.access_token,
            "expiresIn": pkce_token_info.expires_in,
            "scope": list(scopes)  # Use the requested scopes
        }

        self.logger.info(f"CUSTOM_TP_DEBUG (Instance {self.instance_id}): Created token response for scopes {' '.join(scopes)}")
        
        try:
            return _OriginalLibrespotTokenProvider.StoredToken(oauth_token_response)
        except Exception as e:
            self.logger.error(f"CUSTOM_TP_DEBUG (Instance {self.instance_id}): Error creating StoredToken: {e}", exc_info=True)
            raise

class SpotifyAPI:
    logger = logging.getLogger(__name__)

    _spotify_url_pattern = re.compile(
        r"^(?:https?://open\.spotify\.com/(?:"
        r"(?:(track|album|artist|playlist|show|episode)/([a-zA-Z0-9]{22}))"  # Standard types with 22-char ID
        r"|(?:user/[^/]+/playlist/([a-zA-Z0-9]{22}))"  # User playlist
        r")|spotify:(track|album|artist|playlist|show|episode):([a-zA-Z0-9]{22}))"
        r"(?:\?.*)?$"  # Allow any query parameters
    )    

    def __init__(self, config=None, module_controller=None):
        self.config = config if config else {}
        self.module_controller = module_controller
        self.librespot_session: Optional[LibrespotSession] = None        
        self.user_market: Optional[str] = None        
        self.oauth_handler: Optional[OAuth] = OAuth(CLIENT_ID, REDIRECT_URI, OAUTH_SCOPES, self.logger)
        self.stored_token: Optional[StoredToken] = None
        self.last_custom_provider_id_created: Optional[int] = None # ADDED FOR DIAGNOSTICS

        # Determine script directory for credentials.json - use config/spotify/ subdirectory        
        self.credentials_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "config", "spotify"))
        os.makedirs(self.credentials_dir, exist_ok=True) # Ensure directory exists
        self.credentials_file_path = os.path.join(self.credentials_dir, CREDENTIALS_FILE_NAME)       
        self.logger.info(f"Credentials will be stored/loaded from: {self.credentials_file_path}")

    def _save_credentials(self, token_obj: StoredToken, username: Optional[str] = "PKCE_USER"):
        """Saves OAuth token data and a username to credentials.json for librespot."""        
        if not token_obj or not token_obj.access_token:
            self.logger.error("Cannot save credentials, token object or access token is missing.")
            return

        credentials_content_for_librespot = {
            "username": username if username else "PKCE_USER",
            "auth_data": token_obj.access_token,
            "type": "AUTHENTICATION_USER_PASS"
        }

        # Save the full token details (including refresh token) for *our* use (e.g. refreshing)        
        full_token_details_for_storage = token_obj.to_dict()
        full_token_details_for_storage['spotify_username'] = username # Store the username we got/used

        try:
            # First, save the full token details (this is the primary credentials file now)
            with open(self.credentials_file_path, 'w') as f:
                json.dump(full_token_details_for_storage, f, indent=4)
            self.logger.info(f"Successfully saved full OAuth token details to {self.credentials_file_path}")

        except IOError as e:
            self.logger.error(f"IOError saving credentials to {self.credentials_file_path}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error saving credentials: {e}", exc_info=True)


    def _load_existing_credentials(self) -> bool:
        """Try to load and validate existing OAuth credentials (StoredToken)."""
        if not os.path.exists(self.credentials_file_path):
            self.logger.info(f"No existing credentials file at {self.credentials_file_path}")
            return False
        try:
            with open(self.credentials_file_path, 'r') as f:
                token_data_from_file = json.load(f)
            
            # Check for essential fields from StoredToken.to_dict()
            if not all(k in token_data_from_file for k in ["access_token", "refresh_token", "expires_in"]):
                self.logger.warning(f"Credentials file {self.credentials_file_path} is missing essential token fields. Re-authentication needed.")
                return False

            loaded_token = StoredToken.from_dict(token_data_from_file)

            if loaded_token.expired():
                self.logger.info("Existing token is expired. Attempting to refresh...")
                if not loaded_token.refresh_token:
                    self.logger.warning("No refresh token available. Full re-authentication required.")
                    return False
                
                refreshed_token_data = self.oauth_handler.refresh_access_token(loaded_token.refresh_token)
                if refreshed_token_data:
                    self.stored_token = StoredToken(refreshed_token_data)                    
                    self.logger.info("Successfully refreshed and loaded token.")
                    return True # Librespot session will be created next
                else:
                    self.logger.warning("Failed to refresh token. Full re-authentication required.")
                    # Potentially delete the invalid credentials file here
                    try: os.remove(self.credentials_file_path); self.logger.info(f"Removed invalid/expired credentials file: {self.credentials_file_path}")
                    except OSError as e_rm: self.logger.error(f"Error removing invalid credentials file: {e_rm}")
                    return False
            else:
                self.stored_token = loaded_token
                self.logger.info("Successfully loaded valid existing token.")
                return True # Librespot session will be created next

        except json.JSONDecodeError:
            self.logger.error(f"Error decoding JSON from {self.credentials_file_path}. File might be corrupted.")
            return False # Treat as needing re-auth
        except Exception as e:
            self.logger.error(f"Unexpected error loading credentials: {e}", exc_info=True)
            return False

    def _perform_oauth_flow(self) -> bool:
        """Performs the full PKCE OAuth flow and saves credentials."""
        if not self.oauth_handler:
            self.logger.error("OAuth handler not initialized!")
            return False
        
        self.logger.info("Starting PKCE OAuth flow...")
        token_data = self.oauth_handler.perform_full_oauth_flow()

        if token_data:
            self.stored_token = StoredToken(token_data)
            self.logger.info(f"OAuth flow successful. Access token obtained: {self.stored_token.access_token[:20]}...")
            
            # Try to get username for storage, default if not available
            spotify_user_details = self._fetch_spotify_user_details(self.stored_token.access_token)
            username_for_storage = spotify_user_details.get('id', "PKCE_USER_NEW") if spotify_user_details else "PKCE_USER_UNKNOWN"
            if spotify_user_details and 'country' in spotify_user_details:
                self.user_market = spotify_user_details['country'] # Set user market
                self.logger.info(f"User market set to: {self.user_market}")
            else:
                self.logger.warning("Could not determine user market from OAuth flow.")

            self._save_credentials(self.stored_token, username_for_storage)
            return True
        else:
            self.logger.error(f"OAuth flow failed. Error: {self.oauth_handler.error_message if self.oauth_handler else 'Unknown OAuth error'}")
            self.stored_token = None
            return False

    def _fetch_spotify_user_details(self, access_token: str) -> Optional[dict]:
        """Fetches user details (like username/ID and market) from Spotify API."""
        if not access_token:
            self.logger.warning("Cannot fetch user details without an access token.")
            return None
        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            response = requests.get(API_URL + "me", headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            user_data = response.json()
            self.logger.info(f"Successfully fetched user details: ID={user_data.get('id')}, Market={user_data.get('country')}")
            return user_data
        except requests.RequestException as e:
            self.logger.error(f"Error fetching user details: {e}")
            return None

    def _create_librespot_session_from_oauth(self) -> bool:
        """Create librespot session using OAuth token with global TokenProvider patch."""
        if not self.stored_token or not self.stored_token.access_token:
            self.logger.error("No valid OAuth token available for librespot session creation.")
            return False

        spotify_username_for_librespot = "PKCE_LibrespotUser"
        if os.path.exists(self.credentials_file_path):
            try:
                with open(self.credentials_file_path, 'r') as f_user:
                    cred_data_user = json.load(f_user)
                    spotify_username_for_librespot = cred_data_user.get('spotify_username', spotify_username_for_librespot)
            except Exception as e_load_user:
                self.logger.warning(f"Could not load username from credentials file, using default. Error: {e_load_user}")

        self.logger.info(f"Attempting to create librespot session for user: '{spotify_username_for_librespot}' using OAuth token.")

        # --- Setup Temporary Global librespot.core.TokenProvider Patch (Closure-based) ---
        current_spotify_api_instance_ref = weakref.ref(self)

        def temporary_token_provider_factory_for_patch(session_instance_for_provider, *args_passed_by_librespot, **kwargs_passed_by_librespot):
            api_instance = current_spotify_api_instance_ref()
            if api_instance:
                api_instance.logger.info(f"GLOBAL_PATCH_DEBUG: temporary_token_provider_factory called. SpotifyAPI ID: {id(api_instance)}.")
                provider = SpotifyApiTokenProvider(session_instance_for_provider, api_instance) # Pass api_instance (SpotifyAPI)
                return provider
            else:
                # This path should ideally not be hit if SpotifyAPI instance is managed correctly.
                logging.getLogger(__name__).error("GLOBAL_PATCH_DEBUG: temporary_token_provider_factory: SpotifyAPI weak_ref is dead! Cannot create custom provider.")
                return _OriginalLibrespotTokenProvider(session_instance_for_provider, *args_passed_by_librespot, **kwargs_passed_by_librespot)

        # Store the truly original one if we haven't for this whole module load        
        if not hasattr(librespot.core, '_truly_original_token_provider_for_restore'):
            librespot.core._truly_original_token_provider_for_restore = librespot.core.TokenProvider # Store current before patch
            self.logger.info(f"GLOBAL_PATCH_DEBUG: Stored _truly_original_token_provider_for_restore (was: {librespot.core._truly_original_token_provider_for_restore}).")
        
        # Apply the patch
        librespot.core.TokenProvider = temporary_token_provider_factory_for_patch
        self.logger.info(f"GLOBAL_PATCH_DEBUG: Applied temporary global patch. librespot.core.TokenProvider is now: {librespot.core.TokenProvider}")        

        try:
            conf_builder = LibrespotSession.Configuration.Builder()
            conf_builder.set_store_credentials(False) 
            cache_path = os.path.join(self.credentials_dir, ".librespot_cache")
            os.makedirs(cache_path, exist_ok=True)
            conf_builder.set_cache_dir(cache_path)
            conf_builder.set_cache_enabled(True)
            conf = conf_builder.build()

            builder = LibrespotSession.Builder(conf)
            
            auth_type_for_oauth = Authentication_pb2.AuthenticationType.values()[3] 
            self.logger.info(f"Using AuthenticationType index 3 for OAuth: {Authentication_pb2.AuthenticationType.Name(auth_type_for_oauth)}")
            
            credentials_pb = Authentication_pb2.LoginCredentials(
                username=spotify_username_for_librespot,
                typ=auth_type_for_oauth,
                auth_data=self.stored_token.access_token.encode('utf-8')
            )
            builder.login_credentials = credentials_pb
            self.logger.info(f"Set LoginCredentials for Librespot with OAuth token for user {spotify_username_for_librespot}.")

            self.logger.info("GLOBAL_PATCH_DEBUG: About to call builder.create()...")
            self.librespot_session = builder.create() 
            self.logger.info(f"GLOBAL_PATCH_DEBUG: builder.create() completed. Resulting session object ID: {id(self.librespot_session) if self.librespot_session else 'None'}")

            if self.librespot_session:
                self.logger.info(f"Librespot session created successfully. Username: {self.librespot_session.username()}. Device ID: {self.librespot_session.device_id()}")
                
                actual_provider = self.librespot_session.tokens() # type: ignore
                self.logger.info(f"DIAGNOSTIC: Librespot session's internal token provider type: {type(actual_provider)}")
                if isinstance(actual_provider, SpotifyApiTokenProvider):
                    self.logger.info(f"  It IS SpotifyApiTokenProvider (Instance ID: {actual_provider.instance_id})")
                    bound_api_instance = actual_provider._spotify_api_ref() if hasattr(actual_provider, '_spotify_api_ref') else None
                    if bound_api_instance and id(self) == id(bound_api_instance):
                         self.logger.info(f"  And it's bound to the correct SpotifyAPI instance ({id(self)}).")
                    else:
                         self.logger.error(f"  BUT it's bound to a DIFFERENT/DEAD SpotifyAPI instance (Provider's ref: {id(bound_api_instance) if bound_api_instance else 'N/A'})!")
                else:
                    self.logger.warning(f"  It is NOT SpotifyApiTokenProvider, it is {type(actual_provider)}.")

                # Test with a simple API call that requires a token, made via Librespot's mechanisms
                try:                    
                    example_track_id = TrackId.from_uri("spotify:track:0VjIjW4GlUZAMYd2vXMi3b") # The Weeknd - Blinding Lights
                    self.logger.info(f"Performing post-session creation Librespot API test call (get_metadata_4_track for {str(example_track_id)})...")
                    track_meta = self.librespot_session.api().get_metadata_4_track(example_track_id)
                    self.logger.info(f"Post-session creation Librespot API test call SUCCEEDED. Track: {track_meta.name if track_meta else 'Unknown'}")
                except Exception as e_meta_test:
                    self.logger.error(f"Post-session creation Librespot API test call (get_metadata_4_track for {str(example_track_id) if 'example_track_id' in locals() else 'unknown track'}) FAILED: {e_meta_test}", exc_info=True)
                    
                return True
            else:
                self.logger.error("Librespot builder.create() returned None.")
                return False # Session creation failed

        except librespot.core.Session.SpotifyAuthenticationException as auth_exc:
            self.logger.error(f"Librespot authentication failed during session creation: {auth_exc}") # No exc_info for this specific case
            self.librespot_session = None
            return False

        except MercuryClient.MercuryException as me:
            self.logger.error(f"GLOBAL_PATCH_DEBUG: MercuryException during builder.create(): {me}", exc_info=True)
            self.librespot_session = None # Clear session on error
            return False
        except Exception as e:
            self.logger.error(f"GLOBAL_PATCH_DEBUG: Unexpected generic exception during Librespot session creation: {e}", exc_info=True)
            self.librespot_session = None # Clear session on error
            return False
        finally:
            # --- Restore Original Global librespot.core.TokenProvider ---
            if hasattr(librespot.core, '_truly_original_token_provider_for_restore'):
                librespot.core.TokenProvider = librespot.core._truly_original_token_provider_for_restore
                self.logger.info(f"GLOBAL_PATCH_DEBUG: Restored original librespot.core.TokenProvider from _truly_original_token_provider_for_restore. It is now: {librespot.core.TokenProvider}")
            else:
                self.logger.warning("GLOBAL_PATCH_DEBUG: _truly_original_token_provider_for_restore not found. Original may not have been stored or patch was bypassed.")
            self.logger.info("GLOBAL_PATCH_DEBUG: Librespot session creation attempt finished.")
        
        return False

    def _load_credentials_and_init_session(self) -> bool:
        """Loads existing OAuth credentials or performs PKCE flow, then creates librespot session."""
        self.logger.info("Attempting to authenticate and initialize session...")
        
        # 1. Try to load existing credentials (StoredToken with access/refresh tokens)
        if self._load_existing_credentials():
            self.logger.info("Successfully loaded existing OAuth credentials.")
            # Now, create librespot session using these loaded credentials
            if self._create_librespot_session_from_oauth():
                self.logger.info("Successfully initialized Librespot session from existing OAuth credentials.")
                return True
            else:
                self.logger.warning("Failed to create Librespot session from existing OAuth credentials. Forcing new OAuth flow.")                
                self.stored_token = None
                try: os.remove(self.credentials_file_path); self.logger.info(f"Removed credentials file {self.credentials_file_path} to force re-auth.");
                except OSError: pass # Ignore if already gone
        else:
            self.logger.info("No valid existing credentials found or refresh failed.")

        # 2. If loading failed or was skipped, perform full OAuth flow
        self.logger.info("Proceeding with full PKCE OAuth flow.")
        if self._perform_oauth_flow():
            self.logger.info("OAuth PKCE flow completed successfully.")
            # Now, create librespot session using the NEWLY obtained OAuth credentials
            if self._create_librespot_session_from_oauth():
                self.logger.info("Successfully initialized Librespot session after new OAuth flow.")
                return True
            else:
                self.logger.error("CRITICAL: Failed to create Librespot session even after a successful new OAuth flow.")                
                return False
        else:
            self.logger.error("OAuth PKCE flow failed.")
            return False

    def _is_session_valid(self, session_obj: Optional[LibrespotSession]) -> bool:
        """Checks if the provided librespot session object is considered valid."""
        self.logger.debug(f"_is_session_valid invoked. Type of session_obj: {type(session_obj)}")
        if hasattr(self, 'librespot_session'): # Check if self.librespot_session is initialized
            self.logger.debug(f"Is session_obj the same instance as self.librespot_session? {session_obj is self.librespot_session}")
            if self.librespot_session is not None:
                # Safely try to get username from self.librespot_session for comparison/debug
                try:
                    s_username = self.librespot_session.username()
                    self.logger.debug(f"Username from self.librespot_session (internal): '{s_username}'")
                except AttributeError:
                    self.logger.debug("self.librespot_session does not have username() attribute internally at this point.")
        else:
            self.logger.debug("self.librespot_session attribute not yet initialized in SpotifyAPI instance.")

        if session_obj is None:
            self.logger.debug("_is_session_valid: session_obj argument is None.")
            return False
        try:
            # Try a very basic check: if the session object exists and has a callable username method that returns a non-empty string.
            username = session_obj.username()
            is_logged_in_internal = session_obj.is_logged_in() if hasattr(session_obj, 'is_logged_in') else True
            is_valid = username is not None and username != "" and is_logged_in_internal
            self.logger.debug(f"_is_session_valid: username='{username}', is_logged_in_internal={is_logged_in_internal}, result={is_valid}")
            return is_valid
        except AttributeError as ae:
            self.logger.warning(f"_is_session_valid: AttributeError encountered (session might be None or malformed): {ae}")
            return False
        except Exception as e:
            self.logger.error(f"_is_session_valid: Unexpected error checking session validity: {e}", exc_info=True)
            return False
        
    def _fetch_user_market(self, _retry_attempted: bool = False) -> Optional[str]:
        """Fetches user market using the access token. Retries once on 401.
           Returns the market string or None if fetching fails.
        """
        self.logger.debug(f"SpotifyAPI._fetch_user_market called{' (retry)' if _retry_attempted else ''}")
        if not self.stored_token or not self.stored_token.access_token or self.stored_token.expired():
            self.logger.info("SpotifyAPI._fetch_user_market: Token missing, invalid or expired. Attempting to load/refresh session.")
            # Try to re-initialize the session to get a valid token
            if not self._load_credentials_and_init_session():
                self.logger.warning("SpotifyAPI._fetch_user_market: Session initialization failed. Cannot fetch market.")
                return None
        
        # After potential session init, check token again
        if not self.stored_token or not self.stored_token.access_token:
            self.logger.warning("SpotifyAPI._fetch_user_market: Still no valid access token after attempt. Cannot fetch market.")
            return None

        headers = {'Authorization': f'Bearer {self.stored_token.access_token}'}
        web_api_me_url = "https://api.spotify.com/v1/me"
        try:
            response = requests.get(web_api_me_url, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            user_data = response.json()
            self.user_market = user_data.get("country")
            if self.user_market:
                self.logger.info(f"User market/country determined: {self.user_market}")
            else:
                self.logger.warning("Could not determine user market from /v1/me endpoint (no 'country' field in response).")
            return self.user_market
        except requests.exceptions.HTTPError as http_err:
            if http_err.response.status_code == 401:
                self.logger.warning(f"SpotifyAPI._fetch_user_market: Auth error (401). Token might be invalid.")
                if not _retry_attempted:
                    self.logger.info("SpotifyAPI._fetch_user_market: Attempting re-auth and retry for 401.")
                    self.stored_token = None
                    if self._perform_oauth_flow():
                        self.logger.info("SpotifyAPI._fetch_user_market: Re-auth successful. Retrying call.")
                        return self._fetch_user_market(_retry_attempted=True)
                    else:
                        self.logger.error("SpotifyAPI._fetch_user_market: Re-auth failed after 401.")                        
                        return None 
                else:
                    self.logger.error("SpotifyAPI._fetch_user_market: Auth error (401) even after retry.")
                    return None
            else:
                self.logger.error(f"SpotifyAPI._fetch_user_market: HTTP error: {http_err.response.status_code} - {http_err.response.text[:200]}", exc_info=False)
                return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"SpotifyAPI._fetch_user_market: RequestException: {e}", exc_info=False)
            return None
        except Exception as e:
            self.logger.error(f"SpotifyAPI._fetch_user_market: Unexpected error: {e}", exc_info=True)
            return None

    def _convert_base62_to_gid_hex(self, base62_id: str) -> Optional[str]:
        if not base62_id:
            self.logger.warning("Attempted to convert an empty base62_id to GID hex.")
            return None
        try:
            if not isinstance(base62_id, str):
                self.logger.error(f"base62_id must be a string, got {type(base62_id)}: {base62_id}")
                return None
            gid_obj = TrackId.from_base62(base62_id)
            hex_id = gid_obj.hex_id()
            self.logger.info(f"Converted base62 ID '{base62_id}' to GID hex '{hex_id}'")
            return hex_id
        except Exception as e:
            self.logger.error(f"Failed to convert base62 ID '{base62_id}' to GID hex: {e}", exc_info=True)
            return None

    def search(self, query_type_enum_or_str, query_str: str, track_info=None, market: Optional[str] = None, limit: int = 20, _retry_attempted: bool = False) -> List[dict]:
        self.logger.info(f"SpotifyAPI.search: type='{query_type_enum_or_str}', query='{query_str}', limit={limit}{', retry' if _retry_attempted else ''}")
        # Initial auth check
        if not self.stored_token or not self.stored_token.access_token or self.stored_token.expired():
            self.logger.info("SpotifyAPI.search: Token missing, invalid or expired. Attempting to load/refresh session.")
            if not self._load_credentials_and_init_session():
                self.logger.error("SpotifyAPI.search: Session initialization failed.")
                raise SpotifyAuthError("Authentication required/failed for search. Session could not be initialized.")
        
        if not self.stored_token or not self.stored_token.access_token:
            self.logger.error("SpotifyAPI.search: Still no access token after session initialization attempt.")
            raise SpotifyAuthError("Authentication failed for search. No valid token.")

        # Determine market if not provided
        effective_market = market
        if not effective_market:
            effective_market = self._fetch_user_market() # This method will also handle its own 401s with retry
            if not effective_market:
                self.logger.warning("SpotifyAPI.search: No market provided and could not determine user market. Results may be inconsistent.")
        
        query_type_str = query_type_enum_or_str.name.lower() if hasattr(query_type_enum_or_str, 'name') else str(query_type_enum_or_str).lower()
        
        search_url = "https://api.spotify.com/v1/search"
        headers = {'Authorization': f'Bearer {self.stored_token.access_token}'}
        params = {'q': query_str, 'type': query_type_str, 'limit': limit}
        if effective_market:
            params['market'] = effective_market
            self.logger.info(f"SpotifyAPI.search: Using market: {effective_market}")

        try:
            response = requests.get(search_url, headers=headers, params=params, timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            search_results = response.json()
            
            plural_type = query_type_str + "s"
            if plural_type in search_results and "items" in search_results[plural_type]:
                items = search_results[plural_type]["items"]
                if not items:
                     self.logger.info(f"No {plural_type} found for '{query_str}'.")
                return items 
            else:
                self.logger.warning(f"'{plural_type}' or '{plural_type}.items' not in search response for query '{query_str}'. Response keys: {list(search_results.keys())}")
                if query_type_str in search_results and isinstance(search_results[query_type_str], dict) and "id" in search_results[query_type_str]:
                    self.logger.info(f"Found a single item matching type '{query_type_str}' directly in response.")
                    return [search_results[query_type_str]]
                # Handle API error messages if present
                if "error" in search_results:
                    error_details = search_results["error"]
                    msg = error_details.get("message", "Unknown Spotify API error during search")
                    status = error_details.get("status", 0)
                    self.logger.error(f"Spotify API error during search: {status} - {msg}")
                    if status == 401: # This should ideally be caught by HTTPError, but as a fallback
                        raise SpotifyAuthError(f"Search failed due to authorization issue (API Error: {msg}). Token may be invalid or scopes insufficient.")
                    elif status == 404:
                         raise SpotifyItemNotFoundError(f"Search query '{query_str}' of type '{query_type_str}' not found (API Error: {msg}).")
                    else: 
                        raise SpotifyApiError(f"Spotify API error during search: {status} - {msg}")
            return []

        except requests.exceptions.HTTPError as http_err:
            if http_err.response.status_code == 401:
                self.logger.warning(f"SpotifyAPI.search: Auth error (401) for query '{query_str}'. Token might be invalid.")
                if not _retry_attempted:
                    self.logger.info("SpotifyAPI.search: Attempting re-auth and retry for 401.")
                    self.stored_token = None
                    if self._perform_oauth_flow():
                        self.logger.info("SpotifyAPI.search: Re-auth successful. Retrying call.")
                        return self.search(query_type_enum_or_str, query_str, track_info, market, limit, _retry_attempted=True)
                    else:
                        self.logger.error("SpotifyAPI.search: Re-auth failed after 401.")
                        raise SpotifyAuthError(f"Re-authentication failed for search '{query_str}' after 401.")
                else:
                    self.logger.error(f"SpotifyAPI.search: Auth error (401) for '{query_str}' after retry.")
                    raise SpotifyAuthError(f"Auth failed for search '{query_str}' (401) after retry.")
            elif http_err.response.status_code == 404:
                self.logger.warning(f"SpotifyAPI.search: Query '{query_str}' (type {query_type_str}) resulted in 404.")
                raise SpotifyItemNotFoundError(f"Search query '{query_str}' (type {query_type_str}) not found (HTTP 404).")
            elif http_err.response.status_code == 429:
                self.logger.warning(f"Spotify API rate limit hit (429) during search for '{query_str}'. Raw: {http_err.response.text[:200]}")
                raise SpotifyRateLimitDetectedError(f"Spotify API rate limit hit during search for '{query_str}'.")
            else:
                self.logger.error(f"SpotifyAPI.search: HTTP error for '{query_str}': {http_err.response.status_code} - {http_err.response.text[:200]}", exc_info=False)
                raise SpotifyApiError(f"HTTP error during search for '{query_str}': {http_err.response.status_code} - {http_err.response.text[:200]}") from http_err
        except requests.exceptions.RequestException as req_err:
            self.logger.error(f"SpotifyAPI.search: RequestException for '{query_str}': {req_err}", exc_info=False)
            raise SpotifyApiError(f"Network or request error during search for '{query_str}': {req_err}")
        except SpotifyAuthError:
            raise
        except Exception as e:
            self.logger.error(f"SpotifyAPI.search: Unexpected error for '{query_str}': {e}", exc_info=True)
            if isinstance(e, SpotifyApiError): raise
            raise SpotifyApiError(f"An unexpected error occurred during search for '{query_str}': {e}")
            
    def _save_stream_to_temp_file(self, stream_object, determined_codec_enum: CodecEnum) -> Optional[str]:
        temp_file_path = None
        try:
            project_root_for_temp = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
            target_temp_dir = os.path.join(project_root_for_temp, 'temp')
            os.makedirs(target_temp_dir, exist_ok=True)
            file_suffix = ".ogg"
            try:
                from utils.models import codec_data as core_codec_data
                if determined_codec_enum in core_codec_data and hasattr(core_codec_data[determined_codec_enum].container, 'name'):
                    file_suffix = f".{core_codec_data[determined_codec_enum].container.name}"
            except ImportError:
                self.logger.warning("_save_stream_to_temp_file: Could not import core_codec_data, using default .ogg suffix.")
            except KeyError:
                self.logger.warning(f"_save_stream_to_temp_file: Codec {determined_codec_enum} not in core_codec_data, using default .ogg suffix.")
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_suffix, dir=target_temp_dir) as temp_file:
                temp_file_path = temp_file.name
                self.logger.info(f"Attempting to save stream to {temp_file_path}...")
                bytes_written = 0
                if hasattr(stream_object, 'read') and callable(stream_object.read):
                    while True:
                        chunk = stream_object.read(8192)
                        if not chunk:
                            break
                        temp_file.write(chunk)
                        bytes_written += len(chunk)
                    self.logger.info(f"Finished writing stream to {temp_file_path} ({bytes_written} bytes).")
                else: 
                    self.logger.error(f"Stream object for {temp_file_path} does not have a callable .read() method. Trying iteration as fallback.")
                    for chunk_iter in stream_object: 
                        temp_file.write(chunk_iter)
                        bytes_written += len(chunk_iter)
                    self.logger.info(f"Finished writing stream (iteration fallback) to {temp_file_path} ({bytes_written} bytes).")
            self.logger.info(f"Temporary file size for {temp_file_path}: {bytes_written} bytes.")
            if bytes_written == 0:
                self.logger.error(f"Temporary file {temp_file_path} is empty after saving!")
                if os.path.exists(temp_file_path): os.unlink(temp_file_path)
                return None
            return temp_file_path
        except Exception as save_err:
            self.logger.error(f"Failed during stream saving to temp file: {save_err}", exc_info=True)
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except OSError as e_unlink:
                    self.logger.error(f"Error removing temp file {temp_file_path} after save error: {e_unlink}")
            return None
        finally:
            if stream_object and hasattr(stream_object, 'close') and callable(stream_object.close):
                try:
                    stream_object.close()
                except Exception as close_err:
                    self.logger.warning(f"Error closing original stream object after saving: {close_err}")

    def get_track_download(self, **kwargs) -> Optional[TrackDownloadInfo]:
        track_id_hex = kwargs.get("track_id_str")
        quality_tier = kwargs.get("quality_tier")
        download_options = kwargs.get("codec_options")
        track_info_obj = kwargs.get("track_info_obj")

        if not self._is_session_valid(self.librespot_session):
            self.logger.error("Librespot session is not active or not logged in for track download.")
            if not self._load_credentials_and_init_session() or not self._is_session_valid(self.librespot_session):
                 raise SpotifyAuthError("Authentication required/failed for track download.")
        track_id_obj = TrackId.from_hex(track_id_hex)
        temp_file_path = None
        try:
            self.logger.info(f"Fetching librespot Track metadata for GID hex: {track_id_hex}")
            librespot_audio_quality_mode = LibrespotAudioQualityEnum.NORMAL
            qt_str = None
            if hasattr(quality_tier, 'name'):
                qt_str = quality_tier.name.upper()
            elif isinstance(quality_tier, str):
                qt_str = quality_tier.upper()
            if qt_str == "HIFI" or qt_str == "VERY_HIGH":
                librespot_audio_quality_mode = LibrespotAudioQualityEnum.VERY_HIGH
            elif qt_str == "HIGH":
                librespot_audio_quality_mode = LibrespotAudioQualityEnum.HIGH
            elif qt_str == "LOW":
                librespot_audio_quality_mode = LibrespotAudioQualityEnum.LOW
            self.logger.info(f"Quality tier input: '{quality_tier}', resolved to string: '{qt_str}', mapped to librespot AudioQuality mode: {librespot_audio_quality_mode}")
            content_feeder = self.librespot_session.content_feeder()
            self.logger.info(f"Attempting to load track {track_id_hex} using content_feeder.load_track with VorbisOnlyAudioQuality.")
            stream_loader = content_feeder.load_track(
                track_id_obj,
                VorbisOnlyAudioQuality(librespot_audio_quality_mode),
                False, 
                None   
            )
            if not stream_loader or not hasattr(stream_loader, 'input_stream') or not stream_loader.input_stream:
                self.logger.error(f"Librespot returned no stream_loader or input_stream for track {track_id_hex} (TrackId: {str(track_id_obj)}).")
                try:
                    track_metadata_check = track_id_obj.get(self.librespot_session)
                    if track_metadata_check and not track_metadata_check.file:
                         self.logger.error(f"Additionally, track metadata for GID {track_id_hex} has no associated audio files.")
                         raise SpotifyTrackUnavailableError(f"No audio files listed for track GID {track_id_hex} and stream_loader failed.")
                    elif not track_metadata_check:
                         self.logger.error(f"Additionally, failed to get any track metadata from librespot for GID hex: {track_id_hex}")
                except Exception as meta_err:
                     self.logger.error(f"Error during additional metadata check for {track_id_hex} after stream_loader failure: {meta_err}")
                raise SpotifyTrackUnavailableError(f"Failed to load audio stream (no stream_loader or input_stream) for GID {track_id_hex}")
            raw_audio_byte_stream = stream_loader.input_stream.stream()
            temp_file_path = self._save_stream_to_temp_file(raw_audio_byte_stream, CodecEnum.VORBIS)
            if not temp_file_path:
                self.logger.error(f"Failed to save downloaded stream for GID {track_id_hex} to a temp file.")
                if hasattr(stream_loader, 'input_stream') and stream_loader.input_stream and hasattr(stream_loader.input_stream, 'close'):
                    try:
                        stream_loader.input_stream.close()
                    except Exception as close_ex:
                        self.logger.warning(f"Exception while closing input_stream after save failure for track {track_id_hex}: {close_ex}")
                return None
            self.logger.info(f"Successfully downloaded track {track_id_hex} to {temp_file_path}")
            if track_info_obj and hasattr(track_info_obj, 'codec'):
                self.logger.info(f"Updating track_info_obj.codec to VORBIS for track: {track_info_obj.name if hasattr(track_info_obj, 'name') else track_id_hex}")
                track_info_obj.codec = CodecEnum.VORBIS
            elif track_info_obj:
                self.logger.warning(f"track_info_obj for {track_id_hex} provided but has no 'codec' attribute to update.")
            return TrackDownloadInfo(
                download_type=DownloadEnum.TEMP_FILE_PATH,
                temp_file_path=temp_file_path,
            )
        except SpotifyAuthError: 
            raise
        except SpotifyTrackUnavailableError as e: 
            self.logger.warning(f"Track {track_id_hex} is unavailable for download: {e}")
            raise 
        except SpotifyItemNotFoundError as e: 
            self.logger.warning(f"Track metadata for {track_id_hex} not found: {e}")
            raise 
        except RuntimeError as rt_err:
            if "Failed fetching audio key!" in str(rt_err):
                self.logger.warning(f"Rate limit suspected for track {track_id_hex} due to audio key error: {rt_err}")
                raise SpotifyRateLimitDetectedError(f"Rate limit suspected: {rt_err}") from rt_err
            elif str(rt_err) == "Cannot get alternative track":
                self.logger.warning(f"Track {track_id_hex} is unavailable (librespot: Cannot get alternative track).")
                raise SpotifyTrackUnavailableError(f"Track {track_id_hex} is unavailable (Cannot get alternative track)") from rt_err
            else:
                self.logger.error(f"Unhandled RuntimeError during get_track_download for {track_id_hex}: {rt_err}", exc_info=True)
                raise SpotifyApiError(f"Runtime error during track download {track_id_hex}: {rt_err}") from rt_err
        except Exception as e:
            self.logger.error(f"Unexpected error during get_track_download for {track_id_hex}: {e}", exc_info=True)
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                    self.logger.info(f"Cleaned up temp file {temp_file_path} after error in get_track_download.")
                except OSError as unlink_e:
                    self.logger.error(f"Error unlinking temp file {temp_file_path} during error handling: {unlink_e}")
            raise SpotifyApiError(f"Failed to download track {track_id_hex}: {e}") from e

    def close_session(self):
        """Placeholder for closing librespot session if needed by OrpheusDL's lifecycle."""
        if self.librespot_session:
            try:
                self.logger.info("Simulating librespot session closure (clearing reference).")
                if hasattr(self.librespot_session, 'close') and callable(self.librespot_session.close):
                    self.librespot_session.close()
                    self.logger.info("Called self.librespot_session.close()")
            except Exception as e:
                self.logger.error(f"Error during librespot session close() method: {e}", exc_info=True)
            finally:
                self.librespot_session = None
                self.stored_token = None 
                self.oauth_handler = None 
                self.user_market = None 
                self.logger.info("Cleared librespot_session, stored_token, oauth_handler, and user_market.")
        else: 
            self.logger.info("No active librespot session to close. Ensuring other related attributes are cleared.")
            self.stored_token = None
            self.oauth_handler = None
            self.user_market = None

    def authenticate_stream_api(self, is_initial_setup_check: bool = False) -> bool:
        """Alias for _load_credentials_and_init_session to maintain compatibility with interface.py."""
        self.logger.debug(f"authenticate_stream_api called (aliased to _load_credentials_and_init_session). is_initial_setup_check={is_initial_setup_check}")
        try:
            return self._load_credentials_and_init_session()
        except SpotifyApiError as e:
            self.logger.error(f"authenticate_stream_api failed: {e}")
            if isinstance(e, (SpotifyAuthError, SpotifyConfigError, SpotifyLibrespotError)):
                 return False 
            raise 

    def get_track_by_id(self, track_id: str, market: Optional[str] = None, _retry_attempted: bool = False) -> Optional[dict]:
        """Get track details by its Spotify ID using the Web API."""
        self.logger.debug(f"SpotifyAPI.get_track_by_id entered for track_id: {track_id}, market: {market}{', retry' if _retry_attempted else ''}")

        if not self.stored_token or not self.stored_token.access_token or self.stored_token.expired():
            self.logger.info("SpotifyAPI.get_track_by_id: Token missing, invalid or expired. Attempting to load/refresh session.")
            if not self._load_credentials_and_init_session(): 
                self.logger.error("SpotifyAPI.get_track_by_id: Session initialization failed.")
                raise SpotifyAuthError("Authentication required/failed for get_track_by_id. Session could not be initialized.")
        
        if not self.stored_token or not self.stored_token.access_token: 
             self.logger.error("SpotifyAPI.get_track_by_id: Still no access token after session initialization attempt.")
             raise SpotifyAuthError("Authentication failed for get_track_by_id. No valid token.")

        headers = {"Authorization": f"Bearer {self.stored_token.access_token}"}
        params = {}
        if market:
            params["market"] = market
        elif self.user_market: 
            params["market"] = self.user_market
        
        api_url = f"https://api.spotify.com/v1/tracks/{track_id}"
        self.logger.debug(f"Calling Spotify Web API: GET {api_url} with params: {params}")
        try:
            response = requests.get(api_url, headers=headers, params=params, timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status() # Will raise HTTPError for 4xx/5xx status codes
            track_data = response.json()
            self.logger.debug(f"get_track_by_id SUCCEEDED for track_id: {track_id}. Data (truncated): {str(track_data)[:200]}...")
            return track_data
        except requests.exceptions.HTTPError as http_err:
            if http_err.response.status_code == 401:
                self.logger.warning(f"SpotifyAPI.get_track_by_id: Auth error (401) for track {track_id}. Token might be invalid.")
                if not _retry_attempted:
                    self.logger.info("SpotifyAPI.get_track_by_id: Attempting re-auth and retry for 401.")
                    self.stored_token = None # Invalidate current token
                    if self._perform_oauth_flow():
                        self.logger.info("SpotifyAPI.get_track_by_id: Re-auth successful. Retrying call.")
                        return self.get_track_by_id(track_id, market, _retry_attempted=True)
                    else:
                        self.logger.error("SpotifyAPI.get_track_by_id: Re-auth failed after 401.")
                        raise SpotifyAuthError(f"Re-authentication failed for track {track_id} after 401.")
                else:
                    self.logger.error(f"SpotifyAPI.get_track_by_id: Auth error (401) for track {track_id} after retry.")
                    raise SpotifyAuthError(f"Auth failed for track {track_id} (401) after retry.")
            elif http_err.response.status_code == 404:
                self.logger.warning(f"Track {track_id} not found via Spotify API (404).")
                raise SpotifyItemNotFoundError(f"Track {track_id} not found.") from http_err
            else:
                self.logger.error(f"HTTP error fetching track {track_id}: {http_err.response.status_code} - {http_err.response.text[:200]}", exc_info=False)
                raise SpotifyApiError(f"Spotify API request failed for track {track_id}: {http_err.response.status_code} - {http_err.response.text[:200]}") from http_err
        except requests.exceptions.RequestException as req_err:
            self.logger.error(f"Request exception fetching track {track_id}: {req_err}", exc_info=False)
            raise SpotifyApiError(f"Network error fetching track {track_id}: {req_err}")
        except json.JSONDecodeError as json_err:
            self.logger.error(f"Failed to decode JSON response for track {track_id}: {json_err.msg}. Response text: {response.text[:200]}...", exc_info=False)
            raise SpotifyApiError(f"Invalid JSON response for track {track_id}: {json_err.msg}") from json_err
        except SpotifyAuthError: # Re-raise
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error in get_track_by_id for {track_id}: {e}", exc_info=True)
            if isinstance(e, SpotifyApiError): raise
            raise SpotifyApiError(f"An unexpected error occurred while fetching track {track_id}: {e}")

    @staticmethod
    def is_spotify_url(url_string: str) -> bool:
        if not isinstance(url_string, str):
            SpotifyAPI.logger.debug(f"is_spotify_url: input is not a string: {type(url_string)}")
            return False
        return bool(SpotifyAPI._spotify_url_pattern.match(url_string))

    @staticmethod
    def parse_spotify_url(url_string: str) -> Optional[dict]:
        if not isinstance(url_string, str):
            SpotifyAPI.logger.debug(f"parse_spotify_url: input is not a string: {type(url_string)}")
            return None
        match = SpotifyAPI._spotify_url_pattern.match(url_string)
        if not match:
            SpotifyAPI.logger.debug(f"parse_spotify_url: no regex match for URL: {url_string}")
            return None
        g = match.groups()
        item_type_str = None
        item_id = None
        if g[0] and g[1]:
            item_type_str = g[0]
            item_id = g[1]
        elif g[2]:
            item_type_str = "playlist"
            item_id = g[2]
        elif g[3] and g[4]:
            item_type_str = g[3]
            item_id = g[4]
        if item_type_str and item_id:
            if len(item_id) == 22 and item_id.isalnum():
                valid_types = {"track", "album", "artist", "playlist", "show", "episode"}
                if item_type_str in valid_types:
                    SpotifyAPI.logger.debug(f"parse_spotify_url: successfully parsed URL '{url_string}' to type '{item_type_str}', id '{item_id}'")
                    return {'type': item_type_str, 'id': item_id}
                else: 
                    SpotifyAPI.logger.warning(f"parse_spotify_url: parsed type '{item_type_str}' is not a recognized valid type for URL '{url_string}'.")
            else: 
                SpotifyAPI.logger.warning(f"parse_spotify_url: parsed ID '{item_id}' (type '{item_type_str}') from URL '{url_string}' does not look like a valid Spotify ID (expected 22 alphanumeric chars).")
            return None 
        else: 
            SpotifyAPI.logger.warning(f"parse_spotify_url: could not extract type/id from URL '{url_string}' despite initial regex match. Groups: {g}")
            return None

    def parse_url(self, input_str: str) -> Optional[Tuple[DownloadTypeEnum, str]]:
        """
        Parses a Spotify URL/URI string and returns a tuple of (DownloadTypeEnum, item_id)
        or None if parsing fails. This method is specifically for the interface.py's parse_input.
        """
        parsed_info = SpotifyAPI.parse_spotify_url(input_str)
        if parsed_info:
            type_str = parsed_info.get('type')
            id_str = parsed_info.get('id')
            if type_str and id_str:
                try:
                    from utils.models import DownloadTypeEnum as CoreDownloadTypeEnum
                    try:
                        dt_enum_member = CoreDownloadTypeEnum(type_str)
                        self.logger.info(f"parse_url: Successfully mapped type '{type_str}' to CoreDownloadTypeEnum member for ID '{id_str}'.")
                        return dt_enum_member, id_str
                    except ValueError:
                        self.logger.error(f"parse_url: Type string '{type_str}' from URL ('{input_str}') is not a valid value for CoreDownloadTypeEnum.")
                        return None
                except ImportError:
                    self.logger.warning("parse_url: CoreDownloadTypeEnum not imported. Using fallback enum mapping for URL parsing.")
                    if hasattr(DownloadTypeEnum, type_str):
                        try:
                            fallback_enum_member_value = getattr(DownloadTypeEnum, type_str)
                            self.logger.info(f"parse_url (fallback): Mapped type '{type_str}' to fallback DownloadTypeEnum value '{fallback_enum_member_value}' for ID '{id_str}'.")
                            return fallback_enum_member_value, id_str
                        except AttributeError: 
                            self.logger.error(f"parse_url (fallback): Type '{type_str}' not found as an attribute in fallback DownloadTypeEnum. Input: '{input_str}'.")
                            return None
                    else:
                        self.logger.error(f"parse_url (fallback): Unknown type '{type_str}' for input '{input_str}'. Not an attribute of fallback DownloadTypeEnum.")
                        return None
            else: 
                self.logger.warning(f"parse_url: parse_spotify_url returned data but type_str or id_str is missing. Parsed info: {parsed_info}. Input: '{input_str}'.")
                return None
        else: 
            self.logger.debug(f"parse_url: input_str '{input_str}' was not recognized as a Spotify URL by parse_spotify_url, or another issue occurred.")
            return None

    def get_track_info(self, track_id: str, quality_tier: QualityEnum, codec_options: CodecOptions, **extra_kwargs) -> Optional[TrackInfo]:
        """
        Fetches track information using the Spotify Web API (via get_track_by_id)
        and then enriches it with stream details if necessary (placeholder for now).
        """
        self.logger.debug(f"SpotifyAPI.get_track_info entered for track_id: {track_id}")
        if not self.stored_token or not self.stored_token.access_token or self.stored_token.expired():
            self.logger.info("Access token missing or expired in get_track_info. Attempting to load/refresh.")
            if not self._load_credentials_and_init_session():
                self.logger.error("Failed to ensure authentication for get_track_info.")
                pass 
        try:
            web_api_track_data = self.get_track_by_id(track_id) 
            if not web_api_track_data:
                self.logger.warning(f"No track data returned from Web API for ID: {track_id}")
                return None
            name = web_api_track_data.get('name')
            duration_ms = web_api_track_data.get('duration_ms')
            explicit = web_api_track_data.get('explicit', False)
            track_number = web_api_track_data.get('track_number')
            disc_number = web_api_track_data.get('disc_number')
            isrc = web_api_track_data.get('external_ids', {}).get('isrc')
            artists_data = web_api_track_data.get('artists', [])
            artist_names = [artist.get('name') for artist in artists_data if artist.get('name')]
            artist_ids = [artist.get('id') for artist in artists_data if artist.get('id')]
            album_data = web_api_track_data.get('album', {})
            album_name = album_data.get('name')
            album_id_spotify = album_data.get('id')
            album_release_date_str = album_data.get('release_date')
            album_type_str = album_data.get('album_type')
            album_total_tracks = album_data.get('total_tracks')
            album_artist_data = album_data.get('artists', [])
            album_artist_names = [aa.get('name') for aa in album_artist_data if aa.get('name')]
            album_release_year_int = 0
            if album_release_date_str and len(album_release_date_str) >= 4:
                try:
                    album_release_year_int = int(album_release_date_str[:4])
                except ValueError:
                    self.logger.warning(f"Could not parse year from album release_date: {album_release_date_str} for track {track_id}")
            cover_url = None
            if album_data.get('images'):
                preferred_image = next((img for img in album_data['images'] if img.get('height') == 640 and img.get('width') == 640), None)
                if preferred_image:
                    cover_url = preferred_image.get('url')
                else: 
                    cover_url = album_data['images'][0].get('url')
            gid_hex_value = self._convert_base62_to_gid_hex(track_id) 
            tags_obj = Tags(
                album_artist=album_artist_names if album_artist_names else artist_names,
                track_number=str(track_number) if track_number is not None else None,
                total_tracks=str(album_total_tracks) if album_total_tracks is not None else None,
                disc_number=str(disc_number) if disc_number is not None else None,
                release_date=album_release_date_str,
            )
            track_info_instance = TrackInfo(
                id=track_id,
                name=name,
                artists=artist_names,
                artist_id=artist_ids[0] if artist_ids else None,
                album_id=album_id_spotify,
                album=album_name,
                duration=duration_ms // 1000 if duration_ms else 0,
                cover_url=cover_url,
                explicit=explicit,
                tags=tags_obj,
                codec=CodecEnum.VORBIS, 
                release_year=album_release_year_int,
                gid_hex=gid_hex_value,
            )
            self.logger.debug(f"Successfully created TrackInfo for {track_id}: {name}. Returning object.")
            return track_info_instance
        except SpotifyItemNotFoundError:
            self.logger.warning(f"Track with ID '{track_id}' not found via Spotify Web API.")
            return None
        except SpotifyAuthError as auth_err:
            self.logger.error(f"Authentication error while getting track info for {track_id}: {auth_err}", exc_info=True)
            raise
        except SpotifyApiError as api_err:
            self.logger.error(f"API error while getting track info for {track_id}: {api_err}", exc_info=True)
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error in get_track_info for track_id {track_id}: {e}", exc_info=True)
            return None

    def get_album_info(self, album_id: str, metadata: Optional['AlbumInfo'] = None, _retry_attempted: bool = False) -> Optional[dict]:
        self.logger.info(f"SpotifyAPI: Attempting to get album info for ID: {album_id}{' (retry)' if _retry_attempted else ''}")

        # Initial check for token validity before making the API call
        if not self.stored_token or not self.stored_token.access_token or self.stored_token.expired():
            self.logger.info("SpotifyAPI.get_album_info: Token missing, invalid or expired. Attempting to load/refresh session.")
            if not self._load_credentials_and_init_session():
                self.logger.error("SpotifyAPI.get_album_info: Session initialization failed.")
                raise SpotifyAuthError("Authentication required/failed for get_album_info. Session could not be initialized.")
        
        # Ensure token is definitely valid after potential refresh/load
        if not self.stored_token or not self.stored_token.access_token:
            self.logger.error("SpotifyAPI.get_album_info: Still no access token after session initialization attempt.")
            raise SpotifyAuthError("Authentication failed for get_album_info. No valid token.")

        api_url = f"https://api.spotify.com/v1/albums/{album_id}"
        headers = {"Authorization": f"Bearer {self.stored_token.access_token}"}
        params = {}
        if self.user_market:
            params['market'] = self.user_market

        try:
            self.logger.debug(f"SpotifyAPI.get_album_info: Making GET request to {api_url} with params {params}")
            response = requests.get(api_url, headers=headers, params=params, timeout=DEFAULT_REQUEST_TIMEOUT)

            if response.status_code == 200:
                album_data = response.json()
                self.logger.info(f"SpotifyAPI.get_album_info: Successfully retrieved album data for {album_id}")
                tracks_list = []
                if 'tracks' in album_data and 'items' in album_data['tracks']:
                    tracks_list.extend([item['id'] for item in album_data['tracks']['items'] if item and 'id' in item])
                    next_tracks_url = album_data['tracks'].get('next')
                    while next_tracks_url:
                        self.logger.debug(f"SpotifyAPI.get_album_info: Fetching next page of tracks from {next_tracks_url}")
                        # Use new access token for paginated calls if it was refreshed
                        current_headers = {"Authorization": f"Bearer {self.stored_token.access_token}"}
                        paginated_response = requests.get(next_tracks_url, headers=current_headers, timeout=DEFAULT_REQUEST_TIMEOUT)
                        if paginated_response.status_code == 200:
                            paginated_data = paginated_response.json()
                            tracks_list.extend([item['id'] for item in paginated_data.get('items', []) if item and 'id' in item])
                            next_tracks_url = paginated_data.get('next')
                        elif paginated_response.status_code == 401 and not _retry_attempted:
                            self.logger.warning(f"SpotifyAPI.get_album_info (pagination): Auth error (401) fetching next page for {album_id}. Invalidating token and attempting full re-auth flow.")
                            self.stored_token = None # Invalidate token
                            if self._perform_oauth_flow(): # This will open browser if needed
                                self.logger.info("SpotifyAPI.get_album_info (pagination): Re-authentication successful. Retrying the original get_album_info call.")
                                return self.get_album_info(album_id, metadata, _retry_attempted=True)
                            else:
                                self.logger.error("SpotifyAPI.get_album_info (pagination): Re-authentication failed after 401 on next page.")
                                raise SpotifyAuthError(f"Re-authentication failed after 401 on paginated album tracks for {album_id}.")
                        else:
                            self.logger.warning(f"SpotifyAPI.get_album_info: Failed to get next page of tracks (status: {paginated_response.status_code}). Breaking pagination.")
                            break 
                album_data['tracks'] = tracks_list
                return album_data
            elif response.status_code == 401:
                self.logger.warning(f"SpotifyAPI.get_album_info: Authorization error (401) for {album_id}. Token might be invalid.")
                if not _retry_attempted:
                    self.logger.info("SpotifyAPI.get_album_info: Attempting re-authentication and retry for 401.")
                    self.stored_token = None # Invalidate current token
                    if self._perform_oauth_flow(): # This handles browser opening etc.
                        self.logger.info("SpotifyAPI.get_album_info: Re-authentication successful. Retrying original call.")
                        return self.get_album_info(album_id, metadata, _retry_attempted=True) # Recursive call with retry flag
                    else:
                        self.logger.error("SpotifyAPI.get_album_info: Re-authentication failed after 401.")
                        raise SpotifyAuthError(f"Re-authentication failed for album {album_id} after 401.")
                else:
                    self.logger.error(f"SpotifyAPI.get_album_info: Authorization error (401) for {album_id} even after retry.")
                    raise SpotifyAuthError(f"Authorization failed for album {album_id} (401) after retry.")
            elif response.status_code == 404:
                self.logger.warning(f"SpotifyAPI.get_album_info: Album {album_id} not found (404).")
                raise SpotifyItemNotFoundError(f"Album with ID {album_id} not found.")
            else:
                self.logger.error(f"SpotifyAPI.get_album_info: Failed to get album data for {album_id}. Status: {response.status_code}, Response: {response.text}")
                raise SpotifyApiError(f"Failed to get album data for {album_id}. Status: {response.status_code}, Response Text: {response.text[:200]}")

        except requests.exceptions.HTTPError as http_err: # Catch HTTP errors from requests lib directly
            if http_err.response.status_code == 401:
                self.logger.warning(f"SpotifyAPI.get_album_info: HTTPError 401 caught for {album_id}.")
                if not _retry_attempted:
                    self.logger.info("SpotifyAPI.get_album_info: Attempting re-authentication and retry for HTTPError 401.")
                    self.stored_token = None # Invalidate current token
                    if self._perform_oauth_flow():
                        self.logger.info("SpotifyAPI.get_album_info: Re-authentication successful. Retrying original call.")
                        return self.get_album_info(album_id, metadata, _retry_attempted=True)
                    else:
                        self.logger.error("SpotifyAPI.get_album_info: Re-authentication failed after HTTPError 401.")
                        raise SpotifyAuthError(f"Re-authentication failed for album {album_id} after HTTPError 401.")
                else:
                    self.logger.error(f"SpotifyAPI.get_album_info: HTTPError 401 for {album_id} even after retry.")
                    raise SpotifyAuthError(f"Authorization failed for album {album_id} (HTTPError 401) after retry.")
            else: # Re-raise other HTTPError s as SpotifyApiError
                self.logger.error(f"SpotifyAPI.get_album_info: HTTPError {http_err.response.status_code} for {album_id}: {http_err.response.text[:200]}")
                raise SpotifyApiError(f"HTTP error fetching album {album_id}: {http_err.response.status_code} - {http_err.response.text[:200]}") from http_err
        except requests.exceptions.RequestException as e:
            self.logger.error(f"SpotifyAPI.get_album_info: RequestException for {album_id}: {e}", exc_info=False) # exc_info=False for cleaner log
            raise SpotifyApiError(f"Network error while fetching album {album_id}: {e}")
        except SpotifyAuthError: # Re-raise if it's already our specific auth error
             raise
        except Exception as e:
            self.logger.error(f"SpotifyAPI.get_album_info: Unexpected error for {album_id}: {e}", exc_info=True)
            # Avoid wrapping SpotifyApiError in another SpotifyApiError
            if isinstance(e, SpotifyApiError):
                raise
            raise SpotifyApiError(f"An unexpected error occurred while fetching album {album_id}: {e}")

    def get_playlist_info(self, playlist_id: str, metadata: Optional['PlaylistInfo'] = None, _retry_attempted: bool = False) -> Optional[dict]:
        self.logger.info(f"SpotifyAPI: Attempting to get playlist info for ID: {playlist_id}{' (retry)' if _retry_attempted else ''}")

        if not self.stored_token or not self.stored_token.access_token or self.stored_token.expired():
            self.logger.info("SpotifyAPI.get_playlist_info: Token missing, invalid or expired. Attempting to load/refresh session.")
            if not self._load_credentials_and_init_session():
                self.logger.error("SpotifyAPI.get_playlist_info: Session initialization failed.")
                raise SpotifyAuthError("Authentication required/failed for get_playlist_info. Session could not be initialized.")
        
        if not self.stored_token or not self.stored_token.access_token:
            self.logger.error("SpotifyAPI.get_playlist_info: Still no access token after session initialization attempt.")
            raise SpotifyAuthError("Authentication failed for get_playlist_info. No valid token.")

        api_url = f"https://api.spotify.com/v1/playlists/{playlist_id}"
        headers = {"Authorization": f"Bearer {self.stored_token.access_token}"}
        params = {} # Add market if needed, Spotify API for playlists doesn't typically use it directly for main info but for tracks inside.

        try:
            self.logger.debug(f"SpotifyAPI.get_playlist_info: Making GET request to {api_url} with params {params}")
            response = requests.get(api_url, headers=headers, params=params, timeout=DEFAULT_REQUEST_TIMEOUT)

            if response.status_code == 200:
                playlist_data = response.json()
                self.logger.info(f"SpotifyAPI.get_playlist_info: Successfully retrieved initial playlist data for {playlist_id}")
                all_track_items = []
                if 'tracks' in playlist_data and 'items' in playlist_data['tracks']:
                    all_track_items.extend(playlist_data['tracks']['items'])
                    next_tracks_url = playlist_data['tracks'].get('next')
                    while next_tracks_url:
                        self.logger.debug(f"SpotifyAPI.get_playlist_info: Fetching next page of tracks from {next_tracks_url}")
                        current_headers = {"Authorization": f"Bearer {self.stored_token.access_token}"}
                        paginated_response = requests.get(next_tracks_url, headers=current_headers, timeout=DEFAULT_REQUEST_TIMEOUT)
                        if paginated_response.status_code == 200:
                            paginated_data = paginated_response.json()
                            all_track_items.extend(paginated_data.get('items', []))
                            next_tracks_url = paginated_data.get('next')
                        elif paginated_response.status_code == 401 and not _retry_attempted:
                            self.logger.warning(f"SpotifyAPI.get_playlist_info (pagination): Auth error (401) for {playlist_id}. Invalidating token, attempting re-auth.")
                            self.stored_token = None
                            if self._perform_oauth_flow():
                                self.logger.info("SpotifyAPI.get_playlist_info (pagination): Re-authentication successful. Retrying original call.")
                                return self.get_playlist_info(playlist_id, metadata, _retry_attempted=True)
                            else:
                                self.logger.error("SpotifyAPI.get_playlist_info (pagination): Re-authentication failed.")
                                raise SpotifyAuthError(f"Re-authentication failed for paginated playlist tracks {playlist_id}.")
                        else:
                            self.logger.warning(f"SpotifyAPI.get_playlist_info: Failed to get next page of playlist tracks for {playlist_id} (status: {paginated_response.status_code}). Breaking.")
                            break
                
                if 'tracks' in playlist_data and isinstance(playlist_data['tracks'], dict):
                    playlist_data['tracks']['items'] = all_track_items
                    playlist_data['tracks']['next'] = None # All items fetched
                else:
                    self.logger.warning(f"SpotifyAPI.get_playlist_info: Playlist data for {playlist_id} missing 'tracks' object or not a dict. Reconstructing.")
                    playlist_data['tracks'] = {'items': all_track_items, 'total': len(all_track_items), 'next': None}
                return playlist_data
            elif response.status_code == 401:
                self.logger.warning(f"SpotifyAPI.get_playlist_info: Auth error (401) for {playlist_id}. Token might be invalid.")
                if not _retry_attempted:
                    self.logger.info("SpotifyAPI.get_playlist_info: Attempting re-auth and retry for 401.")
                    self.stored_token = None
                    if self._perform_oauth_flow():
                        self.logger.info("SpotifyAPI.get_playlist_info: Re-auth successful. Retrying call.")
                        return self.get_playlist_info(playlist_id, metadata, _retry_attempted=True)
                    else:
                        self.logger.error("SpotifyAPI.get_playlist_info: Re-auth failed after 401.")
                        raise SpotifyAuthError(f"Re-authentication failed for playlist {playlist_id} after 401.")
                else:
                    self.logger.error(f"SpotifyAPI.get_playlist_info: Auth error (401) for {playlist_id} after retry.")
                    raise SpotifyAuthError(f"Auth failed for playlist {playlist_id} (401) after retry.")
            elif response.status_code == 404:
                self.logger.warning(f"SpotifyAPI.get_playlist_info: Playlist {playlist_id} not found (404).")
                raise SpotifyItemNotFoundError(f"Playlist with ID {playlist_id} not found.")
            else:
                self.logger.error(f"SpotifyAPI.get_playlist_info: Failed for {playlist_id}. Status: {response.status_code}, Response: {response.text[:200]}")
                raise SpotifyApiError(f"Failed for playlist {playlist_id}. Status: {response.status_code}, Text: {response.text[:200]}")

        except requests.exceptions.HTTPError as http_err:
            if http_err.response.status_code == 401:
                self.logger.warning(f"SpotifyAPI.get_playlist_info: HTTPError 401 for {playlist_id}.")
                if not _retry_attempted:
                    self.logger.info("SpotifyAPI.get_playlist_info: Attempting re-auth for HTTPError 401.")
                    self.stored_token = None
                    if self._perform_oauth_flow():
                        self.logger.info("SpotifyAPI.get_playlist_info: Re-auth successful. Retrying call.")
                        return self.get_playlist_info(playlist_id, metadata, _retry_attempted=True)
                    else:
                        self.logger.error("SpotifyAPI.get_playlist_info: Re-auth failed after HTTPError 401.")
                        raise SpotifyAuthError(f"Re-auth failed for playlist {playlist_id} after HTTPError 401.")
                else:
                    self.logger.error(f"SpotifyAPI.get_playlist_info: HTTPError 401 for {playlist_id} after retry.")
                    raise SpotifyAuthError(f"Auth failed for playlist {playlist_id} (HTTPError 401) after retry.")
            else:
                self.logger.error(f"SpotifyAPI.get_playlist_info: HTTPError {http_err.response.status_code} for {playlist_id}: {http_err.response.text[:200]}")
                raise SpotifyApiError(f"HTTP error for playlist {playlist_id}: {http_err.response.status_code} - {http_err.response.text[:200]}") from http_err
        except requests.exceptions.RequestException as e:
            self.logger.error(f"SpotifyAPI.get_playlist_info: RequestException for {playlist_id}: {e}", exc_info=False)
            raise SpotifyApiError(f"Network error for playlist {playlist_id}: {e}")
        except SpotifyAuthError:
             raise
        except Exception as e:
            self.logger.error(f"SpotifyAPI.get_playlist_info: Unexpected error for {playlist_id}: {e}", exc_info=True)
            if isinstance(e, SpotifyApiError):
                raise
            raise SpotifyApiError(f"Unexpected error for playlist {playlist_id}: {e}")

    def get_artist_info(self, artist_id: str, metadata: Optional['ArtistInfo'] = None, _retry_attempted: bool = False) -> Optional['ArtistInfo']:
        self.logger.info(f"SpotifyAPI: Attempting to get artist info for ID: {artist_id}{' (retry)' if _retry_attempted else ''}")

        if not self.stored_token or not self.stored_token.access_token or self.stored_token.expired():
            self.logger.info("SpotifyAPI.get_artist_info: Token missing, invalid or expired. Attempting to load/refresh session.")
            if not self._load_credentials_and_init_session():
                self.logger.error("SpotifyAPI.get_artist_info: Session initialization failed.")
                raise SpotifyAuthError("Authentication required/failed for get_artist_info. Session could not be initialized.")
        
        if not self.stored_token or not self.stored_token.access_token:
            self.logger.error("SpotifyAPI.get_artist_info: Still no access token after session initialization attempt.")
            raise SpotifyAuthError("Authentication failed for get_artist_info. No valid token.")

        artist_api_url = f"https://api.spotify.com/v1/artists/{artist_id}"
        headers = {"Authorization": f"Bearer {self.stored_token.access_token}"}
        artist_data = None

        try:
            self.logger.debug(f"SpotifyAPI.get_artist_info: Getting basic artist details from {artist_api_url}")
            response = requests.get(artist_api_url, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status() # Will raise HTTPError for 4xx/5xx
            artist_data = response.json()
            self.logger.info(f"SpotifyAPI.get_artist_info: Successfully retrieved basic artist data for {artist_id}: {artist_data.get('name')}")
        
        except requests.exceptions.HTTPError as http_err:
            if http_err.response.status_code == 401:
                self.logger.warning(f"SpotifyAPI.get_artist_info (basic details): Auth error (401) for {artist_id}. Token might be invalid.")
                if not _retry_attempted:
                    self.logger.info("SpotifyAPI.get_artist_info (basic details): Attempting re-auth and retry for 401.")
                    self.stored_token = None
                    if self._perform_oauth_flow():
                        self.logger.info("SpotifyAPI.get_artist_info (basic details): Re-auth successful. Retrying call.")
                        return self.get_artist_info(artist_id, metadata, _retry_attempted=True)
                    else:
                        self.logger.error("SpotifyAPI.get_artist_info (basic details): Re-auth failed after 401.")
                        raise SpotifyAuthError(f"Re-authentication failed for artist {artist_id} (basic details) after 401.")
                else:
                    self.logger.error(f"SpotifyAPI.get_artist_info (basic details): Auth error (401) for {artist_id} after retry.")
                    raise SpotifyAuthError(f"Auth failed for artist {artist_id} (basic details) (401) after retry.")
            elif http_err.response.status_code == 404:
                self.logger.warning(f"SpotifyAPI.get_artist_info: Artist {artist_id} not found (404).")
                raise SpotifyItemNotFoundError(f"Artist with ID {artist_id} not found.") from http_err
            else:
                self.logger.error(f"SpotifyAPI.get_artist_info: HTTP error fetching basic artist data for {artist_id}: {http_err.response.status_code} - {http_err.response.text[:200]}", exc_info=False)
                raise SpotifyApiError(f"Failed to get basic artist data for {artist_id}. Status: {http_err.response.status_code}, Text: {http_err.response.text[:200]}") from http_err
        except requests.exceptions.RequestException as req_err:
            self.logger.error(f"SpotifyAPI.get_artist_info: RequestException for basic artist data {artist_id}: {req_err}", exc_info=False)
            raise SpotifyApiError(f"Network error while fetching basic artist data for {artist_id}: {req_err}")
        except SpotifyAuthError: # Re-raise if it's already our specific auth error from session init
             raise
        except Exception as e: # Catch other initial errors like JSONDecodeError, etc.
            self.logger.error(f"SpotifyAPI.get_artist_info: Unexpected error for basic artist data {artist_id}: {e}", exc_info=True)
            if isinstance(e, SpotifyApiError): raise
            raise SpotifyApiError(f"An unexpected error occurred while fetching basic artist data for {artist_id}: {e}")

        if not artist_data:
            return None # Should have been raised as an error above if call failed

        # Fetch albums for the artist
        artist_albums_api_url = f"https://api.spotify.com/v1/artists/{artist_id}/albums"
        album_params = {'include_groups': 'album,single', 'limit': 50}
        if self.user_market:
            album_params['market'] = self.user_market
        
        all_album_items_from_api = []
        current_albums_url = artist_albums_api_url
        # Use a new header dict for album calls, as token might have been refreshed
        current_headers_for_albums = {"Authorization": f"Bearer {self.stored_token.access_token}"}

        try:
            while current_albums_url:
                self.logger.debug(f"SpotifyAPI.get_artist_info: Fetching artist albums from {current_albums_url} with params {album_params if current_albums_url == artist_albums_api_url else 'implicit'}")
                paginated_response = requests.get(current_albums_url, headers=current_headers_for_albums, params=album_params if current_albums_url == artist_albums_api_url else None, timeout=DEFAULT_REQUEST_TIMEOUT)
                
                if paginated_response.status_code == 200:
                    albums_page_data = paginated_response.json()
                    all_album_items_from_api.extend(albums_page_data.get('items', []))
                    current_albums_url = albums_page_data.get('next')
                    album_params = {} # Clear params for subsequent `next` calls as they are full URLs
                elif paginated_response.status_code == 401 and not _retry_attempted:
                    self.logger.warning(f"SpotifyAPI.get_artist_info (albums pagination): Auth error (401) for artist {artist_id}. Invalidating token, attempting re-auth.")
                    self.stored_token = None
                    if self._perform_oauth_flow():
                        self.logger.info("SpotifyAPI.get_artist_info (albums pagination): Re-auth successful. Retrying the entire get_artist_info call.")
                        # Retry the whole get_artist_info, as base artist info might also need re-fetch with new token
                        return self.get_artist_info(artist_id, metadata, _retry_attempted=True)
                    else:
                        self.logger.error("SpotifyAPI.get_artist_info (albums pagination): Re-auth failed.")
                        raise SpotifyAuthError(f"Re-authentication failed for artist {artist_id} albums pagination.")
                else:
                    paginated_response.raise_for_status() # Raise HTTPError for other bad statuses on album fetch
                    # Should not be reached if raise_for_status() works, but as a fallback:
                    self.logger.warning(f"SpotifyAPI.get_artist_info: Breaking album pagination for artist {artist_id} due to status {paginated_response.status_code}.")
                    break
            self.logger.info(f"SpotifyAPI.get_artist_info: Fetched {len(all_album_items_from_api)} album items for artist {artist_id}")

        except requests.exceptions.HTTPError as http_err_albums:
            # This will catch non-401 HTTP errors from album pagination raised by raise_for_status()            
            self.logger.error(f"SpotifyAPI.get_artist_info: HTTP error fetching albums for artist {artist_id}: {http_err_albums.response.status_code} - {http_err_albums.response.text[:200]}", exc_info=False)            
        except requests.exceptions.RequestException as req_err_albums:
            self.logger.error(f"SpotifyAPI.get_artist_info: RequestException for artist albums {artist_id}: {req_err_albums}", exc_info=False)
        except SpotifyAuthError: # Re-raise if it's already our specific auth error
             raise
        except Exception as e_albums: # Other errors during album fetching
            self.logger.error(f"SpotifyAPI.get_artist_info: Unexpected error fetching albums for artist {artist_id}: {e_albums}", exc_info=True)

        simplified_albums_for_artist_info = []
        for album_item in all_album_items_from_api:
            if isinstance(album_item, dict):
                album_cover_url = None
                if album_item.get('images') and len(album_item['images']) > 0:
                    album_cover_url = album_item['images'][0].get('url')
                release_year = 0
                release_date_str = album_item.get('release_date')
                if release_date_str and isinstance(release_date_str, str) and len(release_date_str) >= 4:
                    try: release_year = int(release_date_str[:4])
                    except ValueError: pass
                simplified_albums_for_artist_info.append({
                    'id': album_item.get('id'),
                    'name': album_item.get('name'),
                    'album_type': album_item.get('album_type'),
                    'release_year': release_year,
                    'cover_url': album_cover_url,
                    'total_tracks': album_item.get('total_tracks')
                })
        artist_name = artist_data.get('name', "Unknown Artist")
        artist_image_url = None
        if artist_data.get('images') and len(artist_data['images']) > 0:
            artist_image_url = artist_data['images'][0].get('url')
        try:
            artist_info_obj = ArtistInfo(
                name=artist_name,
                albums=simplified_albums_for_artist_info,
            )
            self.logger.info(f"SpotifyAPI.get_artist_info: Successfully created ArtistInfo object for {artist_name} ({artist_id}) with {len(simplified_albums_for_artist_info)} albums.")
            return artist_info_obj
        except Exception as e_artist_info_create:
            self.logger.error(f"SpotifyAPI.get_artist_info: Error creating ArtistInfo object for {artist_name} ({artist_id}): {e_artist_info_create}", exc_info=True)
            return None

# --- Main function for testing or standalone use (Optional) ---
def main():
    parser = argparse.ArgumentParser(description="Search Spotify via its Web API using librespot for auth.")
    parser.add_argument("search_type", choices=["album", "track", "artist", "playlist", "show", "episode"], help="The type of item to search for.")
    parser.add_argument("query", help="The search query string.")
    parser.add_argument("--limit", type=int, default=5, help="Number of results to display.")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    spotify_client = SpotifyAPI(config={}, module_controller=None)
    try:
        results = spotify_client.search(query_type_enum_or_str=args.search_type, query_str=args.query, limit=args.limit)
        if results:
            print(f"--- Spotify Search Results for '{args.query}' (Type: {args.search_type}) ---")
            for i, item in enumerate(results):
                item_name = item.get("name", "N/A")
                item_id = item.get("id", "N/A")
                display_line = f"  {i+1}. {item_name} [ID: {item_id}]"
                if args.search_type == "track":
                    artists = ", ".join([artist.get("name", "N/A") for artist in item.get("artists", [])])
                    album_name = item.get("album", {}).get("name", "N/A")
                    display_line += f" - Artists: {artists} (Album: {album_name})"
                elif args.search_type == "album":
                    artists = ", ".join([artist.get("name", "N/A") for artist in item.get("artists", [])])
                    display_line += f" - Artists: {artists}"
                elif args.search_type == "artist":
                    genres = ", ".join(item.get("genres", []))
                    pop = item.get("popularity")
                    display_line += f" - Genres: {genres if genres else 'N/A'} (Popularity: {pop if pop is not None else 'N/A'})"
                elif args.search_type == "playlist":
                    owner = item.get("owner", {}).get("display_name", "N/A")
                    tracks_total = item.get("tracks", {}).get("total", "N/A")
                    display_line += f" - Owner: {owner} (Tracks: {tracks_total})"
                elif args.search_type == "show":
                    publisher = item.get("publisher", "N/A")
                    episodes_total = item.get("total_episodes", "N/A")
                    display_line += f" - Publisher: {publisher} (Episodes: {episodes_total})"
                elif args.search_type == "episode":
                    show_name = item.get("show", {}).get("name", "N/A")
                    release_date = item.get("release_date", "N/A")
                    duration_ms = item.get("duration_ms", 0)
                    duration_s = duration_ms // 1000
                    duration_m = duration_s // 60
                    duration_s %= 60
                    display_line += f" - Show: {show_name} (Released: {release_date}, Duration: {duration_m}m{duration_s}s)"
                print(display_line)
            else:
                print(f"No results found for '{args.query}' (Type: {args.search_type}).")
    except SpotifyApiError as e: 
        print(f"A Spotify API error occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        traceback.print_exc()
    finally:
        spotify_client.close_session()

if __name__ == "__main__":
    main()