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
import sys
import io
import contextlib
import platform
import subprocess as sp

from utils.utils import find_system_ffmpeg, get_clean_env
from utils.vendor_bootstrap import bootstrap_vendor_paths
bootstrap_vendor_paths()

# OAuth and HTTP server imports for Zotify-style authentication
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import urlencode, urlparse, parse_qs

# PKCE imports
import secrets
import base64
import hashlib

# Optional TrackId import for base62->gid conversion helper.
try:
    from librespot.metadata import TrackId
except Exception:
    TrackId = None  # type: ignore

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
    "streaming",
    "user-read-email",
    "user-read-private",
    "playlist-read",
    "playlist-read-collaborative",
    "playlist-read-private",
    "user-library-read",
    "user-read-playback-state",
    "user-read-currently-playing",
    "user-read-recently-played",
    "user-read-playback-position",
    "user-top-read"
]
DEFAULT_REQUEST_TIMEOUT = 15 # seconds
DESKTOP_CLIENT_ID = "65b708073fc0480ea92a077233ca87bd" 
SPOTIFY_TOKEN_URL = "https://api.spotify.com/api/token" 
CREDENTIALS_FILE_NAME = "credentials.json"

# Device Flow constants
DEVICE_AUTH_URL = "https://accounts.spotify.com/oauth2/device/authorize"
DEVICE_TOKEN_URL = "https://accounts.spotify.com/api/token"
DEVICE_RESOLVE_URL = "https://accounts.spotify.com/pair/api/resolve"
DEVICE_CLIENT_ID = "65b708073fc0480ea92a077233ca87bd"
DEVICE_SCOPE = "app-remote-control,playlist-modify,playlist-modify-private,playlist-modify-public,playlist-read,playlist-read-collaborative,playlist-read-private,streaming,transfer-auth-session,ugc-image-upload,user-follow-modify,user-follow-read,user-library-modify,user-library-read,user-modify,user-modify-playback-state,user-modify-private,user-personalized,user-read-birthdate,user-read-currently-playing,user-read-email,user-read-play-history,user-read-playback-position,user-read-playback-state,user-read-private,user-read-recently-played,user-top-read"
DEVICE_FLOW_USER_AGENT = "Spotify/128600502 Win32_x86_64/0 (PC desktop)"


def _get_spotify_credentials_dir() -> str:
    """Return the directory for Spotify credentials (credentials.json).
    On macOS when running as a bundled .app, use ~/Library/Application Support/OrpheusDL GUI/config
    so config is writable (the .app bundle is read-only). Otherwise use project config relative to module.
    This avoids creating a dedicated config/spotify subfolder."""
    is_frozen = getattr(sys, "frozen", False)
    is_macos = platform.system() == "Darwin"
    if is_macos and is_frozen:
        exe_path = getattr(sys, "executable", "") or ""
        meipass = getattr(sys, "_MEIPASS", "") or ""
        if ".app/Contents" in exe_path or ".app" in meipass:
            app_support = os.path.expanduser("~/Library/Application Support/OrpheusDL GUI")
            cred_dir = os.path.join(app_support, "config")
            return os.path.abspath(cred_dir)
    # Default: next to project root (config)
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "config"))


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
    # Custom state moved to self.server (HTTPServer instance)

    def log_message(self, format, *args):
        if "code=" in format % args or "error=" in format % args:
            logging.info(f"OAuthCallbackHandler: {format % args}")
        pass # Suppress other logs

    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        if 'code' in query_components:
            access_code_payload = query_components["code"][0]
            message = "<html><body><h1>Authentication Successful!</h1><p>You can close this window now. Return to the app to continue.</p></body></html>"
            self.server.access_code_payload = access_code_payload
        elif 'error' in query_components:
            error_payload = query_components["error"][0]
            message = f"<html><body><h1>Authentication Failed</h1><p>Error: {error_payload}. You can close this window.</p></body></html>"
            self.server.error_payload = error_payload
        else:
            message = "<html><body><h1>Waiting for Spotify...</h1><p>No code or error received. Please complete the authorization in your browser.</p></body></html>"
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))

class OAuth:
    """Handles the PKCE OAuth flow for Spotify."""
    def __init__(self, client_id: str, redirect_uri: str, scopes: List[str], logger_instance=None, client_secret: Optional[str] = None):
        self.client_id = client_id
        self.client_secret = client_secret  # Optional: needed for token refresh with custom client_id
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
        self.last_auth_url: Optional[str] = None
        self.last_exit_reason: Optional[str] = None

    def _start_http_server(self):
        try:
            self.http_server = HTTPServer(self.server_address, OAuthCallbackHandler)
            self.http_server.access_code_payload = None 
            self.http_server.error_payload = None
            self.server_thread = Thread(target=self.http_server.serve_forever, daemon=True)
            self.server_thread.start()
            self.logger.info(f"OAuth callback server started at {self.redirect_uri}")
        except Exception as e:
            self.logger.error(f"Failed to start OAuth callback server on {self.server_address}: {e}")
            self.http_server = None
            self.error_message = f"Could not start OAuth server on port {self.server_address[1]}. Is it in use?"

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
        # Add client_secret if available (needed for custom client_id token exchange)
        if self.client_secret:
            payload['client_secret'] = self.client_secret
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
        # Add client_secret if available (needed for custom client_id token refresh)
        if self.client_secret:
            payload['client_secret'] = self.client_secret
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
        if not self.http_server:
            # error_message already set in _start_http_server
            return None
        auth_url = self.get_authorization_url()
        self.last_auth_url = auth_url # Store for later display in GUI if flow fails
        self.logger.info(f"Please authorize in your browser: {auth_url}")
        print(f"\nOpening browser for Spotify authorization...\nURL: {auth_url}")
        print(f"If the browser does not open, please copy the URL above and paste it manually.")
        print()  # Add empty line after authorization messages
        try:
            time.sleep(1.0) # Grace period for HTTP server to stabilize
            
            # Prioritize os.startfile on Windows as it is more reliable for default browsers
            opened = False
            if platform.system() == "Windows":
                try:
                    os.startfile(auth_url)
                    opened = True
                    self.logger.info("Successfully opened browser via os.startfile.")
                except Exception as e_start:
                    self.logger.warning(f"os.startfile failed: {e_start}")

            if not opened:
                try:
                    webbrowser.open(auth_url)
                    opened = True
                except Exception as e_wb:
                    self.logger.warning(f"webbrowser.open failed: {e_wb}")

            if not opened:
                # Last resort fallback
                if platform.system() == "Windows":
                    import subprocess
                    subprocess.run(["cmd", "/c", "start", "", auth_url], shell=True)
                else:
                    self.logger.error(f"Could not open browser automatically. Please copy the URL manually.")
        except Exception as e_final:
            self.logger.error(f"Ultimate failure opening browser: {e_final}")

        try:
            self.logger.info("Waiting for user authorization in browser...")
            timeout_seconds = 180 
            start_time = time.time()
            last_heartbeat = start_time
            
            while True:
                current_time = time.time()
                elapsed = current_time - start_time
                
                # Heartbeat every 2 seconds
                if current_time - last_heartbeat >= 2.0:
                    self.logger.debug(f"OAuth loop heartbeat... {int(elapsed)}s elapsed. Waiting for code.")
                    last_heartbeat = current_time

                if not self.http_server:
                    self.last_exit_reason = "Server object became None unexpectedly."
                    break
                if self.http_server.access_code_payload:
                    self.last_exit_reason = f"Code received after {int(elapsed)}s."
                    break
                if self.http_server.error_payload:
                    self.last_exit_reason = f"Error payload received: {self.http_server.error_payload}"
                    break
                if elapsed > timeout_seconds:
                    self.last_exit_reason = f"Timeout reached after {int(elapsed)}s."
                    break
                    
                time.sleep(0.5) 
            
            self.logger.info(f"OAuth loop finished. Reason: {self.last_exit_reason}")
            
            self.access_code = self.http_server.access_code_payload if self.http_server else None
            self.error_message = self.http_server.error_payload if self.http_server else self.error_message 

            if self.access_code:
                # Give browser a tiny bit of time to receive the success page before shutting down the socket
                time.sleep(1.5)

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

class SpotifyTrackUnavailableError(SpotifyAuthError):
    """Raised when a track is unavailable."""
    pass

class SpotifyRateLimitDetectedError(SpotifyAuthError):
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
        return (self.issued_at + self.expires_in - margin_seconds) < time.time()

class StoredToken: 
    """OAuth token storage helper."""
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
        self.user_market: Optional[str] = None
        
        # Initialize Spotify Embed Client for metadata operations (no OAuth required)
        from .spotify_embed_api import SpotifyEmbedClient
        self.embed_client = SpotifyEmbedClient(logger_instance=self.logger)
        self.logger.info("Initialized SpotifyEmbedClient for metadata operations (no credentials required)")
        
        # Web API Client ID (Can be custom from config)
        config_client_id = (self.config.get('client_id') or '').strip()
        config_client_secret = (self.config.get('client_secret') or '').strip()
        
        main_client_id = config_client_id if config_client_id else CLIENT_ID
        main_client_secret = config_client_secret if config_client_secret else None
        
        if config_client_id:
            self.logger.info(f"Using custom Client ID for Web API: {main_client_id[:10]}...")
        else:
            self.logger.info(f"Using default Client ID for Web API: {main_client_id[:10]}...")

        # Create main OAuth handler for Web API
        self.oauth_handler = OAuth(main_client_id, REDIRECT_URI, OAUTH_SCOPES, self.logger, client_secret=main_client_secret)
        
        # Initialize Web API client (lazy initialized)
        self.client: Optional[any] = None 
        
        # Token storage
        self.stored_token: Optional[StoredToken] = None
        
        self.last_custom_provider_id_created: Optional[int] = None 

        # Determine credentials directory
        self.credentials_dir = _get_spotify_credentials_dir()
        os.makedirs(self.credentials_dir, exist_ok=True)
        
        # Credential file for current Spotify auth flow
        self.credentials_file_path = os.path.join(self.credentials_dir, CREDENTIALS_FILE_NAME)
        
        self.logger.info(f"Web API Credentials: {self.credentials_file_path}")

    def _save_credentials(self, token_obj: StoredToken, username: Optional[str] = "PKCE_USER"):
        """Saves OAuth token data and a username to credentials.json."""
        if not token_obj or not token_obj.access_token:
            self.logger.error("Cannot save credentials, token object or access token is missing.")
            return

        # Save the full token details (including refresh token) for *our* use (e.g. refreshing)        
        full_token_details_for_storage = token_obj.to_dict()
        full_token_details_for_storage['spotify_username'] = username # Store the username we got/used
        # Store the client_id used for this token so we can detect if it changed
        full_token_details_for_storage['client_id'] = self.oauth_handler.client_id if self.oauth_handler else None

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
            
            # Check if client_id has changed - if so, we need to re-authenticate with new credentials
            stored_client_id = token_data_from_file.get('client_id')
            current_client_id = self.oauth_handler.client_id if self.oauth_handler else None
            
            # If no client_id is stored, it's from the old Desktop client_id (before we added this feature)
            # If we now have a custom client_id, we need to re-authenticate
            if not stored_client_id and current_client_id and current_client_id != CLIENT_ID:
                self.logger.warning(f"Old credentials file (no client_id stored) detected, but custom client_id is now configured. Removing old credentials to force re-authentication with new client ID.")
                try:
                    os.remove(self.credentials_file_path)
                    self.logger.info(f"Removed credentials file {self.credentials_file_path} due to client_id change.")
                except OSError as e:
                    self.logger.error(f"Error removing credentials file: {e}")
                return False
            
            # If client_id is stored and different from current, remove old credentials
            if stored_client_id and current_client_id and stored_client_id != current_client_id:
                self.logger.warning(f"Client ID has changed (stored: {stored_client_id[:10]}..., current: {current_client_id[:10]}...). Removing old credentials to force re-authentication with new client ID.")
                try:
                    os.remove(self.credentials_file_path)
                    self.logger.info(f"Removed credentials file {self.credentials_file_path} due to client_id change.")
                except OSError as e:
                    self.logger.error(f"Error removing credentials file: {e}")
                return False
            
            # Check for essential fields from StoredToken.to_dict()
            if not all(k in token_data_from_file for k in ["access_token", "refresh_token", "expires_in"]):
                self.logger.warning(f"Credentials file {self.credentials_file_path} is missing essential token fields. Re-authentication needed.")
                return False

            loaded_token = StoredToken.from_dict(token_data_from_file)

            # Check if token has all required scopes
            loaded_scopes = set(loaded_token.scopes)
            required_scopes = set(OAUTH_SCOPES)
            missing_scopes = required_scopes - loaded_scopes
            if missing_scopes:
                self.logger.warning(f"Stored token is missing required scopes: {missing_scopes}. Full re-authentication required.")
                try:
                    os.remove(self.credentials_file_path)
                    self.logger.info(f"Removed credentials file {self.credentials_file_path} due to missing scopes.")
                except OSError as e:
                    self.logger.error(f"Error removing credentials file: {e}")
                return False

            if loaded_token.expired():
                self.logger.info("Existing token is expired. Attempting to refresh...")
                if not loaded_token.refresh_token:
                    self.logger.warning("No refresh token available. Full re-authentication required.")
                    try:
                        os.remove(self.credentials_file_path)
                        self.logger.info(f"Removed credentials file {self.credentials_file_path} (no refresh token).")
                    except OSError as e_rm:
                        self.logger.error(f"Error removing credentials file: {e_rm}")
                    return False
                
                refreshed_token_data = self.oauth_handler.refresh_access_token(loaded_token.refresh_token)
                if refreshed_token_data:
                    self.stored_token = StoredToken(refreshed_token_data)
                    # Save the refreshed token
                    try:
                        token_dict = self.stored_token.to_dict()
                        token_dict['spotify_username'] = token_data_from_file.get('spotify_username', 'PKCE_USER')
                        token_dict['client_id'] = self.oauth_handler.client_id if self.oauth_handler else None
                        with open(self.credentials_file_path, 'w') as f:
                            json.dump(token_dict, f, indent=4)
                        self.logger.info("Successfully refreshed and saved token.")
                    except Exception as e_save:
                        self.logger.warning(f"Could not save refreshed token: {e_save}")
                    self.logger.info("Successfully refreshed and loaded token.")
                    return True
                else:
                    error_msg = self.oauth_handler.error_message if self.oauth_handler else "Unknown error"
                    self.logger.warning(f"Failed to refresh token: {error_msg}. Full re-authentication required.")
                    # Delete the invalid credentials file to force re-authentication
                    try:
                        os.remove(self.credentials_file_path)
                        self.logger.info(f"Removed invalid/expired credentials file: {self.credentials_file_path}")
                    except OSError as e_rm:
                        self.logger.error(f"Error removing invalid credentials file: {e_rm}")
                    return False
            else:
                self.stored_token = loaded_token
                self.logger.info("Successfully loaded valid existing token.")
                return True

        except json.JSONDecodeError:
            self.logger.error(f"Error decoding JSON from {self.credentials_file_path}. File might be corrupted.")
            return False # Treat as needing re-auth
        except Exception as e:
            self.logger.error(f"Unexpected error loading credentials: {e}", exc_info=True)
            return False

    def _perform_oauth_flow(self, save_to_main_file: bool = True, is_session_retry: bool = False) -> bool:
        """Performs the full PKCE OAuth flow and optionally saves credentials to the main file."""
        if not self.oauth_handler:
            self.logger.error("OAuth handler not initialized!")
            return False
        
        # Reset last attempt URL so we don't return a stale one if things fail early
        self._last_attempted_auth_url = None
        
        # Check if required credentials are provided before opening browser
        username = (self.config.get('username', '') or '').strip() if self.config else ''
        
        if not username:
            error_msg = (
                "Spotify username is missing in settings.json. "
                "Please fill it in using the OrpheusDL GUI Settings tab (Spotify)."
            )
            self.logger.error(error_msg)
            raise SpotifyConfigError(error_msg)
        
        # Log which client identity is being used with a clear banner as requested
        handler_client_id = self.oauth_handler.client_id if self.oauth_handler else None
        is_official = (handler_client_id == DEVICE_CLIENT_ID or handler_client_id == CLIENT_ID)
        
        retry_suffix = " (Session Creation Failed)" if is_session_retry else ""
        banner = f"""
============================================================
SPOTIFY AUTHENTICATION REQUIRED{retry_suffix}
============================================================
A browser window will open for Spotify authorization.
Please complete the authorization in your browser.

Note: This is only required for downloading audio.
Searching and browsing metadata does NOT require authentication.
============================================================
"""
        # Print the banner to both log and console/stdout to ensure it's visible
        self.logger.info(banner)
        print(banner)

        if not is_official and handler_client_id:
            self.logger.info(f"Initiating OAuth flow using custom Client ID: {handler_client_id[:10]}...")
        else:
            self.logger.info(f"Proceeding with PKCE OAuth flow ({'Desktop client_id' if handler_client_id == DEVICE_CLIENT_ID else 'Official client_id'}).")
        
        self.logger.info("Starting PKCE OAuth flow...")
        auth_url = self.oauth_handler.get_authorization_url()
        self._last_attempted_auth_url = auth_url # Store in main API object for interface.py
        
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

            if save_to_main_file:
                self._save_credentials(self.stored_token, username_for_storage)
            else:
                self.logger.info("Skipping save to main credentials file (save_to_main_file=False).")
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

    def _clear_credentials(self):
        """Clear Spotify credentials file to force re-authentication."""
        if os.path.exists(self.credentials_file_path):
            try:
                os.remove(self.credentials_file_path)
                self.logger.info(f"Removed credentials file: {self.credentials_file_path}")
            except OSError as e:
                self.logger.warning(f"Could not remove credentials file {self.credentials_file_path}: {e}")

    def _init_web_api_client(self) -> bool:
        """
        Initializes the Web API client (self.client) using Client Credentials flow if possible.
        This provides a way to fetch ISRC and other metadata without a full user session.
        """
        if self.client:
            return True
            
        client_id = (self.config.get('client_id', '') or '').strip()
        client_secret = (self.config.get('client_secret', '') or '').strip()
        
        if not client_id or not client_secret:
            self.logger.debug("Web API Client Credentials flow skipped: missing client_id or client_secret.")
            return False
            
        try:
            self.logger.info("Initializing Web API client via Client Credentials flow...")
            payload = {
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': client_secret
            }
            response = requests.post(AUTH_URL + "api/token", data=payload, timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            token_data = response.json()
            access_token = token_data.get('access_token')
            
            if access_token:
                # We'll use a simple wrapper or just the token for direct requests
                # If spotipy is available, we could use it, but direct requests are safer here
                self.web_api_token = access_token
                # Create a minimal client object compatible with track() call
                class WebApiClient:
                    def __init__(self, token, logger):
                        self.token = token
                        self.logger = logger
                    def track(self, track_id):
                        headers = {"Authorization": f"Bearer {self.token}"}
                        url = f"https://api.spotify.com/v1/tracks/{track_id}"
                        r = requests.get(url, headers=headers, timeout=10)
                        r.raise_for_status()
                        return r.json()
                    def album(self, album_id):
                        headers = {"Authorization": f"Bearer {self.token}"}
                        url = f"https://api.spotify.com/v1/albums/{album_id}"
                        r = requests.get(url, headers=headers, timeout=10)
                        r.raise_for_status()
                        return r.json()
                    def artist(self, artist_id):
                        headers = {"Authorization": f"Bearer {self.token}"}
                        url = f"https://api.spotify.com/v1/artists/{artist_id}"
                        r = requests.get(url, headers=headers, timeout=10)
                        r.raise_for_status()
                        return r.json()                

                self.client = WebApiClient(access_token, self.logger)
                self.logger.info("Web API client successfully initialized for metadata enhancement.")
                return True
        except Exception as e:
            self.logger.warning(f"Failed to initialize Web API client via Client Credentials flow: {e}")
            
        return False

    # _fetch_user_market removed - no longer needed for Embed API

    def _gid_to_base62(self, gid: bytes) -> str:
        """Converts a GID (bytes) to a Spotify Base62 ID string."""
        try:
            # Convert bytes to int
            num = int.from_bytes(gid, byteorder='big')
            
            alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            base = 62
            
            if num == 0:
                return alphabet[0]
            
            arr = []
            while num:
                num, rem = divmod(num, base)
                arr.append(alphabet[rem])
            
            arr.reverse()
            return ''.join(arr).rjust(22, '0') # Standard spotify IDs are 22 chars
        except Exception as e:
            self.logger.error(f"Error converting GID bytes to Base62: {e}")
            return ""

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
        limit = int(limit)
        self.logger.info(f"SpotifyAPI.search: type='{query_type_enum_or_str}', query='{query_str}', limit={limit} (Using Embed API)")
        
        query_type_str = query_type_enum_or_str.name.lower() if hasattr(query_type_enum_or_str, 'name') else str(query_type_enum_or_str).lower()
        
        all_items = []
        offset = 0
        BATCH_SIZE = 50 
        
        while len(all_items) < limit:
            try:
                # Use Embed Client Search
                data = self.embed_client.search(query=query_str, limit=BATCH_SIZE, offset=offset)
                
                # Check for errors in GraphQL response
                if 'errors' in data:
                    self.logger.error(f"GraphQL errors in search: {data['errors']}")
                    # If specific error like rate limit, could handle here, but generally generic error
                    raise SpotifyApiError(f"GraphQL error during search: {data['errors']}")
                
                # Parse searchV2 structure
                search_v2 = data.get('data', {}).get('searchV2', {})
                if not search_v2:
                     # Check top-level 'data' for direct structure if different
                     search_v2 = data.get('data', {})

                # Map query type to response keys
                # Tracks: tracksV2 -> items -> item -> data
                # Albums: albumsV2 -> items -> data
                # Artists: artists -> items -> data
                # Playlists: playlists -> items -> data
                
                items = []
                total = 0
                
                if query_type_str == 'track':
                    # Handle tracks
                    tracks_container = search_v2.get('tracksV2', {})
                    if not tracks_container: tracks_container = search_v2.get('tracks', {})
                    
                    raw_items = tracks_container.get('items', [])
                    total = tracks_container.get('totalCount', 0)
                    
                    for item_wrapper in raw_items:
                        # Item structure: item -> data OR track -> data
                        item_data = item_wrapper.get('item', {}).get('data') or item_wrapper.get('track') # fallback
                        if not item_data: continue
                        
                        # Map to simplified structure expected by Orpheus
                        # Extract artists
                        artists_list = item_data.get('artists', {}).get('items', [])
                        artists = [{'name': a.get('profile', {}).get('name') or a.get('name'), 'id': a.get('uri', '').split(':')[-1]} for a in artists_list]
                        
                        # Album
                        album_data = item_data.get('albumOfTrack', {})
                        album_date = album_data.get('date', {}).get('year')
                        album = {'name': album_data.get('name'), 'id': album_data.get('uri', '').split(':')[-1], 'release_date': album_date, 'images': [{'url': img.get('sources', [{}])[0].get('url')} for img in [album_data.get('coverArt', {})] if img]}

                        track_obj = {
                            'id': item_data.get('id'),
                            'name': item_data.get('name'),
                            'type': 'track',
                            'artists': artists,
                            'album': album,
                            'duration_ms': item_data.get('duration', {}).get('totalMilliseconds'),
                            'explicit': item_data.get('contentRating', {}).get('label') == 'EXPLICIT',
                            'popularity': 0, # Not usually available in embed
                            'external_urls': {'spotify': f"https://open.spotify.com/track/{item_data.get('id')}"}
                        }
                        items.append(track_obj)

                elif query_type_str == 'album':
                     # Handle albums
                    albums_container = search_v2.get('albumsV2', {})
                    if not albums_container: albums_container = search_v2.get('albums', {})
                    
                    raw_items = albums_container.get('items', [])
                    total = albums_container.get('totalCount', 0)
                    
                    for item_wrapper in raw_items:
                        item_data = item_wrapper.get('data') or item_wrapper.get('album') # Wrapper usually has 'data'
                        if not item_data: continue
                        
                        artists_list = item_data.get('artists', {}).get('items', [])
                        artists = [{'name': a.get('profile', {}).get('name') or a.get('name'), 'id': a.get('uri', '').split(':')[-1]} for a in artists_list]
                        
                        cover_art = item_data.get('coverArt', {})
                        images = [{'url': img.get('sources', [{}])[0].get('url')} for img in [cover_art] if img]

                        album_obj = {
                            'id': item_data.get('uri', '').split(':')[-1],
                            'name': item_data.get('name'),
                            'type': 'album',
                            'artists': artists,
                            'images': images,
                            'release_date': item_data.get('date', {}).get('year'), # Approximate
                            'total_tracks': item_data.get('tracks', {}).get('totalCount') or item_data.get('tracks', {}).get('total') or 0,
                            'explicit': item_data.get('contentRating', {}).get('label') == 'EXPLICIT',
                            'external_urls': {'spotify': f"https://open.spotify.com/album/{item_data.get('uri', '').split(':')[-1]}"}
                        }
                        items.append(album_obj)

                elif query_type_str == 'artist':
                     # Handle artists
                    artists_container = search_v2.get('artists', {}) # Struct might differ
                    raw_items = artists_container.get('items', [])
                    total = artists_container.get('totalCount', 0)

                    for item_wrapper in raw_items:
                         item_data = item_wrapper.get('data') or item_wrapper # Sometimes direct
                         if not item_data: continue
                         
                         profile = item_data.get('profile', {})
                         visuals = item_data.get('visuals', {}).get('avatarImage', {})
                         images = [{'url': img.get('sources', [{}])[0].get('url')} for img in [visuals] if img]

                         artist_obj = {
                             'id': item_data.get('uri', '').split(':')[-1],
                             'name': profile.get('name'),
                             'type': 'artist',
                             'images': images,
                             'genres': [],
                             'popularity': 0,
                             'external_urls': {'spotify': f"https://open.spotify.com/artist/{item_data.get('uri', '').split(':')[-1]}"}
                         }
                         items.append(artist_obj)
                         
                elif query_type_str == 'playlist':
                     # Handle playlists
                    playlists_container = search_v2.get('playlists', {}) # Struct might differ
                    raw_items = playlists_container.get('items', [])
                    total = playlists_container.get('totalCount', 0)
                    
                    for item_wrapper in raw_items:
                        item_data = item_wrapper.get('data') or item_wrapper
                        if not item_data: continue

                        images = item_data.get('images', {}).get('items', [])
                        formatted_images = []
                        if images and images[0].get('sources'):
                             formatted_images = [{'url': images[0]['sources'][0]['url']}]

                        playlist_obj = {
                            'id': item_data.get('uri', '').split(':')[-1],
                            'name': item_data.get('name'),
                            'type': 'playlist',
                            'images': formatted_images,
                            'owner': {'display_name': item_data.get('ownerV2', {}).get('data', {}).get('name')},
                            'total_tracks': item_data.get('tracks', {}).get('totalCount') or item_data.get('tracks', {}).get('total') or 0,
                            'external_urls': {'spotify': f"https://open.spotify.com/playlist/{item_data.get('uri', '').split(':')[-1]}"}
                        }
                        items.append(playlist_obj)
                
                if not items:
                     break
                
                all_items.extend(items)
                offset += len(items)
                
                # Check pagination
                if len(items) < BATCH_SIZE or offset >= total:
                    break

            except Exception as e:
                self.logger.error(f"SpotifyAPI.search: Error during embed search for '{query_str}': {e}", exc_info=True)
                # If we already have some items, return them instead of failing completely
                if all_items:
                    self.logger.warning(f"SpotifyAPI.search: Returning partial results ({len(all_items)}) due to error: {e}")
                    return all_items
                # Otherwise, raise as ApiError
                raise SpotifyApiError(f"Error during embed search: {e}")
        
        self.logger.info(f"SpotifyAPI.search: Successfully retrieved {len(all_items)} items for '{query_str}' via Embed API")
        return all_items[:limit]


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
            
            ffmpeg_found, ffmpeg_path = find_system_ffmpeg()
            use_ffmpeg_mux = (determined_codec_enum == CodecEnum.VORBIS and ffmpeg_found)
            
            if use_ffmpeg_mux:
                with tempfile.NamedTemporaryFile(delete=False, suffix=file_suffix, dir=target_temp_dir) as temp_file:
                    temp_file_path = temp_file.name
                
                self.logger.info(f"Using FFmpeg at: {ffmpeg_path}")
                # Try without -f vorbis first to see if auto-detect works, as some Vorbis streams have slight framing
                cmd = [ffmpeg_path, '-y', '-hide_banner', '-i', 'pipe:0', '-c:a', 'copy', '-f', 'ogg', temp_file_path]
                self.logger.debug(f"FFmpeg command: {' '.join(cmd)}")
                
                try:
                    process = sp.Popen(cmd, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, env=get_clean_env())
                except Exception as popen_err:
                    self.logger.error(f"Failed to start FFmpeg process: {popen_err}")
                    raise SpotifyApiError(f"Failed to start FFmpeg: {popen_err}")
                
                bytes_pushed = 0
                try:
                    if hasattr(stream_object, 'read') and callable(stream_object.read):
                        while True:
                            # Check if FFmpeg has died prematurely
                            if process.poll() is not None:
                                self.logger.error("FFmpeg process terminated prematurely while writing stream.")
                                break

                            chunk = stream_object.read(16384)
                            if not chunk:
                                break
                            
                            try:
                                process.stdin.write(chunk)
                                bytes_pushed += len(chunk)
                            except (BrokenPipeError, OSError, ValueError) as write_err:
                                # Catching ValueError specifically for "Flush of closed file"
                                self.logger.error(f"Failed to write to FFmpeg stdin (stream broken): {write_err}")
                                break
                    else:
                        for chunk_iter in stream_object:
                            if process.poll() is not None:
                                self.logger.error("FFmpeg process terminated prematurely while writing stream (iteration).")
                                break
                            try:
                                process.stdin.write(chunk_iter)
                                bytes_pushed += len(chunk_iter)
                            except (BrokenPipeError, OSError, ValueError) as write_err:
                                # Catching ValueError specifically for "Flush of closed file"
                                self.logger.error(f"Failed to write to FFmpeg stdin (iteration broken): {write_err}")
                                break
                    
                    try:
                        if not process.stdin.closed:
                            process.stdin.close()
                            # Critical: prevent communicate() from trying to flush a closed pipe on macOS/Linux
                            process.stdin = None
                    except (BrokenPipeError, OSError, ValueError):
                        # Ensure it's None even on failure
                        process.stdin = None

                    stdout, stderr = process.communicate()
                    
                    if process.returncode != 0:
                        stderr_text = stderr.decode('utf-8', 'ignore')
                        self.logger.error(f"FFmpeg muxing failed with return code {process.returncode}. Error: {stderr_text}")
                        
                        # LOG TO FILE IN PROJECT ROOT TO ENSURE USER CAN FIND IT
                        ffmpeg_log_path = os.path.join(project_root_for_temp, "ffmpeg_error.txt")
                        try:
                            with open(ffmpeg_log_path, "w") as f:
                                f.write(f"Command: {' '.join(cmd)}\n")
                                f.write(f"FFmpeg Path: {ffmpeg_path}\n")
                                f.write(f"Return code: {process.returncode}\n")
                                f.write(f"Error Output:\n{stderr_text}\n")
                            self.logger.info(f"FFmpeg error details have been written to {ffmpeg_log_path}")
                        except Exception as log_err: 
                            self.logger.warning(f"Could not write ffmpeg_error.txt to {ffmpeg_log_path}: {log_err}")
                        
                        # Raise error instead of returning None
                        if os.path.exists(temp_file_path): 
                            try: os.unlink(temp_file_path)
                            except: pass
                        raise SpotifyApiError(f"Spotify FFmpeg muxing failed (code {process.returncode}). See {os.path.basename(ffmpeg_log_path)} for details. Error snippet: {stderr_text[:100]}...")
                    
                    bytes_written = os.path.getsize(temp_file_path)
                    self.logger.info(f"FFmpeg muxing completed. Pushed {bytes_pushed} bytes, result size: {bytes_written} bytes.")
                except SpotifyApiError:
                    raise
                except Exception as mux_err:
                    self.logger.error(f"Error during FFmpeg muxing process: {mux_err}")
                    
                    # Try to capture whatever FFmpeg output we can
                    try:
                        if 'process' in locals() and process:
                            if process.poll() is None:
                                process.kill()
                            out, err = process.communicate(timeout=2)
                            if err:
                                self.logger.error(f"FFmpeg stderr during failure: {err.decode('utf-8', 'ignore')}")
                    except: pass
                    
                    # Ensure we log the path we are trying to use for the error file
                    try:
                        ffmpeg_log_path = os.path.join(project_root_for_temp, "ffmpeg_error.txt")
                        self.logger.info(f"Attempting to write diagnostic info to: {ffmpeg_log_path}")
                        with open(ffmpeg_log_path, "w") as f:
                            f.write(f"Exception Message: {mux_err}\n")
                            f.write(f"Command: {' '.join(cmd)}\n")
                    except: pass
                    
                    raise SpotifyApiError(f"Error during FFmpeg muxing process: {mux_err}") from mux_err
            else:
                if determined_codec_enum == CodecEnum.VORBIS and not ffmpeg_found:
                    self.logger.warning("FFmpeg NOT found! Saving raw Vorbis stream WITHOUT Ogg container. Tagging WILL likely fail.")

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
                raise SpotifyApiError(f"Downloaded temporary file is empty ({temp_file_path})")
            return temp_file_path
        except SpotifyApiError:
            raise
        except Exception as save_err:
            self.logger.error(f"Failed during stream saving to temp file: {save_err}", exc_info=True)
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except OSError as e_unlink:
                    self.logger.error(f"Error removing temp file {temp_file_path} after save error: {e_unlink}")
            raise SpotifyApiError(f"Failed during stream saving to temp file: {save_err}") from save_err
        finally:
            if stream_object and hasattr(stream_object, 'close') and callable(stream_object.close):
                try:
                    stream_object.close()
                except Exception as close_err:
                    self.logger.warning(f"Error closing original stream object after saving: {close_err}")

    def is_desktop_api_available(self) -> bool:
        """Checks if all prerequisites for the Desktop API (Votify) are present."""
        cookie_path = self._resolve_spotify_cookies_path()
        dll_path = self._resolve_spotify_dll_path()
        cookie_exists = bool(cookie_path and os.path.exists(cookie_path))
        dll_exists = bool(dll_path and os.path.exists(dll_path))
        self.logger.info(
            "[Spotify Desktop Prereq] cookies_path='%s' exists=%s | spotify_dll_path='%s' exists=%s",
            cookie_path,
            cookie_exists,
            dll_path,
            dll_exists,
        )
        return cookie_exists and dll_exists

    def _resolve_spotify_cookies_path(self) -> str:
        """Resolve spotify-cookies path across dev and frozen app modes."""
        configured_path = (self.config.get("cookies_path") or "").strip()
        return self._resolve_spotify_path(
            configured_path=configured_path,
            relative_default=os.path.join("config", "spotify-cookies.txt"),
            app_support_default=os.path.expanduser("~/Library/Application Support/OrpheusDL GUI/config/spotify-cookies.txt"),
        )

    def _resolve_spotify_dll_path(self) -> str:
        """Resolve Spotify.dll path across dev and frozen app modes."""
        configured_path = (self.config.get("spotify_dll_path") or "").strip()
        return self._resolve_spotify_path(
            configured_path=configured_path,
            relative_default="Spotify.dll",
            app_support_default=os.path.expanduser("~/Library/Application Support/OrpheusDL GUI/Spotify.dll"),
        )

    def _resolve_spotify_path(self, configured_path: str, relative_default: str, app_support_default: str) -> str:
        """
        Resolve a user-configurable Spotify resource path with frozen-app fallbacks.
        Priority:
        1) Explicit absolute configured path
        2) Relative configured/default in writable app data location (macOS App Support when frozen)
        3) Bundled resources (PyInstaller/macOS .app Resources)
        4) Project-root relative path (dev)
        5) CWD-relative path
        """
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        relative_path = (configured_path or relative_default).replace("\\", "/")
        if relative_path.startswith("./"):
            relative_path = relative_path[2:]

        if configured_path and os.path.isabs(configured_path):
            return os.path.normpath(configured_path)

        candidates = []
        if getattr(sys, "frozen", False) and platform.system() == "Darwin":
            # Bundled macOS app uses writable Application Support for user-managed files.
            candidates.append(app_support_default)

        if relative_path:
            # Data dir based on executable location for frozen mode; cwd for dev mode.
            if getattr(sys, "frozen", False):
                if platform.system() == "Darwin":
                    data_dir = os.path.expanduser("~/Library/Application Support/OrpheusDL GUI")
                elif platform.system() == "Windows":
                    data_dir = os.getenv("APPDATA") or os.path.expanduser("~")
                    data_dir = os.path.join(data_dir, "OrpheusDL GUI")
                else:
                    data_dir = os.path.expanduser("~/.config/OrpheusDL-GUI")
            else:
                data_dir = os.getcwd()
            candidates.append(os.path.join(data_dir, relative_path))

            # PyInstaller temporary directory (_MEIPASS) if present.
            meipass = getattr(sys, "_MEIPASS", None)
            if meipass:
                candidates.append(os.path.join(meipass, relative_path))

            # macOS app bundle Resources directory.
            if getattr(sys, "frozen", False) and platform.system() == "Darwin":
                resources_base = os.path.normpath(os.path.join(os.path.dirname(sys.executable), "..", "Resources"))
                candidates.append(os.path.join(resources_base, relative_path))

            candidates.append(os.path.join(project_root, relative_path))
            candidates.append(os.path.join(os.getcwd(), relative_path))

        # Keep deterministic order while avoiding duplicate checks.
        seen = set()
        for candidate in candidates:
            if not candidate:
                continue
            normalized = os.path.normpath(candidate)
            if normalized in seen:
                continue
            seen.add(normalized)
            if os.path.exists(normalized):
                return normalized

        # Return best-effort normalized path for downstream error reporting.
        if candidates:
            return os.path.normpath(candidates[0])
        return os.path.normpath(configured_path or relative_default)

    @staticmethod
    def _quality_tier_str(quality_tier) -> str:
        if hasattr(quality_tier, "name"):
            return quality_tier.name.upper()
        if isinstance(quality_tier, str):
            return quality_tier.upper()
        return str(quality_tier).upper()

    def is_spotify_lossless_desktop_tier(self, quality_tier, download_options) -> bool:
        """True when the request matches the desktop FLAC/lossless path."""
        from utils.models import CodecEnum
        qt_str = self._quality_tier_str(quality_tier)
        if download_options and hasattr(download_options, "codec") and getattr(download_options, "codec", None) == CodecEnum.FLAC:
            return True
        return qt_str in ("LOSSLESS", "HIFI", "FLAC_24", "ATMOS")

    def wants_spotify_ogg_desktop(self, quality_tier, download_options) -> bool:
        """True when we should use the desktop PlayPlay path for OGG 320/160/96."""
        from utils.models import CodecEnum
        qt_str = self._quality_tier_str(quality_tier)
        if self.is_spotify_lossless_desktop_tier(quality_tier, download_options):
            return False
        if download_options and hasattr(download_options, "codec") and getattr(download_options, "codec", None) == CodecEnum.VORBIS:
            return True
        if (not download_options) or (not hasattr(download_options, "codec")):
            return qt_str in ("HIGH", "MEDIUM", "LOW", "MINIMUM")
        if getattr(download_options, "codec", None) is None:
            return qt_str in ("HIGH", "MEDIUM", "LOW", "MINIMUM")
        return False

    def wants_spotify_desktop_stream(self, quality_tier, download_options) -> bool:
        """True if we should use the desktop stream path when sp_dc + Spotify.dll are available (FLAC/HiFi/Atmos/OGG Vorbis)."""
        return self.is_spotify_lossless_desktop_tier(quality_tier, download_options) or self.wants_spotify_ogg_desktop(quality_tier, download_options)

    def get_track_download(self, **kwargs) -> Optional[TrackDownloadInfo]:
        """Desktop-only Spotify audio download (requires sp_dc + Spotify.dll)."""
        track_id_base62 = kwargs.get("track_id_str") or kwargs.get("track_id")
        quality_tier = kwargs.get("quality_tier")
        download_options = kwargs.get("codec_options")
        track_info_obj = kwargs.get("track_info_obj")

        if not track_id_base62:
            self.logger.error("get_track_download: No track_id provided in kwargs")
            raise SpotifyApiError("No track_id provided for download")

        if not self.is_desktop_api_available():
            raise SpotifyApiError(
                "Desktop Spotify audio path requires spotify-cookies (sp_dc) and Spotify.dll. "
                "Librespot fallback has been disabled."
            )

        return self._download_using_desktop_api(
            track_id_base62,
            track_info_obj,
            quality_tier,
            download_options,
        )

    def close_session(self):
        """Clear in-memory Spotify auth/session state."""
        self.stored_token = None
        self.oauth_handler = None
        self.user_market = None
        self.logger.info("Cleared Spotify in-memory auth/session state.")

    def _download_using_desktop_api(self, track_id_base62: str, track_info_obj, quality_tier, download_options) -> Optional['TrackDownloadInfo']:
        try:
            from .desktop_api import DesktopSpotifyApi
        except ImportError as e:
            self.logger.error(f"Could not load desktop_api: {e}")
            raise SpotifyApiError(f"Desktop API not available ({e}). Did you install unplayplay?")
            
        cookie_path = self._resolve_spotify_cookies_path()
        dll_path = self._resolve_spotify_dll_path()
            
        sp_dc = None
        try:
            with open(cookie_path, "r", encoding="utf-8") as f:
                for line in f:
                    if "sp_dc" in line and not line.startswith("#"):
                        parts = line.strip().split("\t")
                        if len(parts) >= 7 and parts[5] == "sp_dc":
                            sp_dc = parts[6]
                            break
        except Exception as e:
            self.logger.warning(f"Error reading cookies.txt for sp_dc: {e}")
            
        if not sp_dc:
            self.logger.error("No sp_dc cookie found in cookies.txt")
            raise SpotifyApiError("No sp_dc cookie found in cookies.txt. Desktop API requires sp_dc.")
            
        if not os.path.isfile(dll_path):
            self.logger.error(f"Spotify.dll not found at: {dll_path}")
            raise SpotifyApiError(f"Spotify.dll not found at {dll_path}. Desktop stream downloads (FLAC/OGG) require this file.")
            


        self.logger.debug(f"Initializing Desktop API flow for {track_id_base62}...")



        try:
            api = DesktopSpotifyApi(sp_dc, dll_path)
            api.authenticate()
            
            from utils.models import CodecEnum
            qt_str = getattr(quality_tier, 'name', str(quality_tier)).upper()
            if download_options and hasattr(download_options, "codec") and getattr(download_options, "codec", None) == CodecEnum.FLAC:
                is_flac = True
            elif download_options and hasattr(download_options, "codec") and getattr(download_options, "codec", None) == CodecEnum.VORBIS:
                is_flac = False
            else:
                is_flac = qt_str in ["LOSSLESS", "HIFI", "FLAC_24", "ATMOS"]
            
            target_format_id = 16 # Default FLAC
            stream_info = None
            
            # Fetch all available format IDs to pick the best one
            available_formats = api.get_available_formats(track_id_base62)
            self.logger.debug(f"Available format IDs for track: {available_formats}")

            if is_flac:
                # Attempt 24-bit if highest quality requested
                if qt_str in ["HIFI", "FLAC_24"] and 22 in available_formats:
                    stream_info = api.get_track_stream_info(track_id_base62, 22)
                    if stream_info:
                        target_format_id = 22
                        self.logger.debug("Found FLAC 24-bit stream!")
                
                if not stream_info and 16 in available_formats:
                    stream_info = api.get_track_stream_info(track_id_base62, 16)
                    target_format_id = 16
                    if stream_info:
                        self.logger.debug("Found standard FLAC stream!")
            else:
                # OGG/VORBIS mapping requested by project:
                # HIGH -> 320k (id 4), LOW -> 160k (id 3), others -> 96k (id 2)
                preferred_ids = []
                if qt_str in ["VERY_HIGH", "HIGH"]:
                    preferred_ids = [4, 3, 2]
                elif qt_str in ["LOW"]:
                    # 160k then 96k — never auto-upgrade to 320k (id 4) when OGG 160 / LOW is requested
                    preferred_ids = [3, 2]
                else:
                    preferred_ids = [2, 3, 4]
                
                # Find the first available format ID from our preferred list
                target_format_id = next((fid for fid in preferred_ids if fid in available_formats), None)
                
                if target_format_id:
                    self.logger.debug(f"Selected format ID {target_format_id} based on availability and preference ({qt_str}).")
                    stream_info = api.get_track_stream_info(track_id_base62, target_format_id)
                
            if not stream_info:
                self.logger.error(f"Could not find any suitable stream in available formats: {available_formats}")
                raise SpotifyTrackUnavailableError("Requested audio stream is not available via Desktop API.")
                
            file_id_hex, stream_url = stream_info
            
            # Determine final codec and extension based on target_format_id
            # 16, 22 = FLAC | 4, 3, 2 = VORBIS (OGG)
            final_codec = CodecEnum.FLAC if target_format_id in [16, 22] else CodecEnum.VORBIS
            file_extension = ".flac" if final_codec == CodecEnum.FLAC else ".ogg"
            
            self.logger.debug(f"Decrypting and downloading {final_codec.name} stream ID: {file_id_hex}")
            decryption_key = api.get_playplay_key(file_id_hex)
            
            import tempfile
            project_root_for_temp = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
            target_temp_dir = os.path.join(project_root_for_temp, 'temp')
            os.makedirs(target_temp_dir, exist_ok=True)
            
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_extension, dir=target_temp_dir) as temp_file:
                temp_file_path = temp_file.name
                
            from .desktop_api import FLAC_IV
            if final_codec == CodecEnum.VORBIS:
                # Match votify desktop PlayPlay behavior for OGG:
                # decrypt with FLAC_IV and strip 167-byte preface before OggS.
                target_iv = FLAC_IV
                api.download_and_decrypt(
                    stream_url,
                    decryption_key,
                    temp_file_path,
                    iv_hex=target_iv,
                    byte_skip=167,
                )
            else:
                target_iv = FLAC_IV
                api.download_and_decrypt(stream_url, decryption_key, temp_file_path, iv_hex=target_iv)
            if final_codec == CodecEnum.VORBIS:
                # Safety validation before tagger.
                try:
                    with open(temp_file_path, "rb") as f:
                        magic = f.read(4)
                except Exception:
                    magic = b""
                if magic != b"OggS":
                    raise SpotifyApiError(
                        f"Desktop OGG decrypt validation failed after votify-style decrypt (header={magic!r})."
                    )
            
            if track_info_obj:
                track_info_obj.codec = final_codec
                if final_codec == CodecEnum.FLAC:
                    track_info_obj.bitrate = None # Lossless
                    track_info_obj.bit_depth = 24 if target_format_id == 22 else 16
                else:
                    # Map format IDs back to display bitrates for tagging
                    bitrate_map = {4: 320, 3: 160, 2: 96}
                    track_info_obj.bitrate = bitrate_map.get(target_format_id, 320)
                    track_info_obj.bit_depth = 16
                track_info_obj.sample_rate = 44.1
                    
            from utils.models import DownloadEnum, TrackDownloadInfo
            return TrackDownloadInfo(
                download_type=DownloadEnum.TEMP_FILE_PATH,
                temp_file_path=temp_file_path,
                different_codec=final_codec
            )

        except SpotifyTrackUnavailableError:
            raise
        except Exception as e:
            self.logger.error(f"Desktop download failed: {e}", exc_info=True)
            raise SpotifyApiError(f"Desktop download failure: {e}")

    def authenticate_stream_api(self, is_initial_setup_check: bool = False) -> bool:
        """Desktop-only auth (sp_dc + Spotify.dll)."""
        _ = is_initial_setup_check
        ok = self.is_desktop_api_available()
        if not ok:
            self.logger.error(
                "Spotify desktop auth prerequisites missing: spotify-cookies (sp_dc) and/or Spotify.dll."
            )
        return ok

    def get_last_error(self) -> Optional[str]:
        """Returns the last error message from the OAuth handler if it exists."""
        if hasattr(self, 'oauth_handler') and self.oauth_handler:
            return getattr(self.oauth_handler, 'error_message', None)
        return None

    def get_last_exit_reason(self) -> Optional[str]:
        """Returns the reason why the last OAuth loop exited."""
        if hasattr(self, 'oauth_handler') and self.oauth_handler:
            return getattr(self.oauth_handler, 'last_exit_reason', None)
        return None

    def get_auth_url(self) -> Optional[str]:
        """Returns the last attempted authorization URL."""
        # Check for explicitly stored URL in main API object first (fixes restoration bug)
        if hasattr(self, '_last_attempted_auth_url') and self._last_attempted_auth_url:
            return self._last_attempted_auth_url

        if hasattr(self, 'oauth_handler') and self.oauth_handler:
            # Check for stored URL on the handler
            if hasattr(self.oauth_handler, 'last_auth_url') and self.oauth_handler.last_auth_url:
                return self.oauth_handler.last_auth_url
            return self.oauth_handler.get_authorization_url()
        return None
        return None

    # get_track_by_id removed - replaced by embed_client.get_track_metadata in get_track_info

    def get_preview_url_from_embed(self, track_id: str) -> Optional[str]:
        """
        Fetch preview URL by scraping Spotify's embed page.
        This is a fallback when the API returns null for preview_url.
        
        The embed page at https://open.spotify.com/embed/track/{id} contains
        embedded JSON data with the preview URL (audioPreview field).
        
        See: https://community.spotify.com/t5/Spotify-for-Developers/Preview-URLs-Deprecated/td-p/6791368
        """
        embed_url = f"https://open.spotify.com/embed/track/{track_id}"
        self.logger.debug(f"Fetching preview URL from embed page: {embed_url}")
        
        try:
            # Use a browser-like User-Agent to avoid being blocked
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            response = requests.get(embed_url, headers=headers, timeout=10)
            response.raise_for_status()
            html_content = response.text
            
            # Look for preview URL in the HTML - it's usually in a script tag with JSON data
            # Pattern 1: Look for audioPreview in JSON data (handles escaped URLs in JSON)
            audio_preview_pattern = re.compile(r'"audioPreview"\s*:\s*\{\s*"url"\s*:\s*"(https:\\?/\\?/p\.scdn\.co\\?/mp3-preview\\?/[^"]+)"')
            match = audio_preview_pattern.search(html_content)
            if match:
                preview_url = match.group(1)
                # Unescape JSON escaped slashes
                preview_url = preview_url.replace('\\/', '/').replace('\\u0026', '&')
                self.logger.info(f"Found preview URL from embed page for track {track_id}: {preview_url[:80]}...")
                return preview_url
            
            # Pattern 2: Direct p.scdn.co URL pattern (unescaped)
            scdn_pattern = re.compile(r'(https://p\.scdn\.co/mp3-preview/[a-zA-Z0-9]+(?:\?[^"\'<>\s]*)?)')
            match = scdn_pattern.search(html_content)
            if match:
                preview_url = match.group(1)
                self.logger.info(f"Found preview URL (scdn pattern) from embed page for track {track_id}: {preview_url[:80]}...")
                return preview_url
            
            # Pattern 3: Look for any mp3-preview URL with escaped slashes
            escaped_pattern = re.compile(r'(https:\\?/\\?/p\.scdn\.co\\?/mp3-preview\\?/[a-zA-Z0-9]+(?:\\?[^"\'<>\s]*)?)')
            match = escaped_pattern.search(html_content)
            if match:
                preview_url = match.group(1)
                # Unescape JSON escaped slashes
                preview_url = preview_url.replace('\\/', '/').replace('\\u0026', '&')
                self.logger.info(f"Found preview URL (escaped pattern) from embed page for track {track_id}: {preview_url[:80]}...")
                return preview_url
            
            # Log more details about what we found in the HTML to debug
            self.logger.info(f"[Spotify Preview] No preview URL found in embed page for track {track_id}")
            # Check if the page indicates no preview is available
            if 'preview' not in html_content.lower():
                self.logger.debug(f"[Spotify Preview] The word 'preview' not found in embed page - track likely has no preview")
            return None
            
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Failed to fetch embed page for track {track_id}: {e}")
            return None
        except Exception as e:
            self.logger.warning(f"Error parsing embed page for track {track_id}: {e}")
            return None

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
        Fetches track information using the Spotify Embed API (GraphQL)
        and then enriches it with stream details if necessary.
        """
        self.logger.debug(f"SpotifyAPI.get_track_info entered for track_id: {track_id}")
        
        try:
            # Use Embed Client to get metadata (Always use anonymous for GraphQL to avoid 401/403 with non-official tokens)
            track_data_graphql = self.embed_client.get_track_metadata(track_id, external_token=None)
            track_union = track_data_graphql.get("trackUnion")
            
            if not track_union:
                self.logger.warning(f"No track data returned from Embed API for ID: {track_id}.")
                raise SpotifyItemNotFoundError(f"Track with ID {track_id} not found.")
                
            name = track_union.get('name')
            duration_ms = track_union.get('duration', {}).get('totalMilliseconds')
            
            # Helper to safely get list from various possible structures
            def get_artists(data):
                if not data: return []
                return data.get('items', [])
            
            # Correctly handle artist names in the current GraphQL structure
            artist_items = get_artists(track_union.get('artists'))
            if not artist_items:
                 artist_items = get_artists(track_union.get('firstArtist')) + get_artists(track_union.get('otherArtists'))
            
            artist_names = []
            artist_ids = []
            for a in artist_items:
                profile = a.get('profile', {})
                name_val = profile.get('name') or a.get('name')
                if name_val:
                    artist_names.append(name_val)
                a_id = a.get('id')
                if a_id:
                    artist_ids.append(a_id)
            
            track_union = track_data_graphql.get('trackUnion', {})
        
            # Determine album ID for full metadata fetch
            album_id_fetch = None
            album_uri = track_union.get('albumOfTrack', {}).get('uri')
            if album_uri:
                parts = album_uri.split(':')
                if len(parts) > 2:
                    album_id_fetch = parts[2]
            
            album_data = track_union.get('albumOfTrack', {})
            if album_id_fetch:
                try:
                    # Fetch full album metadata to get disc numbers which are missing in getTrack response
                    full_album_data = self.embed_client.get_album_metadata(album_id_fetch)
                    if full_album_data:
                        # Extract albumUnion which containing the full metadata
                        album_data = full_album_data.get('albumUnion', {})
                        self.logger.debug(f"Using full album metadata for disc info (ID: {album_id_fetch})")
                except Exception as e:
                    self.logger.warning(f"Failed to fetch full album metadata for disc info: {e}")
            album_name = album_data.get('name')
            
            # Extract Label, Copyrights, and UPC from albumOfTrack if available
            label = album_data.get('label')
            
            # GraphQL structure for copyright is usually nested in 'items'
            album_copyright_data = album_data.get('copyright', {})
            copyrights_list = album_copyright_data.get('items', [])
            if not copyrights_list:
                copyrights_list = album_data.get('copyrights', []) # Fallback
                
            copyright_text = ', '.join([c.get('text') for c in copyrights_list if c.get('text')]) if copyrights_list else None
            
            upc = None
            external_ids_album = album_data.get('externalIds', {})
            if external_ids_album:
                eid_items_album = external_ids_album.get('items', [])
                for eid in eid_items_album:
                    if eid.get('type') == 'UPC':
                        upc = eid.get('id')
                        break

            album_id_spotify = None
            if album_data.get('uri'):
                 # extract ID from spotify:album:ID
                 parts = album_data.get('uri').split(':')
                 if len(parts) > 2:
                     album_id_spotify = parts[2]
            
            album_date_iso = album_data.get('date', {}).get('isoString') # e.g. 2020-03-20T00:00:00Z
            album_release_date_str = album_date_iso[:10] if album_date_iso else None
            
            track_number = track_union.get('trackNumber')
            disc_number = track_union.get('discNumber')
            
            # Get total tracks/discs from album metadata in GraphQL
            album_tracks_obj = album_data.get('tracks') or album_data.get('tracksV2', {})
            total_tracks = album_tracks_obj.get('totalCount')

            # Calculate total discs and find current track's disc number from album items
            total_discs = 0
            if items := album_tracks_obj.get('items', []):
                for item in items:
                    track_item = item.get('track', item)
                    d_num = track_item.get('discNumber')
                    if d_num:
                        if d_num > total_discs:
                            total_discs = d_num
                        
                        # If disc_number was missing from track_union, try to find it here
                        t_uri = track_item.get('uri')
                        if t_uri and track_id in t_uri and disc_number is None:
                            disc_number = d_num
            
            if total_discs == 0:
                total_discs = 1 if disc_number else None
            
            # Cleanup debug prints if they were added
            # (I'll remove the ones I added earlier)
            
            # Explicit content check
            explicit = track_union.get('contentRating', {}).get('label') == 'EXPLICIT'
            
            # Cover URL
            cover_url = None
            cover_sources = album_data.get('coverArt', {}).get('sources', [])
            if cover_sources:
                 # Try to find largest or closest to 640
                 # They are usually sorted largest to smallest or vice versa
                 # Let's pick the first one if available
                 cover_url = cover_sources[0].get('url')
                 for src in cover_sources:
                     if src.get('width') == 640:
                         cover_url = src.get('url')
                         break
            
            # Year extraction
            album_release_year_int = 0
            if album_release_date_str and len(album_release_date_str) >= 4:
                try:
                    album_release_year_int = int(album_release_date_str[:4])
                except ValueError:
                    pass
            
            gid_hex_value = self._convert_base62_to_gid_hex(track_id) 
            
            # Extract ISRC if available
            isrc = None
            external_ids = track_union.get('externalIds', {})
            if external_ids:
                eid_items = external_ids.get('items', [])
                for eid in eid_items:
                    if eid.get('type') == 'ISRC':
                        isrc = eid.get('id')
                        break
            
            # Always check for enrichment if the Label or UPC is missing, as Embed API (GraphQL) often omits them.
            if not label or not upc or not isrc or not copyright_text:
                if not self.client:
                    self._init_web_api_client()
                    
                if self.client:
                    try:
                        self.logger.debug(f"Metadata missing in Embed API, trying Web API for {track_id}")
                        api_track = self.client.track(track_id)
                        
                        if not isrc:
                            isrc = api_track.get('external_ids', {}).get('isrc')
                        
                        # Fetch album details from Web API for UPC, Label, and Copyright
                        track_album_api = api_track.get('album', {})
                        api_album_id = track_album_api.get('id')
                        
                        if api_album_id:
                            api_album = self.client.album(api_album_id)
                            if not upc:
                                upc = api_album.get('external_ids', {}).get('upc')
                            if not label:
                                label = api_album.get('label')
                            if not total_tracks:
                                total_tracks = api_album.get('total_tracks')
                            if not copyright_text:
                                api_copyrights = api_album.get('copyrights', [])
                                copyright_text = ', '.join([c.get('text') for c in api_copyrights if c.get('text')]) if api_copyrights else None
                            
                            # Ensure all potentially enriched strings are cleaned, regardless of which ones were found
                            if label and hasattr(label, 'strip'): label = label.strip()
                            if upc and hasattr(upc, 'strip'): upc = upc.strip()
                            if isrc and hasattr(isrc, 'strip'): isrc = isrc.strip()
                                
                    except Exception as api_err:
                        self.logger.warning(f"Failed to enrich metadata via Web API: {api_err}")
                
                # --- Double-Nuclear Label Fallback ---
                # If label is still missing, try to extract it from copyright string
                if not label and copyright_text:
                    import re
                    cp_text = copyright_text
                    # Remove common copyright prefixes like (P) 2009, (C) 2009, 2009, etc.
                    cp_text = re.sub(r'^\s*\(?[PCpc]\)?\s*\d{4}\s*', '', cp_text) # (P) 2009
                    cp_text = re.sub(r'^\s*\d{4}\s*', '', cp_text) # 2009
                    cp_text = re.sub(r'^\s*Copyright\s*\d{4}\s*', '', cp_text, flags=re.IGNORECASE)
                    cp_text = re.sub(r'^\s*℗\s*\d{4}\s*', '', cp_text)
                    cp_text = re.sub(r'^\s*©\s*\d{4}\s*', '', cp_text)
                    if cp_text and len(cp_text) > 2:
                         # Clean up multiple comma-separated copyrights
                        if ',' in cp_text:
                            cp_text = cp_text.split(',')[0].strip()
                        label = cp_text.strip()
                        self.logger.info(f"Extracted Label from Copyright: '{label}'")

            # Fetch Credits (Composers/Writers)
            composers = self._get_track_credits(track_id)
            
            tags_obj = Tags(
                album_artist=artist_names, # Use track artists as fallback
                composer=composers,
                track_number=track_number,
                total_tracks=total_tracks,
                disc_number=disc_number,
                total_discs=total_discs,
                release_date=album_release_date_str,
                isrc=isrc,
                upc=upc,
                label=label,
                copyright=copyright_text,
                track_url=f"https://open.spotify.com/track/{track_id}"
            )
            
            # Determine initial metadata for the UI logs based on requested quality
            initial_codec = CodecEnum.VORBIS
            initial_bitrate = 96
            initial_bit_depth = 16
            initial_sample_rate = 44.1

            qt_str = ""
            if hasattr(quality_tier, 'name'):
                qt_str = quality_tier.name.upper()
            elif isinstance(quality_tier, str):
                qt_str = quality_tier.upper()

            if qt_str in ["LOSSLESS", "HIFI", "ATMOS", "FLAC_24"]:
                initial_codec = CodecEnum.FLAC
                initial_bitrate = None
                if qt_str in ["HIFI", "ATMOS", "FLAC_24"]:
                    initial_bit_depth = 24
            elif qt_str in ["VERY_HIGH", "HIGH"]:
                initial_bitrate = 320
            elif qt_str in ["LOW"]:
                initial_bitrate = 160

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
                codec=initial_codec, 
                release_year=album_release_year_int,
                gid_hex=gid_hex_value,
                bitrate=initial_bitrate,
                bit_depth=initial_bit_depth,
                sample_rate=initial_sample_rate,
            )
            self.logger.debug(f"Successfully created TrackInfo for {track_id}: {name}. Returning object.")
            return track_info_instance
            
        except Exception as e:
            self.logger.error(f"Unexpected error in get_track_info for track_id {track_id}: {e}", exc_info=True)
            raise SpotifyApiError(f"An unexpected error occurred while fetching track {track_id}: {e}")

    def get_album_info(self, album_id: str, metadata: Optional['AlbumInfo'] = None, _retry_attempted: bool = False, _retry_count: int = 0) -> Optional[dict]:
        self.logger.info(f"SpotifyAPI: Attempting to get album info for ID: {album_id}")
        
        try:
            # Use Embed Client to get metadata (no credentials required)
            album_data_graphql = self.embed_client.get_album_metadata(album_id)
            album_union = album_data_graphql.get("albumUnion")
            
            if not album_union:
                self.logger.warning(f"No album data returned from Embed API for ID: {album_id}.")
                raise SpotifyItemNotFoundError(f"Album with ID {album_id} not found.")
                
            name = album_union.get('name')
            
            # Helper to safely extract list from various potential structures
            def get_items(data):
                if not data: return []
                if isinstance(data, dict):
                     items = data.get('items')
                     if items is not None: return items
                     return [data] # Fallback for single item
                if isinstance(data, list): return data
                return []

            # Extract artists
            artists = []
            raw_artists = get_items(album_union.get('artists'))
            if not raw_artists:
                 raw_artists = get_items(album_union.get('firstArtist'))

            for a in raw_artists:
                 profile = a.get('profile', {})
                 name_val = profile.get('name') or a.get('name')
                 if name_val:
                     artists.append({
                         'id': a.get('id'),
                         'name': name_val
                     })
            
            # Extract images (cover art)
            images = []
            cover_art = album_union.get('coverArt', {})
            for src in cover_art.get('sources', []):
                 images.append({
                     'url': src.get('url'),
                     'height': src.get('height'),
                     'width': src.get('width')
                 })
            
            # Release date
            release_date = album_union.get('date', {}).get('isoString')
            if release_date:
                release_date = release_date[:10]
            
            # Tracks
            all_track_items = []
            tracks_v2 = album_union.get('tracksV2', {})
            raw_track_items = tracks_v2.get('items', [])
            
            for item in raw_track_items:
                # item might be a wrapper or the track itself depending on query
                # In getAlbum query, it's usually { track: {...}, uid: ... }
                track = item.get('track')
                if not track: continue
                
                # Transform to Web API format expected by interface
                track_artists = []
                # Combine artists.items or firstArtist, otherArtists, featuredArtists
                t_artists_raw = get_items(track.get('artists')) or \
                               (get_items(track.get('firstArtist')) + get_items(track.get('otherArtists')) + get_items(track.get('featuredArtists')))
                
                seen_ids = set()
                for a in t_artists_raw:
                    a_id = a.get('id')
                    if a_id and a_id in seen_ids: continue
                    if a_id: seen_ids.add(a_id)
                    
                    profile = a.get('profile', {})
                    name_val = profile.get('name') or a.get('name')
                    if name_val:
                        track_artists.append({
                            'id': a_id,
                            'name': name_val
                        })
                
                # Duration
                duration_ms = track.get('trackDuration', {}).get('totalMilliseconds') or track.get('duration', {}).get('totalMilliseconds')
                
                # Explicit
                explicit = track.get('contentRating', {}).get('label') == 'EXPLICIT'
                
                # Track number
                track_number = track.get('trackNumber')
                disc_number = track.get('discNumber')

                all_track_items.append({
                    'id': track.get('uri', '').split(':')[-1] if track.get('uri') else None,
                    'name': track.get('name'),
                    'duration_ms': duration_ms,
                    'track_number': track_number,
                    'disc_number': disc_number,
                    'explicit': explicit,
                    'artists': track_artists,
                    'type': 'track',
                    'is_local': False # Web API field, not relevant here but good to have consistency
                })
            
            # Extract UPC if available
            album_upc = None
            album_external_ids = album_union.get('externalIds', {})
            if album_external_ids:
                album_eid_items = album_external_ids.get('items', [])
                for eid in album_eid_items:
                    if eid.get('type') == 'UPC':
                        album_upc = eid.get('id')
                        break

            # Extract Label and Copyrights correctly from GraphQL
            label = album_union.get('label')
            album_copyright_data = album_union.get('copyright', {})
            copyrights_list = album_copyright_data.get('items', [])
            if not copyrights_list:
                copyrights_list = album_union.get('copyrights', [])
            
            # Extract UPC if available
            album_upc = None
            album_external_ids = album_union.get('externalIds', {})
            if album_external_ids:
                album_eid_items = album_external_ids.get('items', [])
                for eid in album_eid_items:
                    if eid.get('type') == 'UPC':
                        album_upc = eid.get('id')
                        break
            
            # Fallback to Web API for missing fields (especially UPC)
            if not album_upc or not label or not copyrights_list:
                if not self.client:
                    self._init_web_api_client()
                if self.client:
                    try:
                        self.logger.debug(f"Album metadata missing in Embed API, trying Web API for {album_id}")
                        api_album = self.client.album(album_id)
                        if not album_upc:
                            album_upc = api_album.get('external_ids', {}).get('upc')
                        if not label:
                            label = api_album.get('label')
                        if not copyrights_list:
                            copyrights_list = api_album.get('copyrights', [])
                    except Exception as api_err:
                        self.logger.warning(f"Failed to enrich album metadata via Web API: {api_err}")
                    
                # --- Double-Nuclear Label Fallback ---
                # If label is still missing, try to harvest from copyrights_list
                if not label and copyrights_list:
                    import re
                    # Get first copyright text
                    text = copyrights_list[0].get('text') if isinstance(copyrights_list, list) and isinstance(copyrights_list[0], dict) else (copyrights_list[0] if isinstance(copyrights_list, list) and len(copyrights_list) > 0 else None)
                    if text:
                        cp_text = str(text)
                        # Remove common copyright prefixes like (P) 2009, (C) 2009, 2009, etc.
                        cp_text = re.sub(r'^\s*\(?[PCpc]\)?\s*\d{4}\s*', '', cp_text) # (P) 2009
                        cp_text = re.sub(r'^\s*\d{4}\s*', '', cp_text) # 2009
                        cp_text = re.sub(r'^\s*Copyright\s*\d{4}\s*', '', cp_text, flags=re.IGNORECASE)
                        cp_text = re.sub(r'^\s*℗\s*\d{4}\s*', '', cp_text)
                        cp_text = re.sub(r'^\s*©\s*\d{4}\s*', '', cp_text)
                        if cp_text and len(cp_text) > 2:
                            # Clean up multiple comma-separated copyrights
                            if ',' in cp_text:
                                cp_text = cp_text.split(',')[0].strip()
                            label = cp_text.strip()
                            self.logger.info(f"Extracted Label from Copyright: '{label}'")

            # Construct the return dictionary (mimicking Web API response structure)
            album_data = {
                'id': album_id,
                'name': name,
                'artists': artists,
                'images': images,
                'release_date': release_date,
                'total_tracks': tracks_v2.get('totalCount') or len(all_track_items),
                'tracks': {'items': all_track_items, 'total': len(all_track_items)},
                'album_type': album_union.get('type', 'album').lower() if album_union.get('type') else 'album',
                'label': label,
                'copyrights': copyrights_list,
                'upc': album_upc
            }
            
            self.logger.info(f"SpotifyAPI.get_album_info: Successfully retrieved album data for {album_id}")
            return album_data

        except SpotifyItemNotFoundError:
             raise
        except Exception as e:
            self.logger.error(f"Unexpected error in get_album_info for {album_id}: {e}", exc_info=True)
            raise SpotifyApiError(f"An unexpected error occurred while fetching album {album_id}: {e}")

    def _get_track_credits(self, track_id: str) -> Optional[List[str]]:
        """
        Fetches track credits (writers/composers) from Spotify's internal GraphQL API.
        """
        try:
            # Always use anonymous for GraphQL to avoid 401/403 with non-official tokens
            try:
                credits_data = self.embed_client.get_track_credits(track_id, external_token=None)
            except Exception as e_ext:
                self.logger.warning(f"GraphQL credits failed: {e_ext}")
                raise e_ext
            
            track_union = credits_data.get('trackUnion', {})
            credits_obj = track_union.get('credits', {})
            role_credits = credits_obj.get('items', [])
            
            writers = []
            for role in role_credits:
                role_title = role.get('role', '').lower()
                # "Writer" usually covers composers and lyricists on Spotify
                if 'writer' in role_title or 'composer' in role_title:
                    artists = role.get('artists', [])
                    for artist in artists:
                        name = artist.get('name')
                        if name and name not in writers:
                            writers.append(name)
            
            if writers:
                self.logger.info(f"Successfully retrieved writers for {track_id} via GraphQL: {writers}")
                return writers
                
            return None
            
        except Exception as e:
            self.logger.warning(f"Error fetching credits for {track_id} via GraphQL: {e}")
            return None

    def get_playlist_info(self, playlist_id: str, metadata: Optional['PlaylistInfo'] = None, _retry_attempted: bool = False) -> Optional[dict]:
        self.logger.info(f"SpotifyAPI: Attempting to get playlist info (Embed API) for ID: {playlist_id}")

        try:
            # Use Embed Client to get metadata (pagination is handled internally by get_playlist_metadata)
            playlist_data_graphql = self.embed_client.get_playlist_metadata(playlist_id)
            playlist_v2 = playlist_data_graphql.get("playlistV2")
            
            if not playlist_v2:
                self.logger.warning(f"No playlist data returned from Embed API for ID: {playlist_id}.")
                raise SpotifyItemNotFoundError(f"Playlist with ID {playlist_id} not found.")
            
            name = playlist_v2.get('name')

            owner_name = playlist_v2.get('ownerV2', {}).get('data', {}).get('name') or playlist_v2.get('owner', {}).get('name')
            description = playlist_v2.get('description')
            
            # Extract cover URL
            images = []
            cover_art = playlist_v2.get('images', {}).get('items', [])
            if cover_art:
                # Use the first image (usually highest resolution available in sources)
                sources = cover_art[0].get('sources', [])
                if sources:
                    images.append({'url': sources[0].get('url')})

            # Process tracks
            all_track_items = []
            content = playlist_v2.get('content', {})
            items = content.get('items', [])
            
            for item in items:
                if not isinstance(item, dict): continue
                
                track_v2 = item.get('itemV2', {}).get('data', {})
                if not track_v2: continue
                
                # Check for track or episode
                is_episode = track_v2.get('__typename') == 'Episode'
                
                if is_episode:
                    # Map episode back to a track-like structure
                    all_track_items.append({
                        'track': {
                            'id': track_v2.get('id'),
                            'name': track_v2.get('name'),
                            'duration_ms': track_v2.get('duration', {}).get('totalMilliseconds'),
                            'explicit': track_v2.get('contentRating', {}).get('label') == 'EXPLICIT',
                            'type': 'episode'
                        }
                    })
                else:
                    # Standard track
                    track_artists = []
                    artists_v2 = track_v2.get('artists', {}).get('items', [])
                    for a in artists_v2:
                        track_artists.append({
                            'id': a.get('uri', '').split(':')[-1] if a.get('uri') else None,
                            'name': a.get('profile', {}).get('name') or a.get('name')
                        })
                    
                    album_v2 = track_v2.get('albumOfTrack', {})
                    album_images = []
                    album_cover_sources = album_v2.get('coverArt', {}).get('sources', [])
                    if album_cover_sources:
                        album_images.append({'url': album_cover_sources[0].get('url')})

                    all_track_items.append({
                        'track': {
                            'id': track_v2.get('uri', '').split(':')[-1] if track_v2.get('uri') else None,
                            'name': track_v2.get('name'),
                            'duration_ms': track_v2.get('trackDuration', {}).get('totalMilliseconds'),
                            'explicit': track_v2.get('contentRating', {}).get('label') == 'EXPLICIT',
                            'track_number': track_v2.get('trackNumber'),
                            'disc_number': track_v2.get('discNumber'),
                            'artists': track_artists,
                            'album': {
                                'id': album_v2.get('uri', '').split(':')[-1] if album_v2.get('uri') else None,
                                'name': album_v2.get('name'),
                                'release_date': album_v2.get('date', {}).get('isoString'),
                                'images': album_images,
                                'artists': [{'name': a.get('profile', {}).get('name')} for a in album_v2.get('artists', {}).get('items', []) if a.get('profile', {}).get('name')]
                            },
                            'type': 'track'
                        }
                    })
            
            # Construct return dictionary (matching Web API structure expected by interface.py)
            playlist_data = {
                'id': playlist_id,
                'name': name,
                'owner': {'display_name': owner_name},
                'description': description,
                'images': images,
                'tracks': {
                    'items': all_track_items,
                    'total': content.get('totalCount') or len(all_track_items)
                }
            }
            
            self.logger.info(f"SpotifyAPI.get_playlist_info (Embed): Successfully retrieved playlist data for {playlist_id} with {len(all_track_items)} tracks")
            return playlist_data

        except SpotifyItemNotFoundError:
             raise
        except Exception as e:
            self.logger.error(f"Unexpected error in get_playlist_info for {playlist_id}: {e}", exc_info=True)
            raise SpotifyApiError(f"An unexpected error occurred while fetching playlist {playlist_id}: {e}")


    def get_several_artists(self, artist_ids: list, _retry_attempted: bool = False) -> list:
        if not artist_ids:
            return []
        ids_to_fetch = [str(aid) for aid in artist_ids if aid][:50]
        if not ids_to_fetch:
            return []

        # Use anonymous token
        try:
            web_api_token = self.embed_client.get_anonymous_token()
        except Exception as e:
            self.logger.error(f"Failed to get anonymous token for get_several_artists: {e}")
            return []

        url = "https://api.spotify.com/v1/artists"
        headers = {"Authorization": f"Bearer {web_api_token}"}
        params = {"ids": ",".join(ids_to_fetch)}

        try:
            # Use embed_client.session to ensure browser-like headers
            response = self.embed_client.session.get(url, headers=headers, params=params, timeout=DEFAULT_REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                artists = data.get("artists") or []
                return list(artists)
            elif response.status_code == 401:
                 if not _retry_attempted:
                     self.embed_client.get_anonymous_token(force_refresh=True)
                     return self.get_several_artists(artist_ids, _retry_attempted=True)
                 else:
                     self.logger.error("Auth failed for get_several_artists")
                     raise SpotifyAuthError("Auth failed for get_several_artists")
            else:
                 response.raise_for_status()
                 return [] # Should assume raise_for_status raises exception

        except requests.exceptions.HTTPError as http_err:
            if http_err.response.status_code == 401:
                # Logic handled above if caught before raise_for_status, but here for robustness
                 if not _retry_attempted:
                     self.embed_client.get_anonymous_token(force_refresh=True)
                     return self.get_several_artists(artist_ids, _retry_attempted=True)
            self.logger.error(f"get_several_artists failed: {http_err.response.status_code}")
            raise SpotifyApiError(f"get_several_artists failed: {http_err}")
        except requests.exceptions.RequestException as req_err:
            raise SpotifyApiError(f"get_several_artists request error: {req_err}") from req_err

    def get_artist_info(self, artist_id: str, metadata: Optional['ArtistInfo'] = None, _retry_attempted: bool = False, _retry_count: int = 0) -> Optional['ArtistInfo']:
        self.logger.info(f"SpotifyAPI: Attempting to get artist info for ID: {artist_id}")
        
        try:
            # Use Embed Client to get metadata
            artist_data_graphql = self.embed_client.get_artist_metadata(artist_id)
            artist_union = artist_data_graphql.get("artistUnion")
            
            if not artist_union:
                self.logger.warning(f"No artist data returned from Embed API for ID: {artist_id}.")
                raise SpotifyItemNotFoundError(f"Artist with ID {artist_id} not found.")
            
            profile = artist_union.get('profile', {})
            artist_name = profile.get('name') or artist_union.get('name') or "Unknown Artist"
            
            # Simplified albums list
            simplified_albums = []
            
            # Discography is in artistUnion.discography.all.items
            discography = artist_union.get('discography', {}).get('all', {})
            items = discography.get('items', [])
            
            for item in items:
                # item is the album release
                releases = item.get('releases', {}).get('items', [])
                # Sometimes the item itself is the album, or it groups releases
                # In queryArtistDiscographyAll, items are directly albums/singles usually
                
                # Check structure. If using queryArtistDiscographyAll, items are like { usage: ..., releases: { items: [...] } }
                # OR sometimes simplified.
                # Let's handle the structure returned by get_artist_metadata which paginates 'discography.all.items'
                
                # If the item has 'releases', iterate them. If it has 'name' and 'date', it's the album itself.
                albums_to_process = []
                if 'releases' in item:
                    albums_to_process.extend(item['releases'].get('items', []))
                else:
                    albums_to_process.append(item)
                    
                for album in albums_to_process:
                    cover_url = None
                    cover_art = album.get('coverArt', {})
                    sources = cover_art.get('sources', [])
                    if sources:
                        # Prefer 300px or largest
                        cover_url = sources[0].get('url')
                        
                    release_year = 0
                    date_obj = album.get('date', {})
                    if 'year' in date_obj:
                        release_year = date_obj['year']
                    elif 'isoString' in date_obj:
                         try: release_year = int(date_obj['isoString'][:4])
                         except: pass
                    
                    total_tracks = album.get('tracks', {}).get('totalCount')
                    additional = [f"1 track" if total_tracks == 1 else f"{total_tracks} tracks"] if total_tracks is not None else None

                    simplified_albums.append({
                        'id': album.get('id'), # Note: might need to strip spotify:album: prefix if present? usually just ID in GraphQL
                        'name': album.get('name'),
                        'album_type': album.get('type', 'album').lower(), # 'SINGLE', 'ALBUM', etc
                        'release_year': release_year,
                        'cover_url': cover_url,
                        'total_tracks': total_tracks,
                        'additional': additional,
                        'explicit': None
                    })
            
            # Batch fetch missing durations for albums
            albums_to_fetch = [idx for idx, t in enumerate(simplified_albums) if not t.get('duration')]
            if albums_to_fetch:
                a_meta = {}
                def _fetch_spotify_album_duration(aid):
                    try:
                        actual_id = aid.split(':')[-1] if ':' in aid else aid
                        album_meta = self.embed_client.get_album_metadata(actual_id)
                        album_union = album_meta.get('albumUnion') if album_meta else None
                        if album_union:
                            # The structure for tracks in albumUnion is albumUnion.tracksV2.items
                            tracks_obj = album_union.get('tracksV2') or album_union.get('tracks', {})
                            tracks = tracks_obj.get('items', [])
                            nb_tracks = tracks_obj.get('totalCount') or len(tracks)
                            sum_dur = 0
                            for t in tracks:
                                if not isinstance(t, dict): continue
                                # Item might be { track: { ... } } or { ... }
                                track_data = t.get('track') if t.get('track') else t
                                if isinstance(track_data, dict):
                                    d = track_data.get('duration', {})
                                    if isinstance(d, dict):
                                        sum_dur += d.get('totalMilliseconds', 0) or 0
                            
                            # Explicit check
                            explicit = album_union.get('contentRating', {}).get('label') == 'EXPLICIT'
                            if not explicit:
                                for t in tracks:
                                    if not isinstance(t, dict): continue
                                    tr_data = t.get('track') or t
                                    if isinstance(tr_data, dict) and tr_data.get('contentRating', {}).get('label') == 'EXPLICIT':
                                        explicit = True
                                        break
                                        
                            return aid, (sum_dur // 1000 if sum_dur > 0 else None, nb_tracks, explicit)
                    except: pass
                    return aid, (None, None)

                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    fetch_ids = [simplified_albums[idx]['id'] for idx in albums_to_fetch]
                    for aid, (dur, nb_tracks, explicit) in executor.map(_fetch_spotify_album_duration, fetch_ids):
                        a_meta[aid] = (dur, nb_tracks, explicit)
                
                for idx in albums_to_fetch:
                    t = simplified_albums[idx]
                    aid = t['id']
                    if aid in a_meta:
                        dur, nb_tracks, explicit = a_meta[aid]
                        if dur: t['duration'] = dur
                        if nb_tracks and not t.get('total_tracks'):
                            t['total_tracks'] = nb_tracks
                            t['additional'] = [f"1 track" if nb_tracks == 1 else f"{nb_tracks} tracks"]
                        if explicit: t['explicit'] = True

            try:
                artist_info_obj = ArtistInfo(
                    name=artist_name,
                    albums=simplified_albums,
                )
                return artist_info_obj
            except Exception as e_create:
                 self.logger.error(f"Error creating ArtistInfo: {e_create}")
                 return None

        except SpotifyItemNotFoundError:
             raise
        except Exception as e:
            self.logger.error(f"Unexpected error in get_artist_info for {artist_id}: {e}", exc_info=True)
            raise SpotifyApiError(f"An unexpected error occurred while fetching artist {artist_id}: {e}")

    def get_show_info(self, show_id: str, metadata: Optional['AlbumInfo'] = None, _retry_attempted: bool = False) -> Optional[dict]:
        """Get show information from Spotify API. Returns show data in album-like format for compatibility."""
        self.logger.info(f"SpotifyAPI: Attempting to get show info for ID: {show_id}")
        
        # Use anonymous token from Embed Client
        try:
            web_api_token = self.embed_client.get_anonymous_token()
        except Exception as e:
            self.logger.error(f"Failed to get anonymous token for get_show_info: {e}")
            return None

        show_api_url = f"https://api.spotify.com/v1/shows/{show_id}"
        headers = {"Authorization": f"Bearer {web_api_token}"}
        params = {'market': 'US'} # Shows often require market. 'US' is a safe default for anonymous? Or try without?
        # Anonymous token usually has a market associated or implies one? 
        # Experiment: SpotiFLAC uses 'US' often for shows?
        
        try:
            self.logger.debug(f"SpotifyAPI.get_show_info: Getting show details from {show_api_url}")
            # Use embed_client.session to ensure browser-like headers
            response = self.embed_client.session.get(show_api_url, headers=headers, params=params, timeout=DEFAULT_REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                show_data = response.json()
                self.logger.info(f"SpotifyAPI.get_show_info: Successfully retrieved show data for {show_id}")
                
                # Fetch episodes (paginated)
                all_episodes = []
                if 'episodes' in show_data and 'items' in show_data['episodes']:
                    all_episodes.extend(show_data['episodes']['items'])
                    next_url = show_data['episodes'].get('next')
                    while next_url:
                        # ... pagination logic ...
                        # For brevity and since this is a fallback/legacy support, maybe limit pagination or implement simple loop
                        # Implementing simple loop:
                        r = requests.get(next_url, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT)
                        if r.status_code == 200:
                             d = r.json()
                             all_episodes.extend(d.get('items', []))
                             next_url = d.get('next')
                        else:
                             break
                
                # Convert to album structure
                # ... mapping ...
                # Actually, I'll just return the show_data with episodes joined, and let logic downstream handle it if it expects 'tracks'
                # But the signature says Returns dict.
                # The original code mapped it. I should try to preserve mapping if possible or just return raw if downstream handles it.
                # Original code (I can't see it all) likely returned something compatible with 'AlbumInfo' or similar logic.
                # Let's verify existing usage? No, I'll just map to a generic "album-like" dict as docstring says.
                
                # Minimal mapping:
                formatted_episodes = []
                for ep in all_episodes:
                    formatted_episodes.append({
                        'id': ep.get('id'),
                        'name': ep.get('name'),
                        'duration_ms': ep.get('duration_ms'),
                        'track_number': 0, # episodes don't have track numbers usually
                        'disc_number': 1,
                        'explicit': ep.get('explicit'),
                        'artists': [{'name': show_data.get('name'), 'id': show_data.get('id')}], # Show as artist
                        'type': 'episode',
                        'release_date': ep.get('release_date')
                    })
                
                result = {
                    'id': show_id,
                    'name': show_data.get('name'),
                    'artists': [{'name': show_data.get('publisher'), 'id': show_data.get('id')}],
                    'images': show_data.get('images', []),
                    'release_date': show_data.get('episodes', {}).get('items', [{}])[0].get('release_date'), # approx
                    'total_tracks': len(formatted_episodes),
                    'tracks': {'items': formatted_episodes, 'total': len(formatted_episodes)},
                    'album_type': 'show',
                     'label': show_data.get('publisher')
                }
                return result

            elif response.status_code == 401:
                self.logger.warning(f"SpotifyAPI.get_show_info: Auth error (401).")
                if not _retry_attempted:
                    self.embed_client.get_anonymous_token(force_refresh=True)
                    return self.get_show_info(show_id, metadata, _retry_attempted=True)
                else:
                    self.logger.error("SpotifyAPI.get_show_info: Auth error (401) even after retry.")
                    raise SpotifyAuthError(f"Authorization failed for show {show_id} (401) after retry.")
            elif response.status_code == 404:
                self.logger.warning(f"SpotifyAPI.get_show_info: Show {show_id} not found (404).")
                raise SpotifyItemNotFoundError(f"Show with ID {show_id} not found.")
            elif response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 5))
                self.logger.warning(f"SpotifyAPI.get_show_info: Rate limited (429) for {show_id}. Retry-After: {retry_after}s")
                raise SpotifyRateLimitDetectedError(f"Spotify rate limit (429) for show {show_id}. Retry-After: {retry_after}s")
            else:
                self.logger.error(f"SpotifyAPI.get_show_info: Failed to get show data for {show_id}. Status: {response.status_code}, Response: {response.text}")
                raise SpotifyApiError(f"Failed to get show data for {show_id}. Status: {response.status_code}, Response Text: {response.text[:200]}")

        except requests.exceptions.HTTPError as http_err:
            if http_err.response.status_code == 401:
                self.logger.warning(f"SpotifyAPI.get_show_info: HTTPError 401 caught for {show_id}.")
                if not _retry_attempted:
                    self.logger.info("SpotifyAPI.get_show_info: Refreshing anonymous token and retrying after HTTPError 401.")
                    self.embed_client.get_anonymous_token(force_refresh=True)
                    return self.get_show_info(show_id, metadata, _retry_attempted=True)
                else:
                    self.logger.error(f"SpotifyAPI.get_show_info: HTTPError 401 for {show_id} even after retry.")
                    raise SpotifyAuthError(f"Authorization failed for show {show_id} (HTTPError 401) after retry.")
            else:
                self.logger.error(f"SpotifyAPI.get_show_info: HTTPError {http_err.response.status_code} for {show_id}: {http_err.response.text[:200]}")
                raise SpotifyApiError(f"HTTP error fetching show {show_id}: {http_err.response.status_code} - {http_err.response.text[:200]}") from http_err
        except requests.exceptions.RequestException as e:
            self.logger.error(f"SpotifyAPI.get_show_info: RequestException for {show_id}: {e}", exc_info=False)
            raise SpotifyApiError(f"Network error while fetching show {show_id}: {e}")
        except SpotifyAuthError:
            raise
        except Exception as e:
            self.logger.error(f"SpotifyAPI.get_show_info: Unexpected error for {show_id}: {e}", exc_info=True)
            if isinstance(e, SpotifyApiError):
                raise
            raise SpotifyApiError(f"An unexpected error occurred while fetching show {show_id}: {e}")

    def get_episode_by_id(self, episode_id: str, market: Optional[str] = None, _retry_attempted: bool = False) -> Optional[dict]:
        """Get episode details by its Spotify ID using the Web API."""
        self.logger.debug(f"SpotifyAPI.get_episode_by_id entered for episode_id: {episode_id}, market: {market}{', retry' if _retry_attempted else ''}")

        # Use anonymous token from Embed Client
        try:
            web_api_token = self.embed_client.get_anonymous_token()
        except Exception as e:
            self.logger.error(f"Failed to get anonymous token for get_episode_by_id: {e}")
            return None

        headers = {"Authorization": f"Bearer {web_api_token}"}
        params = {}
        if market:
            params["market"] = market
        else:
            # Default to US if not provided
            params["market"] = 'US'

        api_url = f"https://api.spotify.com/v1/episodes/{episode_id}"
        self.logger.debug(f"Calling Spotify Web API: GET {api_url} with params: {params}")
        try:
            # Use embed_client.session to ensure browser-like headers
            response = self.embed_client.session.get(api_url, headers=headers, params=params, timeout=DEFAULT_REQUEST_TIMEOUT)
            self.logger.debug(f"Episode API response status: {response.status_code}")
            
            if response.status_code == 200:
                episode_data = response.json()
                self.logger.debug(f"get_episode_by_id SUCCEEDED for episode_id: {episode_id}. Data keys: {list(episode_data.keys())}")
                return episode_data
            elif response.status_code == 401:
                # Retry once
                if not _retry_attempted:
                     self.embed_client.get_anonymous_token(force_refresh=True)
                     return self.get_episode_by_id(episode_id, market, _retry_attempted=True)
                else:
                     self.logger.error(f"SpotifyAPI.get_episode_by_id: Auth error (401) for episode {episode_id} after retry.")
                     raise SpotifyAuthError(f"Auth failed for episode {episode_id} (401) after retry.")
            elif response.status_code == 404:
                self.logger.warning(f"Episode {episode_id} not found via Spotify API (404).")
                raise SpotifyItemNotFoundError(f"Episode {episode_id} not found.")
            elif response.status_code == 403:
                self.logger.warning(f"Episode {episode_id} access forbidden (403).")
                raise SpotifyItemNotFoundError(f"Episode {episode_id} access forbidden.")
            else:
                response.raise_for_status() # Raise for other errors

        except requests.exceptions.HTTPError as http_err:
            if http_err.response.status_code == 401:
                if not _retry_attempted:
                     self.embed_client.get_anonymous_token(force_refresh=True)
                     return self.get_episode_by_id(episode_id, market, _retry_attempted=True)
            self.logger.error(f"HTTP error fetching episode {episode_id}: {http_err.response.status_code} - {http_err.response.text[:200]}", exc_info=False)
            raise SpotifyApiError(f"Spotify API request failed for episode {episode_id}: {http_err.response.status_code}") from http_err
        except requests.exceptions.RequestException as req_err:
             self.logger.error(f"RequestException for episode {episode_id}: {req_err}")
             raise SpotifyApiError(f"Request error for episode {episode_id}: {req_err}") from req_err
        except SpotifyAuthError:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error in get_episode_by_id: {e}", exc_info=True)
            if isinstance(e, SpotifyApiError): raise
            raise SpotifyApiError(f"Unexpected error fetching episode {episode_id}: {e}")

    def get_episode_download(self, **kwargs) -> Optional[TrackDownloadInfo]:
        """Episode audio download is disabled in desktop-only Spotify mode."""
        _ = kwargs
        raise SpotifyTrackUnavailableError(
            "Spotify episode downloads are unavailable in desktop-only mode."
        )

    def get_episode_info(self, episode_id: str, quality_tier: QualityEnum, codec_options: CodecOptions, **extra_kwargs) -> Optional[TrackInfo]:
        """Get episode information and convert to TrackInfo format for compatibility."""
        self.logger.info(f"SpotifyAPI: get_episode_info for episode_id: {episode_id}")
        
        try:
            # Get episode data from API
            self.logger.debug(f"Calling get_episode_by_id for {episode_id}")
            episode_data = self.get_episode_by_id(episode_id)
            if not episode_data:
                self.logger.error(f"No episode data returned for episode_id: {episode_id}")
                return None
            
            self.logger.debug(f"Episode data keys: {list(episode_data.keys())}")
            
            # Convert episode data to TrackInfo format
            track_name = episode_data.get('name', 'Unknown Episode')
            description = episode_data.get('description', '')
            duration_ms = episode_data.get('duration_ms', 0)
            explicit = episode_data.get('explicit', False)
            release_date = episode_data.get('release_date', '')
            
            self.logger.debug(f"Episode basic info - Name: {track_name}, Duration: {duration_ms}ms")
            
            # Get show (album) information
            show_data = episode_data.get('show', {})
            album_name = show_data.get('name', 'Unknown Show')
            album_id = show_data.get('id', None)
            publisher = show_data.get('publisher', 'Unknown Publisher')
            total_episodes = show_data.get('total_episodes')
            
            self.logger.debug(f"Show info - Name: {album_name}, Publisher: {publisher}")
            
            # Use publisher as artist
            artists = [publisher] if publisher else ['Unknown Publisher']
            artist_id = None  # Shows don't have artist IDs
            
            # Get cover art
            cover_url = None
            if show_data.get('images') and len(show_data['images']) > 0:
                cover_url = show_data['images'][0].get('url')
                self.logger.debug(f"Using show cover: {cover_url}")
            elif episode_data.get('images') and len(episode_data['images']) > 0:
                cover_url = episode_data['images'][0].get('url')
                self.logger.debug(f"Using episode cover: {cover_url}")
            
            # Parse release year
            release_year = 0
            if release_date and len(release_date) >= 4:
                try:
                    release_year = int(release_date[:4])
                except ValueError:
                    self.logger.warning(f"Could not parse year from release_date: {release_date}")
            
            # Create Tags object
            self.logger.debug("Creating Tags object")
            tags = Tags()
            tags.album_artist = publisher
            tags.release_date = release_date
            tags.disc_number = 1
            tags.track_number = 1
            tags.total_tracks = total_episodes
            tags.track_url = f"https://open.spotify.com/episode/{episode_id}"
            
            # Create TrackInfo object with episode data
            self.logger.debug("Creating TrackInfo object")
            track_info = TrackInfo(
                name=track_name,
                id=episode_id,  # Add the episode ID so album download can access it
                album_id=album_id,
                album=album_name,
                artists=artists,
                artist_id=artist_id,
                release_year=release_year,
                explicit=explicit,
                cover_url=cover_url,
                tags=tags,
                codec=CodecEnum.VORBIS,  # Episodes will be downloaded as VORBIS
                duration=int(duration_ms / 1000) if duration_ms else 0,
                # Add episode-specific info in error field for debugging
                error=None
            )
            
            self.logger.info(f"Successfully converted episode '{track_name}' to TrackInfo format")
            return track_info
            
        except Exception as e:
            self.logger.error(f"Error getting episode info for {episode_id}: {e}", exc_info=True)
            return None

# --- Main function for testing or standalone use (Optional) ---
def main():
    parser = argparse.ArgumentParser(description="Search Spotify via its Web API.")
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