import base64
import json
import logging
import os
import pkce
import requests
import spotipy
import struct
import threading
import time
import uuid
import webbrowser

from http.server import HTTPServer, BaseHTTPRequestHandler
from librespot.core import Session as LibrespotSession
from librespot.mercury import MercuryClient
from librespot.proto import Authentication_pb2 as Authentication
from librespot.proto.Connect_pb2 import DeviceType
from queue import Empty
from requests.exceptions import ConnectionError as RequestsConnectionError
from spotipy.oauth2 import SpotifyOAuth
from types import SimpleNamespace
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode

# --- Custom Log Filter ---
class AudioKeyManagerFilter(logging.Filter):
    def filter(self, record):
        # Reject log records containing "AudioKeyManager:Audio key error"        
        is_audiokey_logger = 'librespot' in record.name.lower() and 'audiokeymanager' in record.name.lower()
        has_audiokey_message = 'Audio key error' in record.getMessage()
        # Reject if it seems to be the specific critical message we want to hide
        return not (is_audiokey_logger and has_audiokey_message and record.levelno == logging.CRITICAL)

# --- Duplicate Message Filter ---
class DuplicateMessageFilter(logging.Filter):
    def __init__(self, name="", target_logger_name_contains_lower="", target_level=None, target_message_prefix=""):
        super().__init__(name)
        self.target_logger_name_contains_lower = target_logger_name_contains_lower.lower()
        self.target_level = target_level
        self.target_message_prefix = target_message_prefix.strip()
        self.last_message_signature = None
        self._lock = threading.Lock()
        self.debug_filter = False

    def filter(self, record):
        is_target_logger = self.target_logger_name_contains_lower in record.name.lower()
        is_target_level = record.levelno == self.target_level
        
        current_message_stripped = record.getMessage().strip()
        is_target_message_prefix = current_message_stripped.startswith(self.target_message_prefix)

        if is_target_logger and is_target_level and is_target_message_prefix:
            current_signature = (record.name.lower(), record.levelno, current_message_stripped)
            
            if self.debug_filter:
                print(f"[FILTER_DEBUG] Target Match! Current Sig: {current_signature}, Last Sig: {self.last_message_signature}")
            
            with self._lock:
                if current_signature == self.last_message_signature:
                    if self.debug_filter:
                        print(f"[FILTER_DEBUG] Suppressing duplicate: {current_signature}")
                    return False 
                else:
                    self.last_message_signature = current_signature
                    if self.debug_filter:
                        print(f"[FILTER_DEBUG] Allowing NEW signature: {current_signature}")
                    return True 
        elif self.debug_filter and is_target_logger and is_target_level:
             print(f"[FILTER_DEBUG] Target Lgr/Lvl but wrong msg. StrippedMsg: '{current_message_stripped}', ExpectedPrefix: '{self.target_message_prefix}'")
            
        return True

try:
    root_logger = logging.getLogger()    
    # Remove any old AudioKeyManagerFilter instances if they were somehow added by name or different mechanism.    
    for f_old in list(root_logger.filters):
        if type(f_old).__name__ == 'AudioKeyManagerFilter': 
            root_logger.removeFilter(f_old)
            logging.info("Removed old AudioKeyManagerFilter instance by its class name string.")
    
    if not any(isinstance(f, DuplicateMessageFilter) for f in root_logger.filters):
        # For "CRITICAL:Librespot:AudioKeyManager:Audio key error, code: 2"        
        new_filter = DuplicateMessageFilter(
            target_logger_name_contains_lower="librespot.audiokeymanager", 
            target_level=logging.CRITICAL,
            target_message_prefix="Audio key error, code:"
        )
        root_logger.addFilter(new_filter)
        logging.info("Added DuplicateMessageFilter to the root logger for Librespot.AudioKeyManager critical errors.")
    else:
        logging.info("DuplicateMessageFilter already present on the root logger.")
except Exception as filter_ex:
    logging.warning(f"Could not add/configure DuplicateMessageFilter: {filter_ex}")

# --- Set Spotipy Client logger level to suppress verbose 401 errors ---
try:
    spotipy_client_logger = logging.getLogger('spotipy.client')
    # Set level to CRITICAL to suppress INFO, WARNING, and ERROR messages    
    spotipy_client_logger.setLevel(logging.CRITICAL)
    # Add a NullHandler if no handlers are configured to prevent "No handler found" warnings    
    if not spotipy_client_logger.hasHandlers():
        spotipy_client_logger.addHandler(logging.NullHandler())
    logging.info("Set spotipy.client logger level to CRITICAL to reduce verbosity on errors like 401.")
except Exception as log_ex:
    logging.warning(f"Could not configure spotipy.client logger level: {log_ex}")

# Define required scopes for OrpheusDL functionality
REQUIRED_SCOPES = "user-library-read playlist-read-private user-read-playback-state user-read-currently-playing"
# OrpheusDL Configuration Directory
ORPHEUS_CONFIG_DIR = "config"
# Base directory for this module's caches within the main OrpheusDL config directory.
SPOTIFY_MODULE_CACHE_BASE_DIR = os.path.join(ORPHEUS_CONFIG_DIR, ".spotify_module_cache")
# Location for Spotipy's cache file (Web API tokens)
WEB_API_CACHE_PATH = os.path.join(SPOTIFY_MODULE_CACHE_BASE_DIR, "spotipy_web_api_credentials.json")
# Location for librespot cache (including credentials.json for Stream API)
LIBRESPOT_CACHE_DIR = os.path.join(SPOTIFY_MODULE_CACHE_BASE_DIR, "librespot_cache")

# --- Import librespot-python --- 
try:
    from librespot.core import Session as LibrespotSession
    from librespot.metadata import TrackId
    from librespot.audio.decoders import AudioQuality, VorbisOnlyAudioQuality
    from librespot.proto import Authentication_pb2 as Authentication
    LIBRESPOT_PYTHON_AVAILABLE = True
except ImportError:
    logging.warning("librespot-python library not found. Stream downloading will likely fail.")
    LIBRESPOT_PYTHON_AVAILABLE = False
    class LibrespotSession:
        class Builder:
             def user_pass(self, u, p): return self
             def create(self): return None
             def stored_file(self, path=None): return self
        def content_feeder(self): return None
    class TrackId:
         @staticmethod
         def from_uri(uri): return None
    class AudioQuality:
         VERY_HIGH = None
    class VorbisOnlyAudioQuality:
         def __init__(self, quality): pass

# --- Constants for Zotify-like Interactive OAuth Flow ---
DESKTOP_CLIENT_ID = "65b708073fc0480ea92a077233ca87bd"
INTERACTIVE_OAUTH_REDIRECT_PORT = 4381
INTERACTIVE_OAUTH_REDIRECT_PATH = "/login"
INTERACTIVE_OAUTH_REDIRECT_URI = f"http://127.0.0.1:{INTERACTIVE_OAUTH_REDIRECT_PORT}{INTERACTIVE_OAUTH_REDIRECT_PATH}"
SPOTIFY_AUTH_URL = "https://accounts.spotify.com/authorize"
SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"
ZOTIFY_SCOPES = [
    "streaming", 
    "user-read-private", 
    "user-read-email", 
    "playlist-read-private", 
    "playlist-read-collaborative", 
    "user-library-read"
]

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
        super().__init__(f"Spotify (librespot) requires authorization. Please visit: {auth_url}")
class SpotifyLibrespotNeedsRedirectError(SpotifyAuthError):
    """Indicates Spotify librespot auth requires user interaction via a URL."""
    def __init__(self, auth_url):
        self.auth_url = auth_url
        super().__init__(f"Spotify (librespot) requires authorization. Please visit: {auth_url}")
class SpotifyLibrespotError(SpotifyAuthError):
    """Exception for errors during librespot interaction."""
    pass
class SpotifyTrackUnavailableError(SpotifyLibrespotError):
    """Raised when a track is unavailable (e.g., 'Cannot get alternative track')."""
    pass
class SpotifyRateLimitDetectedError(SpotifyLibrespotError):
    """Raised specifically when the interface detects a likely rate limit."""
    pass
class SpotifyRateLimitError(SpotifyApiError):
    """Exception for hitting Spotify API rate limits (HTTP 429)."""
    pass
class SpotifyItemNotFoundError(SpotifyApiError):
    """Exception for when a specific item (track, album, etc.) is not found (HTTP 404)."""
    pass
class SpotifyContentUnavailableError(SpotifyApiError):
    """Exception for content unavailable due to region restrictions or other reasons."""
    pass

class _InteractiveOAuthHelper:
    """Manages the interactive PKCE OAuth flow for Spotify."""
    def __init__(self, username_hint: str):        
        self.code_verifier = None
        self.auth_code = None
        self.access_token = None
        self.refresh_token = None
        self.error = None
        self._server_thread = None
        self._httpd = None

    def _start_local_server(self):
        class AuthCallbackHandler(BaseHTTPRequestHandler):
            helper_ref = self

            def do_GET(self):
                query_components = parse_qs(urlparse(self.path).query)
                code = query_components.get("code", [None])[0]
                error = query_components.get("error", [None])[0]

                if error:
                    AuthCallbackHandler.helper_ref.error = error
                    self.send_response(400)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(f"<html><body><h1>Authentication Failed</h1><p>{error}</p></body></html>".encode('utf-8'))
                elif code:
                    AuthCallbackHandler.helper_ref.auth_code = code
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write("<html><body><h1>Authentication Successful!</h1><p>You can close this window and return to OrpheusDL.</p></body></html>".encode('utf-8'))
                else:
                    AuthCallbackHandler.helper_ref.error = "Unknown error during callback."
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>Authentication Error</h1><p>No code or error received.</p></body></html>")
                
                # Trigger server shutdown once the request is handled
                threading.Thread(target=AuthCallbackHandler.helper_ref._httpd.shutdown).start()

            def log_message(self, format, *args):
                return

        try:
            self._httpd = HTTPServer(("127.0.0.1", INTERACTIVE_OAUTH_REDIRECT_PORT), AuthCallbackHandler)
            self._server_thread = threading.Thread(target=self._httpd.serve_forever)
            self._server_thread.daemon = True
            self._server_thread.start()
            logging.info(f"Local auth callback server started on port {INTERACTIVE_OAUTH_REDIRECT_PORT}.")
            return True
        except Exception as e:
            logging.error(f"Failed to start local auth callback server: {e}", exc_info=True)
            self.error = f"Failed to start local server: {e}"
            return False

    def get_authorization_url(self) -> str | None:
        if not self._start_local_server():
            return None
            
        self.code_verifier = pkce.generate_code_verifier(length=128)
        code_challenge = pkce.get_code_challenge(self.code_verifier)
        
        params = {
            "client_id": DESKTOP_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": INTERACTIVE_OAUTH_REDIRECT_URI,
            "scope": " ".join(ZOTIFY_SCOPES),
            "code_challenge_method": "S256",
            "code_challenge": code_challenge            
        }
        return f"{SPOTIFY_AUTH_URL}?{urlencode(params)}"

    def await_and_exchange_token(self, timeout_seconds=120) -> bool:
        if not self._server_thread or not self._httpd:
            self.error = "Local server not started."
            return False

        self._server_thread.join(timeout=timeout_seconds)
        
        if self._server_thread.is_alive():
            logging.warning("Timeout waiting for OAuth callback.")
            self.error = "Timeout waiting for authentication callback."
            if self._httpd:
                try: self._httpd.shutdown()
                except: pass
            return False

        if self.error:
            logging.error(f"OAuth callback error: {self.error}")
            return False
        
        if not self.auth_code:
            self.error = "Authorization code not received."
            logging.error(self.error)
            return False

        # Exchange authorization code for tokens
        payload = {
            "client_id": DESKTOP_CLIENT_ID,
            "grant_type": "authorization_code",
            "code": self.auth_code,
            "redirect_uri": INTERACTIVE_OAUTH_REDIRECT_URI,
            "code_verifier": self.code_verifier,
        }
        try:
            response = requests.post(SPOTIFY_TOKEN_URL, data=payload, timeout=10)
            response.raise_for_status()
            token_data = response.json()
            self.access_token = token_data.get("access_token")
            self.refresh_token = token_data.get("refresh_token")
            
            if not self.access_token:
                self.error = "Access token not found in Spotify's response."
                logging.error(f"Token exchange failed: {self.error} - Response: {token_data}")
                return False
            
            logging.info("Successfully exchanged authorization code for tokens.")
            return True
        except requests.exceptions.RequestException as e:
            logging.error(f"Token exchange request failed: {e}", exc_info=True)
            self.error = f"Token exchange failed: {e}"
            try:
                logging.error(f"Spotify token error response: {e.response.text if e.response else 'No response'}")
            except: pass
            return False
        except Exception as e:
            logging.error(f"Unexpected error during token exchange: {e}", exc_info=True)
            self.error = f"Unexpected error: {e}"
            return False

class SpotifyAPI:
    def __init__(self, config=None, settings_manager=None):
        if isinstance(config, dict):
            self.config = SimpleNamespace(**config)
        elif config is None:
            self.config = SimpleNamespace()
        else:
            self.config = config

        self.settings_manager = settings_manager
        self.auth_manager: SpotifyOAuth = None
        self.web_client: spotipy.Spotify = None
        self.librespot_session: LibrespotSession = None
        self.interactive_pkce_auth_failed_after_token: bool = False
        
        # Ensure Spotify module cache directory and subdirectories exist        
        os.makedirs(SPOTIFY_MODULE_CACHE_BASE_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(WEB_API_CACHE_PATH), exist_ok=True)
        os.makedirs(LIBRESPOT_CACHE_DIR, exist_ok=True)
        
        # Ensure librespot cache directory exists (redundant with above but specific for clarity here)
        if LIBRESPOT_PYTHON_AVAILABLE:
            os.makedirs(LIBRESPOT_CACHE_DIR, exist_ok=True)
            self.config.librespot_credentials_path = os.path.join(LIBRESPOT_CACHE_DIR, "credentials.json")
        else:
            # Also ensure attribute assignment works here
            if not hasattr(self.config, 'librespot_credentials_path'):
                 self.config.librespot_credentials_path = None

        # --- Initialize Web API Auth Manager and Client --- 
        try:
            client_id = self.get_config_value('client_id')
            client_secret = self.get_config_value('client_secret')
            redirect_uri = self.get_config_value('redirect_uri', 'http://localhost:8888/callback')

            if client_id and client_secret:
                self.auth_manager = SpotifyOAuth(
                    client_id=client_id,
                    client_secret=client_secret,
                    redirect_uri=redirect_uri,
                    scope=REQUIRED_SCOPES,
                    cache_path=WEB_API_CACHE_PATH,
                    open_browser=False,
                    show_dialog=False,
                    username=None                    
                )                
                logging.info("Spotipy auth manager initialized. Web client will be created upon successful auth.")
            else:
                 logging.warning("Client ID or Secret missing. Auth manager not fully initialized.")
                 
        except Exception as e:
             logging.error(f"Error initializing Spotipy auth manager: {e}", exc_info=True)
             self.auth_manager = None

        logging.info("SpotifyAPI initialized.")

    def get_config_value(self, key, env_var=None):
        """Helper to get config value, checking env vars first."""
        value = os.environ.get(env_var) if env_var else None
        if value:
            logging.debug(f"Using value from environment variable {env_var} for {key}")
            return value
        
        if key == 'client_id' or key == 'client_secret':
            logging.info(f"[SpotifyAPI.get_config_value] Attempting to get '{key}'. Current module_settings: {self.settings_manager.module_settings}")
        
        value = self.settings_manager.module_settings.get(key, None)

        if value is None:
            logging.warning(f"Configuration value '{key}' (or env var '{env_var}') not found.")
        return value

    def authenticate_web_api(self, response_url: str = None):
        """Authenticates with the Spotify Web API using Spotipy."""
        client_id = self.get_config_value('client_id', 'SPOTIPY_CLIENT_ID')
        client_secret = self.get_config_value('client_secret', 'SPOTIPY_CLIENT_SECRET')
        redirect_uri = self.get_config_value('redirect_uri', 'SPOTIPY_REDIRECT_URI')

        # Diagnostic logging
        logging.info(f"[SpotifyAPI.authenticate_web_api] Attempting to authenticate. Client ID from config: '{client_id}', Client Secret from config: '{client_secret is not None and client_secret != ''}', Redirect URI: '{redirect_uri}'")

        if not client_id or not client_secret:
            logging.error(f"[SpotifyAPI.authenticate_web_api] SpotifyConfigError: Client ID is '{client_id}', Client Secret is set: {client_secret is not None and client_secret != ''}")
            raise SpotifyConfigError("Client ID or Secret missing, cannot authenticate Web API.")

        try:
            token_info = self.auth_manager.get_cached_token()

            if not token_info:
                auth_url = self.auth_manager.get_authorize_url()
                if response_url:
                    logging.info("Exchanging code from provided response URL.")
                    code = self.auth_manager.parse_response_code(response_url)
                    token_info = self.auth_manager.get_access_token(code, as_dict=True, check_cache=False)
                else:
                    logging.info("No cached token. Attempting to get auth URL via GUI dialog.")
                    
                    if self.settings_manager:
                        logging.info(f"[SpotifyAPI authenticate_web_api] self.settings_manager.gui_handlers: {getattr(self.settings_manager, 'gui_handlers', 'N/A - settings_manager has no gui_handlers attr')}")
                    else:
                        logging.warning("[SpotifyAPI authenticate_web_api] self.settings_manager is None.")

                    gui_handler = self.settings_manager.get_gui_handler('show_spotify_auth_dialog') if self.settings_manager else None
                    
                    if gui_handler:
                        logging.info(f"Calling GUI handler for Spotify Web API auth with URL: {auth_url}")
                        response_url_from_dialog = gui_handler(auth_url=auth_url, parent_window=None)

                        if response_url_from_dialog:
                            logging.info("Received response URL from GUI dialog. Exchanging code.")
                            
                            code = self.auth_manager.parse_response_code(response_url_from_dialog)
                            token_info = self.auth_manager.get_access_token(code, as_dict=True, check_cache=False)
                            if not token_info:
                                logging.error("Failed to get token after GUI dialog.")
                                raise SpotifyAuthError("Failed to obtain token after GUI dialog.")
                        else:
                            logging.warning("GUI dialog cancelled or returned no URL.")
                            raise SpotifyAuthError("Spotify Web API authentication cancelled by user via GUI.")
                    else:
                        # CLI Mode: Handle authentication interactively
                        logging.info("CLI Mode: Prompting user for Web API authentication.")
                        print(f"--- Spotify Web API Authentication ---")
                        print("")
                        print(f"1. Open this URL in your browser:\n   {auth_url}")
                        print("2. Log in and grant permissions to OrpheusDL.")
                        print("3. After redirect (page may show error/blank), copy the ENTIRE URL from your browser.")
                        
                        response_url_from_cli = ""
                        try:
                            response_url_from_cli = input("4. Paste the full redirected URL here & press Enter: ")
                        except EOFError:
                            logging.warning("EOFError encountered when expecting user input for Spotify Web API auth URL.")
                            raise SpotifyAuthError("Spotify Web API authentication failed: Could not read input for redirected URL.")

                        if response_url_from_cli and response_url_from_cli.strip():
                            try:
                                logging.info("Exchanging code from CLI-provided response URL for Web API.")
                                code = self.auth_manager.parse_response_code(response_url_from_cli.strip())
                                token_info = self.auth_manager.get_access_token(code, as_dict=True, check_cache=False)
                                if not token_info:
                                     logging.error("Failed to obtain Web API token from CLI provided URL (get_access_token returned None).")
                                     raise SpotifyAuthError("Failed to obtain Web API token using the provided URL. Please ensure it was copied correctly.")
                            except spotipy.SpotifyOauthError as e_oauth_cli:
                                logging.error(f"Spotify OAuth Error during CLI Web API authentication: {e_oauth_cli}", exc_info=True)
                                raise SpotifyAuthError(f"Web API authentication failed with provided URL (OAuth Error): {e_oauth_cli}. Please check the URL and try again.")
                            except Exception as e_cli_auth:
                                logging.error(f"Error during CLI Web API authentication: {e_cli_auth}", exc_info=True)
                                raise SpotifyAuthError(f"Web API authentication failed with provided URL: {e_cli_auth}")
                        else:
                            logging.warning("No response URL provided by user in CLI for Web API authentication.")
                            raise SpotifyAuthError("Spotify Web API authentication cancelled or no URL provided by user.")
            
            # If we have token_info (cached or newly acquired)
            if token_info:                
                if self.auth_manager.is_token_expired(token_info):
                    logging.info("Cached/obtained token expired. Refreshing...")
                    token_info = self.auth_manager.refresh_access_token(token_info['refresh_token'])

                if token_info and 'access_token' in token_info:
                    logging.info(f"Successfully obtained token. Assigning new Spotipy client with token.")
                    self.web_client = spotipy.Spotify(auth=token_info['access_token'])
                else:
                    logging.error("Token info was expected but is missing or lacks access_token after auth flow.")
                    raise SpotifyAuthError("Failed to obtain valid access token from authentication flow.")

                # Verify authentication by making a simple API call
                user_info = self.web_client.current_user() # This call will now use the client with the direct token
                account_type = user_info.get('product') 
                logging.info(f"User account type: {account_type}")

                logging.info(f"Spotify Web API authentication successful for user: {user_info['display_name']} ({user_info['id']})")
                return True
                
        except SpotifyNeedsUserRedirectError as e:
            raise
        except spotipy.SpotifyOauthError as e:
            logging.error(f"Spotify OAuth Error: {e}", exc_info=True)
            raise SpotifyAuthError(f"OAuth Error: {e}")
        except Exception as e:
            logging.error(f"Spotify Web API authentication failed: {e}", exc_info=True)
            raise SpotifyApiError(f"Web API auth failed: {e}")
        return False

    def authenticate_stream_api(self, is_initial_setup_check: bool = False) -> bool:
        """
        Ensures the Librespot stream API is authenticated.        
        """
        if not LIBRESPOT_PYTHON_AVAILABLE:
            logging.error("librespot-python library is not available. Cannot authenticate stream API.")
            return False

        os.makedirs(LIBRESPOT_CACHE_DIR, exist_ok=True)

        # Check 1: Current session valid?
        if self.librespot_session and self._is_session_valid(self.librespot_session):
            logging.debug("Librespot session already valid.")
            return True

        # Check 2: Try stored token file
        token_file_existed_before_attempt = os.path.exists(self.config.librespot_credentials_path)

        if self._try_authenticate_from_stored_file():
            logging.info("Successfully authenticated Librespot from stored token file for streaming.")            
            self.interactive_pkce_auth_failed_after_token = False 
            return True
        
        if token_file_existed_before_attempt:
            logging.warning("Authentication with existing stored token failed. Deferring interactive OAuth for a potential retry of the operation.")            
            return False
        
        else:
            if is_initial_setup_check:
                logging.info("Initial setup check: No stored token file. Proceeding directly with interactive OAuth.")                
                if self.interactive_pkce_auth_failed_after_token:
                    logging.warning("Initial setup check: Skipping interactive PKCE OAuth due to recent post-token-exchange failure.")
                    return False
                if self._try_authenticate_with_interactive_oauth():
                    return True
                else:
                    return False
            else:                
                if self.interactive_pkce_auth_failed_after_token:
                    logging.warning("Skipping interactive PKCE OAuth attempt due to a recent failure after token exchange. A higher-level retry might be needed or manual intervention.")
                    return False                
                logging.info("No stored token file found (or previous attempt failed and was retried). Proceeding with interactive OAuth.")
                if self._try_authenticate_with_interactive_oauth():
                    return True

        if not (self.librespot_session and self._is_session_valid(self.librespot_session)):
            logging.debug("Stream API authentication ultimately failed after all attempts.")
        return False

    def _try_authenticate_from_stored_file(self) -> bool:
        logging.info("Attempting librespot authentication from MANUALLY PARSED stored credentials file...")        
        credentials_file_path = os.path.join(LIBRESPOT_CACHE_DIR, "credentials.json")
        
        if not os.path.exists(credentials_file_path):
            logging.info(f"No stored credentials file found at {credentials_file_path}. Skipping this method.")
            return False
        
        temp_session = None
        try:
            with open(credentials_file_path, 'r') as f:
                stored_creds_data = json.load(f)
            
            stored_username = stored_creds_data.get("username")
            stored_cred_blob_b64 = stored_creds_data.get("credentials")
            stored_auth_type_str = stored_creds_data.get("type")

            if not all([stored_username, stored_cred_blob_b64, stored_auth_type_str]):
                logging.warning("Stored credentials file is missing required fields (username, credentials, type).")
                return False

            try:
                auth_data_bytes = base64.b64decode(stored_cred_blob_b64)
            except Exception as b64_e:
                logging.warning(f"Failed to decode Base64 credentials from stored file: {b64_e}")
                return False

            if stored_auth_type_str == "AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS":
                auth_type_enum = Authentication.AuthenticationType.AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS            
            else:
                logging.warning(f"Unsupported authentication type '{stored_auth_type_str}' in stored credentials file.")
                return False

            logging.info(f"Successfully parsed stored credentials for user '{stored_username}' with type '{stored_auth_type_str}'.")

            config = LibrespotSession.Configuration.Builder().set_store_credentials(False).build()
            builder = LibrespotSession.Builder(config)
            
            device_id_str = str(uuid.uuid4())
            builder.set_device_id(device_id_str)
            builder.set_device_name("OrpheusDL")
            builder.set_device_type(DeviceType.COMPUTER)
            
            login_creds = Authentication.LoginCredentials(
                username=stored_username,
                typ=auth_type_enum,
                auth_data=auth_data_bytes
            )
            builder.login_credentials = login_creds
            
            temp_session = builder.create()

            # Check if session object was created and perform a basic functional check
            if temp_session:
                try:                    
                    session_username = temp_session.username() 
                    if session_username:
                        logging.info(f"Librespot authenticated successfully using MANUALLY PARSED stored credentials file (Username: {session_username}).")
                        self.librespot_session = temp_session
                        self.interactive_pkce_auth_failed_after_token = False
                        return True
                    else:
                        logging.warning("MANUALLY PARSED stored credentials: Session created but username is empty.")                        
                        return False
                except Exception as check_err:                    
                    logging.warning(f"MANUALLY PARSED stored credentials: Session created but failed basic check (.username()): {check_err}")
                    return False
            else:
                logging.warning("MANUALLY PARSED stored credentials: builder.create() returned None without exception.")
                return False
        except struct.error as e:            
            logging.warning(f"Error during librespot authentication from MANUALLY PARSED stored file: {e}", exc_info=False)            
            self.librespot_session = None
            return False
        except LibrespotSession.SpotifyAuthenticationException as e:
            logging.warning(f"MANUALLY PARSED stored credentials: SpotifyAuthenticationException (likely BadCredentials): {e}")            
            return False
        except Exception as e:
            logging.warning(f"Error during librespot authentication from MANUALLY PARSED stored file: {e}", exc_info=True)
            return False

    def _try_authenticate_with_interactive_oauth(self) -> bool:
        logging.info("Attempting librespot authentication with interactive Zotify-style OAuth flow...")

        self.interactive_pkce_auth_failed_after_token = False 

        user_provided_username = None        
        try:
            config_username = self.get_config_value('username', 'SPOTIFY_USERNAME')
            if config_username and config_username.strip():
                logging.info(f"Using Spotify username from configuration: {config_username}")
                user_provided_username = config_username.strip()
            else:
                logging.info("Spotify username not found in configuration or is empty, will prompt user.")
        except Exception as e:
            logging.warning(f"Could not retrieve username from config, will prompt user. Error: {e}")

        if not user_provided_username:
            logging.error("Username was not obtained either from config or prompt. Aborting.")
            print("Critical: Spotify username could not be determined. Aborting interactive login.")
            return False

        oauth_helper = _InteractiveOAuthHelper(user_provided_username)
        auth_url = oauth_helper.get_authorization_url()

        if not auth_url or oauth_helper.error:
            logging.error(f"Failed to get authorization URL: {oauth_helper.error}")
            # Check for GUI mode before printing CLI-specific error
            gui_handler_exists = self.settings_manager and self.settings_manager.get_gui_handler('show_spotify_auth_dialog')
            if not gui_handler_exists:
                print(f"Error: Could not prepare interactive login. Details: {oauth_helper.error}")
            return False

        # Check for GUI mode before printing CLI instructions
        gui_handler_exists = self.settings_manager and self.settings_manager.get_gui_handler('show_spotify_auth_dialog')

        if not gui_handler_exists:
            print("\n--- Spotify Stream Authorization ---")
            print("")
            print(f"1. Open this URL in your browser (it may open automatically):\n   {auth_url}")
            print("2. Log in, grant access, then you can close the Spotify tab.")
            print("   OrpheusDL will attempt to complete the process.")
        
        opened_browser = False
        try:
            if webbrowser.open(auth_url):
                opened_browser = True
                if not gui_handler_exists:
                    print("Attempted to open the authorization URL in your default browser.")
            else:
                if not gui_handler_exists:
                    print("Could not automatically open the browser. Please copy the URL above and paste it into your browser manually.")
        except Exception as e:
            logging.warning(f"Could not automatically open browser: {e}. Please copy the URL above and paste it into your browser manually.")
            if not gui_handler_exists:
                print(f"Could not automatically open browser: {e}. Please copy the URL above and paste it into your browser manually.")

        if not opened_browser and not gui_handler_exists:
            print("\nIf the browser did not open, please manually copy and paste this URL:")
            print(f"   {auth_url}\n")

        if not oauth_helper.await_and_exchange_token():
            logging.error(f"Failed to obtain OAuth tokens: {oauth_helper.error}")
            if not gui_handler_exists:
                print(f"Error: Spotify authentication failed. Details: {oauth_helper.error}")
            return False
            
        try:
            logging.info(f"Using PKCE OAuth token for user '{user_provided_username}' for librespot auth.")
            
            credentials_save_path = os.path.join(LIBRESPOT_CACHE_DIR, "credentials.json")
            config_builder = LibrespotSession.Configuration.Builder()
            config_builder.set_store_credentials(True)
            config_builder.set_stored_credential_file(credentials_save_path)
            config = config_builder.build()
            
            builder = LibrespotSession.Builder(config)
            device_id_str = str(uuid.uuid4())
            builder.set_device_id(device_id_str)
            builder.set_device_name("OrpheusDL")
            builder.set_device_type(DeviceType.COMPUTER)
            
            login_credentials = Authentication.LoginCredentials(
                username=user_provided_username,
                typ=Authentication.AuthenticationType.AUTHENTICATION_SPOTIFY_TOKEN,
                auth_data=oauth_helper.access_token.encode('utf-8')
            )
            builder.login_credentials = login_credentials
            
            self.librespot_session = builder.create()

            if self.librespot_session:
                logging.info(f"Librespot authenticated successfully using interactive PKCE OAuth. Credentials should be saved to {credentials_save_path}")
                self.interactive_pkce_auth_failed_after_token = False
                self.settings_manager.module_settings['spotify_refresh_token'] = oauth_helper.refresh_token
                return True
            else:
                logging.warning("Interactive PKCE OAuth: builder.create() returned None without exception.")
                self.interactive_pkce_auth_failed_after_token = True
                return False
        except LibrespotSession.SpotifyAuthenticationException as e:
            logging.warning(f"Interactive PKCE OAuth: SpotifyAuthenticationException with token: {e}")
            print(f"Error: Spotify authentication with the obtained token failed. Details: {e}")
            self.librespot_session = None
            self.interactive_pkce_auth_failed_after_token = True
            return False
        except MercuryClient.MercuryException as e:
            if "status: 403" in str(e):
                logging.debug(f"Interactive PKCE OAuth: Librespot session creation failed with 403 (permission issue with token). Details: {e}")
            else:
                logging.warning(f"Interactive PKCE OAuth: A Spotify communication error (Mercury) occurred: {e}", exc_info=False)
                print(f"Error: Could not complete Spotify login due to a Spotify communication issue. Details: {e}")
            self.librespot_session = None
            self.interactive_pkce_auth_failed_after_token = True
            return False
        except Exception as e:
            logging.warning(f"Unexpected error during librespot session creation with PKCE token: {e}", exc_info=True)
            print(f"Error: Could not complete Spotify login due to an unexpected issue. Details: {e}")
            self.librespot_session = None
            self.interactive_pkce_auth_failed_after_token = True
            return False

    def _is_session_valid(self, session):
        """Placeholder: Check if the librespot session is valid."""
        # TODO: Implement a proper check if librespot provides one (e.g., token expiry)
        # For now, just check if it exists and is connected.
        if session:
            try:
                # Attempt to get the username. If this succeeds and returns a non-empty string,
                # the session is considered active and logged in.
                username = session.username() # librespot.core.Session has a username() method
                if username: # Check if username is not None and not empty
                    return True
                else:
                    logging.debug("_is_session_valid: session.username() returned None or empty.")
                    return False
            except Exception as e:
                # If .username() fails (e.g., session is not properly connected or in a bad state)
                logging.debug(f"_is_session_valid: session.username() failed: {e}")
                return False
        return False

    # --- Web API Methods (using Spotipy) ---
    def search(self, query: str, search_type: str = 'track', limit: int = 20, offset: int = 0) -> dict | None:
        """Performs a search on Spotify using the Web API, with built-in re-authentication for expired tokens."""
        logging.info(f"SpotifyAPI: Searching Spotify ({search_type}) for '{query}' (limit: {limit}, offset: {offset})")

        # Ensure valid search_type
        valid_search_types = ['track', 'album', 'artist', 'playlist']
        if search_type not in valid_search_types:
            logging.error(f"SpotifyAPI.search: Invalid search type '{search_type}'. Must be one of: {valid_search_types}")
            raise ValueError(f"Invalid search type: {search_type}")

        # --- Initial authentication if web_client is not set ---
        if not self.web_client:
            logging.info("SpotifyAPI.search: Web client not available. Attempting initial authentication.")
            try:
                self.authenticate_web_api() # Raises SpotifyAuthError or SpotifyApiError on failure
                if not self.web_client: # Should be redundant if authenticate_web_api is robust
                    logging.error("SpotifyAPI.search: Web client is None after authenticate_web_api call that didn't raise. This is unexpected.")
                    raise SpotifyApiError("Web client became unexpectedly unavailable after an authentication attempt.")
            except (SpotifyAuthError, SpotifyApiError) as e:
                logging.error(f"SpotifyAPI.search: Initial authentication failed: {e}")
                raise # Propagate to ModuleInterface to handle (e.g., return empty list)

        # --- Perform search with retry for 401 and network errors ---
        MAX_AUTH_RETRIES = 1  # Max number of re-authentication attempts for a 401
        MAX_NETWORK_RETRIES = 2 # Max number of retries for network connection issues
        
        for attempt in range(max(MAX_AUTH_RETRIES, MAX_NETWORK_RETRIES) + 1): # Max attempts needed for either case
            if not self.web_client:
                # This state implies a critical failure in auth logic if reached without a prior exception.
                logging.error("SpotifyAPI.search: CRITICAL - web_client is None at the start of a search attempt. Auth propagation failed.")
                raise SpotifyAuthError("Web client is not available for search, and prior authentication attempts failed to establish it or propagate errors correctly.")

            try:
                effective_limit = min(limit, 50)
                if limit > 50:
                    logging.warning(f"SpotifyAPI.search: Requested search limit {limit} exceeds Spotify API maximum (50). Capping at {effective_limit}.")
                
                logging.info(f"SpotifyAPI.search: Calling Spotipy client search (overall attempt {attempt + 1}) "
                             f"q='{query}', limit={effective_limit}, type='{search_type}', offset={offset}")
                
                results = self.web_client.search(q=query, limit=effective_limit, type=search_type, offset=offset)
                logging.info(f"SpotifyAPI.search: Search successful (attempt {attempt + 1}).")
                return results # Success

            except spotipy.SpotifyException as e:
                logging.warning(f"SpotifyAPI.search: SpotifyException on attempt {attempt + 1} (HTTP {e.http_status}): {e.msg}")
                if e.http_status == 401:
                    self.web_client = None # Invalidate client immediately
                    if attempt < MAX_AUTH_RETRIES:
                        logging.info("SpotifyAPI.search: Token expired (401). Attempting re-authentication...")
                        try:
                            self.authenticate_web_api() # This will raise on failure or set self.web_client
                            if not self.web_client: # Safety check, should be guaranteed by authenticate_web_api
                                logging.error("SpotifyAPI.search: Re-authentication seemed to succeed (no error raised) but web_client is still None.")
                                raise SpotifyAuthError("Re-authentication completed but web client was not established.")
                            logging.info("SpotifyAPI.search: Re-authentication successful. Retrying search in next iteration.")
                            continue # Retry the search
                        except (SpotifyAuthError, SpotifyApiError) as auth_e:
                            logging.error(f"SpotifyAPI.search: Re-authentication failed: {auth_e}")
                            raise auth_e # Propagate the specific auth failure, search will not be retried
                    else:
                        logging.error("SpotifyAPI.search: Token remained invalid (401) after re-authentication and retry.")
                        raise SpotifyAuthError("Spotify token became invalid and re-authentication failed or was unsuccessful after retries.")
                elif e.http_status == 429:
                    raise SpotifyRateLimitError(f"Spotify API rate limit hit during search: {e.msg}")
                elif e.http_status == 404:
                    raise SpotifyItemNotFoundError(f"Search returned 404 (item not found or bad request): {e.msg}")
                else: # Other HTTP errors
                    raise SpotifyApiError(f"Spotify search failed with HTTP {e.http_status}: {e.msg}")
            
            except RequestsConnectionError as rce:
                logging.error(f"SpotifyAPI.search: Network error on attempt {attempt + 1}: {rce}", exc_info=True)
                if attempt < MAX_NETWORK_RETRIES:
                    retry_delay = 2 * (attempt + 1) # Simple exponential backoff: 2s, 4s
                    logging.info(f"SpotifyAPI.search: Retrying search after network error in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    # If web_client was valid before network error, no need to re-auth unless it was a very long outage causing token expiry.
                    # For simplicity, we don't force re-auth here, just retry the operation.
                    continue
                else:
                    logging.error(f"SpotifyAPI.search: Persistent network error after {MAX_NETWORK_RETRIES + 1} attempts.")
                    raise SpotifyApiError(f"Persistent network error during Spotify search: {rce}")

            except Exception as ex:
                logging.error(f"SpotifyAPI.search: Unexpected error on attempt {attempt + 1}: {ex}", exc_info=True)
                # For unexpected errors, typically don't retry unless specifically designed to.
                raise SpotifyApiError(f"Unexpected error during Spotify search: {ex}")
        
        # Fallback, should ideally not be reached if loop logic correctly raises exceptions on unrecoverable failures.
        logging.error("SpotifyAPI.search: Exited search loop without returning results or raising an exception. This indicates a bug.")
        raise SpotifyApiError("Search operation failed after multiple attempts due to an unknown issue.")

    def get_track_info(self, track_id: str, stop_event: threading.Event = None) -> dict | None:
        """Gets track information from Spotify Web API, with retry for ReadTimeout and re-auth for 401."""
        logging.info(f"Attempting to get track info for ID: {track_id}")
        reauth_attempted_for_this_call = False

        if not self.web_client:
            logging.warning("Web client not available for get_track_info. Attempting pre-emptive authentication.")
            try:                
                self.authenticate_web_api() 
                if not self.web_client:
                    logging.error("Web API pre-emptive authentication attempted, but web_client is still not set. Cannot get track info.")
                    return None
                logging.info("Pre-emptive authentication successful, web_client is set.")
            except SpotifyAuthError as e_auth:
                logging.error(f"Web API pre-emptive authentication failed: {e_auth}. Cannot get track info for {track_id}.")
                return None
            except Exception as e_auth_unexpected:
                logging.error(f"Unexpected error during Web API pre-emptive authentication for {track_id}: {e_auth_unexpected}", exc_info=True)
                return None

        track_data = None
        max_retries = 3
        retry_delay_seconds = 5

        for attempt in range(max_retries):
            try:
                logging.debug(f"Attempt {attempt + 1}/{max_retries} to get track info for {track_id}")
                if not self.web_client:
                    logging.error(f"Web client is unexpectedly None at attempt {attempt + 1} for track {track_id}. Aborting fetch for this track.")
                    return None
                track_data = self.web_client.track(track_id)
                if track_data:
                    logging.debug(f"Successfully fetched track info for {track_id} on attempt {attempt + 1}")
                    break
                else:
                    logging.warning(f"No track data returned by API for ID: {track_id} on attempt {attempt + 1} (without exception). Not retrying this specific case.")
                    break

            except requests.exceptions.ReadTimeout as e_timeout:
                logging.warning(f"Read timeout on attempt {attempt + 1}/{max_retries} for track {track_id}: {e_timeout}")
                if attempt < max_retries - 1:
                    if stop_event and stop_event.is_set():
                        logging.info(f"Stop event detected during retry delay for track {track_id}. Aborting.")
                        track_data = None
                        break
                    logging.info(f"Retrying in {retry_delay_seconds} seconds...")
                    time.sleep(retry_delay_seconds)
                else:
                    logging.error(f"Failed to get track info for {track_id} after {max_retries} attempts due to ReadTimeout.")
            
            except spotipy.SpotifyException as e_spotify:
                log_prefix = f"Spotify API error (attempt {attempt + 1}/{max_retries}) for track {track_id}"
                
                if hasattr(e_spotify, 'http_status') and e_spotify.http_status == 401:
                    if not reauth_attempted_for_this_call:
                        reauth_attempted_for_this_call = True                        
                        logging.warning(f"Spotify Web API token for track {track_id} expired (401). Attempting automatic re-authentication...")
                        try:
                            self.authenticate_web_api()
                            if self.web_client:
                                logging.info(f"Re-authentication successful for track {track_id}. Retrying API call.")
                                continue
                            else:
                                logging.error(f"{log_prefix}: Re-authentication attempted but web_client not set. Giving up on track {track_id}.")
                                track_data = None
                                break
                        except SpotifyAuthError as auth_ex:
                            logging.error(f"{log_prefix}: Re-authentication failed: {auth_ex}. Giving up on track {track_id}.")
                            track_data = None
                            break
                        except Exception as e_auth_unexpected:
                            logging.error(f"{log_prefix}: Unexpected error during re-authentication: {e_auth_unexpected}. Giving up on track {track_id}.", exc_info=True)
                            track_data = None
                            break
                    else:
                        logging.error(f"{log_prefix}: Access token still invalid (401) after a re-authentication attempt. Giving up on track {track_id}.")
                        track_data = None
                        break
                elif hasattr(e_spotify, 'http_status') and e_spotify.http_status == 404:
                    logging.warning(f"{log_prefix}: Track ID {track_id} not found on Spotify (404).")
                    track_data = None
                    break 
                elif hasattr(e_spotify, 'http_status') and e_spotify.http_status == 429:
                    logging.warning(f"{log_prefix}: Rate limited by Spotify API (429).")
                    track_data = None
                    break 
                elif hasattr(e_spotify, 'http_status') and e_spotify.http_status == 403:
                    logging.error(f"{log_prefix}: Spotify API forbidden (403) for track {track_id}. Check permissions. Not retrying with re-auth.")
                    track_data = None
                    break
                else:
                    logging.error(f"{log_prefix}: Unhandled SpotifyException: {e_spotify}. Status: {getattr(e_spotify, 'http_status', 'N/A')}. Not retrying with re-auth.")
                    track_data = None
                    break

            except requests.exceptions.RequestException as e_req:
                 logging.error(f"Network error getting track info for {track_id} (attempt {attempt + 1}/{max_retries}): {e_req}", exc_info=True)
                 track_data = None
                 break

            except Exception as e_generic:
                logging.error(f"Unexpected error getting track info for {track_id} (attempt {attempt + 1}/{max_retries}): {e_generic}", exc_info=True)
                track_data = None
                break
        
        if not track_data:            
            return None
            
        return track_data

    def get_album_info(self, album_id: str) -> dict | None:
        """Fetches detailed album information using the Web API."""
        logging.info(f"Getting album info for ID: {album_id}")
        if not self.web_client:
            logging.warning("Web client not available for get_album_info. Attempting authentication.")
            try:
                if not self.authenticate_web_api():
                    raise SpotifyAuthError("Authentication required before getting album info.")
            except SpotifyNeedsUserRedirectError as e:
                 raise SpotifyAuthError("Authentication required before getting album info. Please login first.")
            except SpotifyApiError as e:
                raise SpotifyAuthError(f"Authentication failed during get_album_info attempt: {e}")
            if not self.web_client:
                 raise SpotifyApiError("Web client still not available after authentication attempt.")
        
        try:
            album_data = self.web_client.album(album_id)
            logging.info(f"Successfully fetched album info for: {album_data.get('name', 'N/A')}")
            # TODO: Check album availability? (e.g., album_data.get('available_markets'))
            return album_data
        except spotipy.SpotifyException as e:
            logging.error(f"Spotify API get album error: {e.http_status} - {e.msg}", exc_info=True)
            if e.http_status == 401:
                 self.web_client = None
                 raise SpotifyAuthError("Spotify token became invalid. Please login again.")
            elif e.http_status == 404:
                 raise SpotifyItemNotFoundError(f"Album ID not found: {album_id}") 
            elif e.http_status == 429:
                 raise SpotifyRateLimitError(f"Spotify API rate limit hit getting album info: {e.msg}")
            else:
                 raise SpotifyApiError(f"Spotify get album failed: {e.msg} (Status: {e.http_status})")
        except Exception as e:
            logging.error(f"Unexpected error getting album info: {e}", exc_info=True)
            raise SpotifyApiError(f"Unexpected error getting album info: {e}")

    def get_playlist_info(self, playlist_id: str, stop_event: threading.Event = None) -> dict | None:
        """Fetches detailed playlist information using the Web API."""
        logging.info(f"Getting playlist info for ID: {playlist_id}")
        if not self.web_client:
            logging.warning("Web client not available for get_playlist_info. Attempting authentication.")
            try:
                if not self.authenticate_web_api():
                    raise SpotifyAuthError("Authentication required before getting playlist info.")
            except SpotifyNeedsUserRedirectError as e:
                 raise SpotifyAuthError("Authentication required before getting playlist info. Please login first.")
            except SpotifyApiError as e:
                raise SpotifyAuthError(f"Authentication failed during get_playlist_info attempt: {e}")
            if not self.web_client:
                 raise SpotifyApiError("Web client still not available after authentication attempt.")
        
        try:            
            playlist_data = self.web_client.playlist(playlist_id)
            if not playlist_data or 'tracks' not in playlist_data:
                logging.error(f"Failed to fetch initial playlist data or no tracks found for {playlist_id}")
                return None

            all_track_items = playlist_data['tracks']['items']
            current_tracks_page = playlist_data['tracks']

            # Paginate if there are more tracks
            while current_tracks_page and current_tracks_page['next']:
                if stop_event and stop_event.is_set():
                    logging.info(f"Stop event detected during playlist track pagination for {playlist_id}. Returning partially fetched data.")
                    break
                logging.info(f"Fetching next page of tracks for playlist {playlist_id}...")
                try:
                    current_tracks_page = self.web_client.next(current_tracks_page)
                    if current_tracks_page and current_tracks_page['items']:
                        all_track_items.extend(current_tracks_page['items'])
                    else:                        
                        break 
                except spotipy.SpotifyException as page_e:
                    logging.error(f"Error fetching next page of tracks for playlist {playlist_id}: {page_e}")                    
                    break
            
            playlist_data['tracks']['items'] = all_track_items            
            
            logging.info(f"Successfully fetched all {len(all_track_items)} tracks for playlist: {playlist_data.get('name', 'N/A')}")
            return playlist_data
        except spotipy.SpotifyException as e:
            logging.error(f"Spotify API get playlist error: {e.http_status} - {e.msg}", exc_info=True)
            if e.http_status == 401:
                 self.web_client = None
                 raise SpotifyAuthError("Spotify token became invalid. Please login again.")
            elif e.http_status == 404:
                 raise SpotifyItemNotFoundError(f"Playlist ID not found: {playlist_id}") 
            elif e.http_status == 429:
                 raise SpotifyRateLimitError(f"Spotify API rate limit hit getting playlist info: {e.msg}")
            else:
                 raise SpotifyApiError(f"Spotify get playlist failed: {e.msg} (Status: {e.http_status})")
        except Exception as e:
            logging.error(f"Unexpected error getting playlist info: {e}", exc_info=True)
            raise SpotifyApiError(f"Unexpected error getting playlist info: {e}")

    def get_artist_info(self, artist_id: str) -> dict | None:
        """Fetches detailed artist information using the Web API."""
        logging.info(f"Getting artist info for ID: {artist_id}")
        if not self.web_client:
            logging.warning("Web client not available for get_artist_info. Attempting authentication.")
            try:
                if not self.authenticate_web_api():
                    raise SpotifyAuthError("Authentication required before getting artist info.")
            except SpotifyNeedsUserRedirectError as e:
                 raise SpotifyAuthError("Authentication required before getting artist info. Please login first.")
            except SpotifyApiError as e:
                raise SpotifyAuthError(f"Authentication failed during get_artist_info attempt: {e}")
            if not self.web_client:
                 raise SpotifyApiError("Web client still not available after authentication attempt.")
        
        try:
            artist_data = self.web_client.artist(artist_id)
            logging.info(f"Successfully fetched artist info for: {artist_data.get('name', 'N/A')}")
            return artist_data
        except spotipy.SpotifyException as e:
            logging.error(f"Spotify API get artist error: {e.http_status} - {e.msg}", exc_info=True)
            if e.http_status == 401:
                 self.web_client = None
                 raise SpotifyAuthError("Spotify token became invalid. Please login again.")
            elif e.http_status == 404:
                 raise SpotifyItemNotFoundError(f"Artist ID not found: {artist_id}") 
            elif e.http_status == 429:
                 raise SpotifyRateLimitError(f"Spotify API rate limit hit getting artist info: {e.msg}")
            else:
                 raise SpotifyApiError(f"Spotify get artist failed: {e.msg} (Status: {e.http_status})")
        except Exception as e:
            logging.error(f"Unexpected error getting artist info: {e}", exc_info=True)
            raise SpotifyApiError(f"Unexpected error getting artist info: {e}")
    
    def get_artist_albums(self, artist_id: str, include_groups: str = 'album,single', limit: int = 50, stop_event: threading.Event = None) -> List[dict] | None:
        """Fetches artist's albums using the Web API, handling pagination."""
        logging.info(f"Getting albums for artist ID: {artist_id}")
        if not self.web_client:
            logging.warning("Web client not available for get_artist_albums.")            
            try:
                if not self.authenticate_web_api():
                    raise SpotifyAuthError("Authentication required before getting artist albums.")
            except Exception as auth_e:
                logging.error(f"Auth failed during get_artist_albums: {auth_e}")
                return None
            if not self.web_client:
                logging.error("Web client still not available after auth attempt in get_artist_albums.")
                return None

        all_albums = []
        offset = 0
        try:
            while True:
                if stop_event and stop_event.is_set():
                    logging.info(f"Stop event detected during artist album pagination for {artist_id}. Returning partially fetched data.")
                    break
                logging.debug(f"Fetching artist albums page: limit={limit}, offset={offset}")
                results = self.web_client.artist_albums(
                    artist_id,
                    album_type=include_groups,
                    limit=limit,
                    offset=offset
                )
                if not results or not results.get('items'):
                    logging.debug("No more album items found or empty results.")
                    break

                page_albums = results['items']
                all_albums.extend(page_albums)
                logging.debug(f"Fetched {len(page_albums)} albums this page. Total so far: {len(all_albums)}")

                # Check if there are more pages
                if results.get('next'):
                    offset += limit
                else:
                    logging.debug("No 'next' page found, finishing album fetch.")
                    break

            logging.info(f"Successfully fetched {len(all_albums)} total albums for artist {artist_id}")
            return all_albums

        except spotipy.SpotifyException as e:
            logging.error(f"Spotify API get artist albums error: {e.http_status} - {e.msg}", exc_info=False)
            if e.http_status == 401:
                 self.web_client = None
                 raise SpotifyAuthError("Spotify token became invalid. Please login again.") from e
            elif e.http_status == 404:
                 raise SpotifyItemNotFoundError(f"Artist ID not found when fetching albums: {artist_id}") from e
            elif e.http_status == 429:
                 raise SpotifyRateLimitError(f"Spotify API rate limit hit getting artist albums: {e.msg}") from e
            else:
                 raise SpotifyApiError(f"Spotify get artist albums failed: {e.msg} (Status: {e.http_status})") from e
        except Exception as e:
            logging.error(f"Unexpected error getting artist albums: {e}", exc_info=True)
            raise SpotifyApiError(f"Unexpected error getting artist albums: {e}") from e

    def get_artist_top_tracks(self, artist_id: str, market: str = 'US') -> List[dict] | None:
        """Fetches artist's top tracks using the Web API."""
        logging.info(f"Getting top tracks for artist ID: {artist_id} in market {market}")
        if not self.web_client:
            logging.warning("Web client not available for get_artist_top_tracks.")            
            try:
                if not self.authenticate_web_api():
                    raise SpotifyAuthError("Authentication required before getting artist top tracks.")
            except Exception as auth_e:
                logging.error(f"Auth failed during get_artist_top_tracks: {auth_e}")
                return None
            if not self.web_client:
                logging.error("Web client still not available after auth attempt in get_artist_top_tracks.")
                return None

        try:
            results = self.web_client.artist_top_tracks(artist_id, country=market)
            if results and results.get('tracks'):
                 logging.info(f"Successfully fetched {len(results['tracks'])} top tracks for artist {artist_id}")
                 return results['tracks']
            else:
                 logging.warning(f"No top tracks found for artist {artist_id} in market {market}")
                 return []

        except spotipy.SpotifyException as e:
            logging.error(f"Spotify API get artist top tracks error: {e.http_status} - {e.msg}", exc_info=False)
            if e.http_status == 401:
                 self.web_client = None
                 raise SpotifyAuthError("Spotify token became invalid. Please login again.") from e
            elif e.http_status == 404:
                 logging.warning(f"Artist ID {artist_id} not found or no top tracks available in market {market}.")
                 return []
            elif e.http_status == 429:
                 raise SpotifyRateLimitError(f"Spotify API rate limit hit getting artist top tracks: {e.msg}") from e
            else:
                 raise SpotifyApiError(f"Spotify get artist top tracks failed: {e.msg} (Status: {e.http_status})") from e
        except Exception as e:
            logging.error(f"Unexpected error getting artist top tracks: {e}", exc_info=True)
            raise SpotifyApiError(f"Unexpected error getting artist top tracks: {e}") from e

    # --- Stream/Download Methods ---
    def get_track_stream_info(self, track_id_str: str, quality: AudioQuality = AudioQuality.VERY_HIGH):
        """Gets the raw audio stream using the authenticated librespot-python session."""
        try:
            if not LIBRESPOT_PYTHON_AVAILABLE:
                logging.error("librespot-python library is not available for get_track_stream_info.")
                raise SpotifyLibrespotError("librespot-python not available.")

            if not self.authenticate_stream_api():
                logging.error("Stream download attempted (get_track_stream_info) without librespot authentication or auth failed.")
                raise SpotifyAuthError("Stream API not authenticated. Please login.")
            
            if not self.librespot_session:
                logging.error("Librespot session is not initialized.")
                raise SpotifyLibrespotError("Librespot session not initialized.")

            track_id_obj = TrackId.from_uri(f"spotify:track:{track_id_str}")
            if not track_id_obj:
                logging.error(f"Could not create TrackId object from: {track_id_str}")
                raise SpotifyLibrespotError(f"Invalid track ID format for librespot: {track_id_str}")

            # Map Orpheus quality to librespot AudioQuality
            # For now, we hardcode to VERY_HIGH as that's the only one used by _fetch_stream_with_retries
            # This could be expanded if different qualities are passed down.
            audio_quality_picker = VorbisOnlyAudioQuality(AudioQuality.VERY_HIGH) 

            logging.debug(f"Librespot: Loading stream for track {track_id_str} with quality {quality}")
            
            stream_loader = self.librespot_session.content_feeder().load(
                track_id_obj, audio_quality_picker, False, None
            )

            if not stream_loader or not hasattr(stream_loader, 'input_stream') or not hasattr(stream_loader.input_stream, 'stream'):
                logging.error(f"Librespot stream_loader or its input_stream is invalid for track {track_id_str}.")
                raise SpotifyLibrespotError(f"Failed to obtain a valid stream object from librespot for track {track_id_str}.")

            # Determine codec (librespot often defaults to OGG Vorbis)
            actual_codec = "ogg_vorbis"
            # TODO: A more reliable way to get codec from librespot stream_loader if available

            logging.info(f"Successfully loaded stream via librespot for track {track_id_str}. Codec assumed: {actual_codec}")
            return {
                'stream': stream_loader.input_stream.stream(), 
                'codec': actual_codec, 
                'error': None
            }

        except RuntimeError as e:
            error_message = str(e)
            clean_error_message = error_message
            gid_index = error_message.find('gid:')
            if gid_index != -1:
                clean_error_message = error_message[:gid_index].strip().rstrip(',')
            
            if clean_error_message == "Failed fetching audio key!":
                logging.debug(f"Error getting track stream via librespot-python: {clean_error_message} (RuntimeError)", exc_info=False)
            elif "Cannot get alternative track" not in clean_error_message:
                logging.error(f"Error getting track stream via librespot-python: {clean_error_message} (RuntimeError)", exc_info=False)

            if "Cannot get alternative track" in clean_error_message:
                raise SpotifyTrackUnavailableError(f"Track unavailable: {clean_error_message}") from e
            else:
                raise SpotifyLibrespotError(f"Error getting track stream: {clean_error_message}") from e
        except Empty:
            logging.debug("Error getting track stream via librespot-python: Audio key retrieval timed out or failed (_queue.Empty).", exc_info=False)
            raise SpotifyLibrespotError("Error getting track stream: Audio key retrieval failed (timeout).") from None
        except RequestsConnectionError as ce:
            logging.warning(f"Librespot connection error getting track stream: {ce}", exc_info=False)
            simplified_error = "Connection aborted or remote end closed connection."
            if ce.args and isinstance(ce.args[0], tuple) and len(ce.args[0]) > 0:
                raw_msg_part = str(ce.args[0][0])
                if "RemoteDisconnected" in str(ce.args[0]):
                    try:
                        inner_error_obj = ce.args[0][1]
                        if hasattr(inner_error_obj, 'args') and inner_error_obj.args:
                            simplified_error = f"{raw_msg_part.rstrip('.')}: {str(inner_error_obj.args[0])}"
                        else:
                            simplified_error = raw_msg_part
                    except IndexError:
                        simplified_error = raw_msg_part
                elif raw_msg_part:
                     simplified_error = raw_msg_part
            raise SpotifyLibrespotError(f"Error getting track stream: {simplified_error}") from ce
        except Exception as e:
            logging.error(f"Unexpected error getting track stream: {e}", exc_info=True)
            raise SpotifyLibrespotError(f"Unexpected error getting track stream: {e}") from e

    # --- Logout/Cleanup ---
    def clear_credentials(self):
        """Clears cached credentials for both Web API and Stream API."""
        if os.path.exists(WEB_API_CACHE_PATH):
            try:
                os.remove(WEB_API_CACHE_PATH)
                logging.info("Cleared Web API (Spotipy) credentials cache.")
            except OSError as e:
                logging.warning(f"Could not remove Web API cache file: {e}")
        self.web_client = None

        # Clear librespot session and potentially credentials file
        self.librespot_session = None        
        logging.info("Cleared Stream API (librespot-python) session.")