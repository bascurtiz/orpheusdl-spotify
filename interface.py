import datetime
import logging
import os
import sys
import time
from typing import List, Optional, Tuple
from enum import Enum
from traceback import print_exc

# --- Custom Log Filter for Mutagen OggVorbisHeaderError ---
class MutagenOggVorbisFilter(logging.Filter):
    def filter(self, record):        
        if isinstance(record.msg, str):
            message_content = record.getMessage()
            if ("mutagen" in message_content and 
                "OggVorbisHeaderError" in message_content and 
                "unable to read full header" in message_content and
                "Ignoring" in message_content):
                return False
        return True

# Apply the filter to the root logger
root_logger = logging.getLogger()
if not any(isinstance(f, MutagenOggVorbisFilter) for f in root_logger.filters):
    root_logger.addFilter(MutagenOggVorbisFilter())
    logging.debug("Applied MutagenOggVorbisFilter to the root logger.")

# --- Add project root to sys.path using append ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.append(project_root)

try:
    from utils.models import (
        ModuleInformation, ModuleFlags, ManualEnum, ModuleModes, # Directly import ModuleFlags
        DownloadTypeEnum, TrackDownloadInfo, SearchResult, TrackInfo,
        AlbumInfo, PlaylistInfo, ArtistInfo, CoverInfo, Tags,
        QualityEnum, CodecOptions, CoverOptions, DownloadEnum, CodecEnum,
        MediaIdentification, ModuleController, codec_data, ImageFileTypeEnum
    )
    from utils.exceptions import ModuleGeneralError, ModuleAPIError # Corrected imports    
  
except ImportError as e:    
    logging.warning(f"Could not import OrpheusDL core modules from utils. Error: {e}. Using dummy placeholders.")
    
    # Dummy placeholders remain for standalone testing, but ModuleFlags part changes
    class DownloadEnum: URL = 1; TEMP_FILE_PATH = 2; MPD = 3
    class CodecEnum: VORBIS = 1; AAC = 2; FLAC = 3; MP3 = 4
    class QualityEnum: LOW=1; HIGH=2; HIFI=3
    class TrackDownloadInfo:
        def __init__(self, download_type=None, file_url=None, codec=None, **kwargs): pass
    class SearchResult:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)
    class TrackInfo: pass
    class AlbumInfo: pass
    class PlaylistInfo: pass
    class ArtistInfo: pass
    class CoverInfo: pass
    class ModuleInformation: pass
    class ModuleController: pass
    class DownloadTypeEnum:
        track="track"; album="album"; playlist="playlist"; artist="artist"
    class MediaIdentification: pass
    class ModuleModes:
        download = "download_dummy"; search = "search_dummy"; lyrics = "lyrics_dummy"; covers = "covers_dummy"; credits = "credits_dummy"
    class Tags: pass
    class CodecOptions: pass
    class CoverOptions: pass
    class ManualEnum:
        manual = "manual_dummy"; orpheus = "orpheus_dummy"
    class DummyFlags:
        def __contains__(self, item): return False
    class DummyContainer: name = 'tmp'
    class DummyCodecData: container = DummyContainer()
    codec_data = {CodecEnum.VORBIS: DummyCodecData(), CodecEnum.AAC: DummyCodecData(), CodecEnum.FLAC: DummyCodecData(), CodecEnum.MP3: DummyCodecData()}
    
    class ModuleFlags(Enum): # Basic fallback for dummy
        enable_jwt_system = 1
        uses_data = 2        

# Local API wrapper import
from .spotify_api import (
    SpotifyAPI,
    SpotifyApiError,
    SpotifyAuthError,
    SpotifyNeedsUserRedirectError,
    SpotifyLibrespotError,
    SpotifyRateLimitDetectedError,
    SpotifyItemNotFoundError,
    SpotifyTrackUnavailableError,
)

# Define the module information object after ModuleFlags is properly defined
module_information = ModuleInformation(
    service_name="Spotify",
    flags=[
        ModuleFlags.enable_jwt_system,
    ],
    login_behaviour=ManualEnum.manual,
    global_settings={
        "username": "",
        "download_pause_seconds": 30
    },
    session_settings={},
    module_supported_modes=[
        ModuleModes.download,
        ModuleModes.covers
    ],
    netlocation_constant=["spotify.com", "open.spotify.com"],
    url_constants={
        "track": DownloadTypeEnum.track,
        "album": DownloadTypeEnum.album,
        "playlist": DownloadTypeEnum.playlist,
        "artist": DownloadTypeEnum.artist
    },
    url_decoding=ManualEnum.orpheus,
    global_storage_variables=[],
    session_storage_variables=[]
)

# --- Module Interface Class ---
class ModuleInterface:
    """Implements the OrpheusDL interface for Spotify."""

    def __init__(self, module_controller: ModuleController):
        self.controller = module_controller
        self.settings = module_controller.module_settings
        self.module_error = module_controller.module_error
        self.printer = module_controller.printer_controller
        self.spotify_api = SpotifyAPI(config=self.settings, module_controller=module_controller)
        self.logged_in = False # Initialize login status
        self.logger = logging.getLogger(__name__)
        # Access debug_mode from the controller, defaulting to False if not present
        self.debug_mode = getattr(self.controller, 'debug_mode', False)

        if self.debug_mode:
            self.logger.info(f"[Spotify Interface __init__] Received module_controller.gui_handlers: {self.controller.gui_handlers}")
        
        # Filter out Mutagen OggVorbisHeaderError messages if not already done
        if not any(isinstance(f, MutagenOggVorbisFilter) for f in self.logger.filters):
            self.logger.addFilter(MutagenOggVorbisFilter())
        if self.debug_mode:
            self.logger.info("Spotify module initialized successfully.")

        self.metadata_cache = {
            'track': {},
            'album': {},
            'playlist': {},
            'artist': {}
        }

    def _ensure_authenticated(self, context_message: str) -> bool:
        """Checks if authenticated and attempts login if not. Returns True if authenticated, False otherwise."""
        if self.debug_mode:
            self.logger.info(f"[{context_message}] Entry point for _ensure_authenticated.")
        session_is_initially_valid = self.spotify_api._is_session_valid(self.spotify_api.librespot_session)
        if self.debug_mode:
            self.logger.info(f"[{context_message}] Initial _is_session_valid check returned: {session_is_initially_valid}")

        if not session_is_initially_valid:
            if self.debug_mode:
                self.logger.info(f"[{context_message}] Session not initially valid. Attempting login via authenticate_stream_api (non-forced)...")
            try:
                auth_attempt_result = self.spotify_api.authenticate_stream_api() # Non-forced
                if self.debug_mode:
                    self.logger.info(f"[{context_message}] authenticate_stream_api (non-forced) call returned: {auth_attempt_result}")
                
                if not auth_attempt_result:
                    self.logger.warning(f"[{context_message}] authenticate_stream_api (non-forced) indicated failure. Setting logged_in=False.")
                    self.printer.oprint("Spotify authentication failed or session could not be refreshed silently.")
                    self.logged_in = False
                    if self.debug_mode:
                        self.logger.info(f"[{context_message}] _ensure_authenticated returning False (auth_attempt_result was False).")
                    return False
                
                # Even if authenticate_stream_api returns True, re-verify with _is_session_valid
                if self.debug_mode:
                    self.logger.info(f"[{context_message}] authenticate_stream_api (non-forced) returned True. Re-validating session...")
                final_session_check = self.spotify_api._is_session_valid(self.spotify_api.librespot_session)
                if self.debug_mode:
                    self.logger.info(f"[{context_message}] Post-auth attempt _is_session_valid check returned: {final_session_check}")
                
                if final_session_check:
                    if self.debug_mode:
                        self.logger.info(f"[{context_message}] Session is now valid. Setting logged_in=True.")
                    self.logged_in = True
                    if self.debug_mode:
                        self.logger.info(f"[{context_message}] _ensure_authenticated returning True (session confirmed valid post-auth attempt).")
                    return True
                else:
                    self.logger.warning(f"[{context_message}] Session STILL NOT VALID after authenticate_stream_api reported success. Setting logged_in=False.")
                    self.printer.oprint("Spotify authentication seemed to succeed but session remains invalid.")
                    self.logged_in = False
                    if self.debug_mode:
                        self.logger.info(f"[{context_message}] _ensure_authenticated returning False (session invalid despite auth attempt success report).")
                    return False
            except SpotifyAuthError as e:
                self.logger.error(f"[{context_message}] SpotifyAuthError caught during authenticate_stream_api (non-forced) call: {e}")
                self.printer.oprint(f"Spotify authentication failed: {e}")
                self.logged_in = False
                if self.debug_mode:
                    self.logger.info(f"[{context_message}] _ensure_authenticated returning False (SpotifyAuthError caught).")
                return False
            except Exception as e_auth_unexpected: # Catch any other unexpected errors during the auth attempt
                self.logger.error(f"[{context_message}] Unexpected exception during authenticate_stream_api (non-forced) call: {e_auth_unexpected}", exc_info=True)
                self.printer.oprint(f"An unexpected error occurred during Spotify authentication: {e_auth_unexpected}")
                self.logged_in = False
                if self.debug_mode:
                    self.logger.info(f"[{context_message}] _ensure_authenticated returning False (unexpected exception caught).")
                return False
        else:
            if self.debug_mode:
                self.logger.info(f"[{context_message}] Session was already valid. Setting logged_in=True.")
            self.logged_in = True
            if self.debug_mode:
                self.logger.info(f"[{context_message}] _ensure_authenticated returning True (session was initially valid).")
            return True

    def login(self) -> bool:
        if self.debug_mode:
            self.logger.info("Attempting Spotify login...")
        try:
            # Attempt to login using the Stream API
            if self.spotify_api.authenticate_stream_api():
                self.logged_in = True
                if self.debug_mode:
                    self.logger.info("Spotify login successful via authenticate_stream_api.")
                return True
            else:
                self.logger.warning("Spotify login attempt via authenticate_stream_api did not result in a confirmed logged-in state or did not raise an exception.")
                self.logged_in = False 
                return False

        except SpotifyNeedsUserRedirectError as e:
            self.logger.warning(f"Spotify login requires user redirect: {e.url}")
            self.printer.oprint(
                f"Spotify login requires browser authorization. Please open the following URL in your browser:\\n{e.url}\\n"
                f"After authorizing, try the operation again."
            )
            self.logged_in = False
            return False
        except SpotifyAuthError as e:
            self.logger.error(f"Spotify authentication error: {e}")
            self.printer.oprint(f"Spotify authentication failed: {e}")
            self.logged_in = False
            return False
        except SpotifyApiError as e:
            self.logger.error(f"Spotify API error during login: {e}")
            self.printer.oprint(f"Spotify API error during login: {e}")
            self.logged_in = False
            return False
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during Spotify login: {e}", exc_info=True)
            self.printer.oprint(f"An unexpected error occurred during Spotify login: {e}")
            self.logged_in = False
            return False

    def valid_account(self) -> bool:
        # Check if already logged in
        if self.logged_in and self.spotify_api.is_authenticated():
            if self.debug_mode:
                self.logger.info("Spotify session is already valid.")
            return True
        
        # If not, attempt to login
        if self.debug_mode:
            self.logger.info("Spotify session is not valid or not yet checked. Attempting login...")
        return self.login()

    def logout(self):
        """Logs the user out by clearing cached credentials."""
        if self.debug_mode:
            logging.info("Spotify module logout called.")
        try:
            self.spotify_api.clear_credentials()
            self.printer.oprint("[Spotify] Logged out successfully. Cached credentials cleared.")
        except Exception as e:
            logging.error(f"Error during Spotify logout: {e}", exc_info=True)
            self.printer.oprint(f"[Spotify Error] Failed to clear credentials during logout: {e}")

    def unload(self):
        """Perform any cleanup needed when the module is unloaded."""
        pass

    def search(self, query_type: DownloadTypeEnum, query: str, track_info: Optional[TrackInfo] = None, limit: Optional[int] = None) -> List[SearchResult]:
        self.logger.info(f"Searching for {query_type.name}: {query}{f', with limit: {limit}' if limit else ''}")
        if not self._ensure_authenticated(f"search for {query_type.name} '{query}'"):
            return []

        try:
            # Pass the limit to the spotify_api.search method            
            raw_results = self.spotify_api.search(query_type_enum_or_str=query_type, 
                                                 query_str=query, 
                                                 track_info=track_info, 
                                                 limit=limit if limit is not None else 20) # Pass limit, default if None
            
            self.logger.info(f"Raw search from spotify_api returned {len(raw_results)} results.")

            # Convert list of dicts to list of SearchResult objects            
            if not raw_results:
                return []
            
            # Before converting, let's inspect the first raw result if available
            if raw_results and isinstance(raw_results[0], dict):
                self.logger.debug(f"First raw result item (dict keys): {list(raw_results[0].keys())}")
            
            processed_results = []
            for item_dict in raw_results:
                if isinstance(item_dict, dict):
                    # Basic direct conversion for now. If SearchResult needs specific transformations
                    # (e.g. artists names as a string, album name string), those would go here.
                    try:
                        # Basic mapping for known used fields by orpheus.py main display
                        kwargs_for_sr = {
                            'name': item_dict.get('name'),
                            'result_id': item_dict.get('id'),
                            'explicit': item_dict.get('explicit', False), # Default to False if not present
                            'artists': [],  # Initialize, will be populated below based on item type
                            'image_url': None, # Initialize, will be populated below
                            'duration': None,  # Initialize, will be populated below
                            'year': None,      # Initialize, will be populated below
                            'additional': []   # Initialize, will be populated with genres below
                        }

                        # Extract artists/creator based on item type
                        item_type = item_dict.get('type', 'unknown')
                        if item_type == 'playlist':
                            # For playlists, use the owner/creator name
                            owner_data = item_dict.get('owner', {})
                            if isinstance(owner_data, dict):
                                creator_name = owner_data.get('display_name') or owner_data.get('name')
                                if creator_name:
                                    kwargs_for_sr['artists'] = [creator_name]
                        else:
                            # For tracks, albums, artists - use the artists array
                            artists_data = item_dict.get('artists', [])
                            if isinstance(artists_data, list):
                                kwargs_for_sr['artists'] = [artist.get('name') for artist in artists_data if artist.get('name')]

                        # Extract genres from different sources based on item type
                        genres = []
                        if item_type == 'track':
                            # For tracks, genres are usually in the album or artist data
                            album_data = item_dict.get('album', {})
                            if isinstance(album_data, dict) and album_data.get('genres'):
                                genres.extend(album_data['genres'])
                            # Also check artist genres if available (less common in search results)
                            artists_data = item_dict.get('artists', [])
                            for artist in artists_data:
                                if isinstance(artist, dict) and artist.get('genres'):
                                    genres.extend(artist['genres'])
                        elif item_type == 'album':
                            # For albums, check direct genres field
                            if item_dict.get('genres') and isinstance(item_dict['genres'], list):
                                genres.extend(item_dict['genres'])
                        elif item_type == 'artist':
                            # For artists, check direct genres field
                            if item_dict.get('genres') and isinstance(item_dict['genres'], list):
                                genres.extend(item_dict['genres'])
                        elif item_type == 'playlist':
                            # Playlists don't typically have genre information in search results
                            pass
                        
                        # Remove duplicates and populate additional field
                        if genres:
                            unique_genres = list(dict.fromkeys(genres))  # Preserve order while removing duplicates
                            kwargs_for_sr['additional'] = unique_genres[:3]  # Limit to first 3 genres to avoid UI clutter

                        # Extract duration from duration_ms (convert from milliseconds to seconds)
                        duration_ms = item_dict.get('duration_ms')
                        if duration_ms and isinstance(duration_ms, int):
                            kwargs_for_sr['duration'] = duration_ms // 1000  # Convert ms to seconds

                        # Extract year from album release date for tracks, or release_date for albums
                        year_value = None
                        if item_dict.get('type') == 'track' and item_dict.get('album', {}).get('release_date'):
                            release_date = item_dict['album']['release_date']
                            if release_date and len(release_date) >= 4:
                                try:
                                    year_value = release_date[:4]  # Extract year from YYYY-MM-DD format
                                except (ValueError, TypeError):
                                    pass
                        elif item_dict.get('release_date'):
                            # For albums, artists, or other items with direct release_date
                            release_date = item_dict['release_date']
                            if release_date and len(release_date) >= 4:
                                try:
                                    year_value = release_date[:4]  # Extract year from YYYY-MM-DD format
                                except (ValueError, TypeError):
                                    pass
                        
                        if year_value:
                            kwargs_for_sr['year'] = year_value

                        # Correctly extract image_url
                        current_image_url = None
                        if item_dict.get('type') == 'track' and item_dict.get('album', {}).get('images'):
                            album_images = item_dict['album']['images']
                            if album_images: # Ensure list is not empty
                                current_image_url = album_images[0]['url']
                        elif item_dict.get('images'): # For items like albums or artists that might have images directly
                            direct_images = item_dict['images']
                            if direct_images:
                                current_image_url = direct_images[0]['url']
                        
                        kwargs_for_sr['image_url'] = current_image_url

                        processed_results.append(SearchResult(**kwargs_for_sr))
                    except Exception as e_create_sr:
                        self.logger.error(f"Error creating SearchResult for item: {item_dict.get('name')}. Error: {e_create_sr}", exc_info=True)                        
                else:
                    self.logger.warning(f"Skipping non-dict item in raw_results: {type(item_dict)}")

            self.logger.info(f"Processed {len(processed_results)} SearchResult objects.")
            return processed_results
        except SpotifyAuthError:
            self.logger.error("Search failed: Not authenticated. This should have been caught by _ensure_authenticated.")
            # This case should ideally not be reached if _ensure_authenticated works correctly
            self.printer.oprint("Search failed: Spotify authentication is required. Please try logging in or re-authorizing.")
            self.logged_in = False # Ensure logged_in status is updated
            return []
        except SpotifyApiError as e:
            self.logger.error(f"API error during Spotify search: {e}", exc_info=True)
            self.printer.oprint(f"Spotify search failed due to an API issue: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error during Spotify search: {e}", exc_info=True)
            self.printer.oprint(f"An unexpected error occurred during Spotify search: {e}")
            return []

    def get_track_info(self, track_id: str, quality_tier: QualityEnum = QualityEnum.HIGH, metadata: Optional[TrackInfo] = None) -> Optional[TrackInfo]:
        operation_name = f"get track info for ID {track_id}"
        self.logger.info(f"Interface get_track_info ORIGINAL track_id param type: {type(track_id)}, value: {track_id}")

        if not self._ensure_authenticated(operation_name):
            self.printer.oprint("Spotify authentication required. Please login first.")
            return None

        # Attempt to retrieve from cache first if ID is a string and not a URL
        if isinstance(track_id, str) and not self.spotify_api.is_spotify_url(track_id) and track_id in self.metadata_cache['track']:
            self.logger.info(f"Returning cached TrackInfo for ID: {track_id}")
            return self.metadata_cache['track'][track_id]

        try:
            parsed_url_info = None
            if isinstance(track_id, str) and self.spotify_api.is_spotify_url(track_id):
                parsed_url_info = self.spotify_api.parse_spotify_url(track_id)
                if parsed_url_info and parsed_url_info.get('type') == 'track' and parsed_url_info.get('id'):
                    track_id = parsed_url_info.get('id') # Use the ID from the URL
                    self.logger.info(f"Extracted track ID {track_id} from URL.")
                else:
                    self.logger.error(f"Could not parse track ID from Spotify URL: {track_id}")
                    return None

            # Construct CodecOptions from settings if possible            
            proprietary_codecs_setting = False # Ensure default initialization
            spatial_codecs_setting = False # Ensure default initialization
            if self.settings and 'codecs' in self.settings:
                proprietary_codecs_setting = self.settings['codecs'].get('proprietary_codecs', False)
                spatial_codecs_setting = self.settings['codecs'].get('spatial_codecs', False)
            else:
                if self.debug_mode:
                    self.logger.warning("Codec settings not found in self.settings. Using default False for proprietary/spatial codecs.")
            
            current_codec_options = CodecOptions(
                proprietary_codecs=proprietary_codecs_setting,
                spatial_codecs=spatial_codecs_setting
            )
            self.logger.info(f"Constructed CodecOptions: proprietary={proprietary_codecs_setting}, spatial={spatial_codecs_setting}")
            
            # Call the spotify_api.get_track_info method which returns a TrackInfo object directly.
            self.logger.info(f"Calling self.spotify_api.get_track_info with ID: {track_id}, quality: {quality_tier.name if hasattr(quality_tier, 'name') else quality_tier}")
            
            # Ensure track_id is indeed a string before calling the API method
            if not isinstance(track_id, str):
                self.logger.error(f"Track ID must be a string for spotify_api.get_track_info, but got {type(track_id)}. Value: {track_id}")
                return None

            # Call the method in spotify_api.py that returns a TrackInfo object
            fetched_track_info_object = self.spotify_api.get_track_info(
                track_id=track_id, 
                quality_tier=quality_tier, 
                codec_options=current_codec_options
                # **extra_kwargs can be added if interface.py's get_track_info had them
            )

            if fetched_track_info_object:
                self.logger.info(f"Successfully fetched and parsed TrackInfo object for ID: {track_id} - Name: {fetched_track_info_object.name}")
                self.metadata_cache['track'][track_id] = fetched_track_info_object
                return fetched_track_info_object
            else:
                # The spotify_api.get_track_info method will have logged its own errors and DEBUG prints.
                self.logger.error(f"self.spotify_api.get_track_info returned None for ID: {track_id}. This indicates failure within the API module's method.")
                # No need for a redundant error print here unless it's specific to the interface layer.                
                return None

        except SpotifyItemNotFoundError:
            self.logger.warning(f"Track with ID '{track_id}' not found (SpotifyItemNotFoundError caught in interface.py).")
        except SpotifyAuthError as e:
            self.logger.error(f"Spotify authentication error in get_track_info: {e}")
            self.printer.oprint(f"Spotify authentication error: {e}")
        except SpotifyApiError as e: # Broader Spotify API errors
            self.logger.error(f"Spotify API error in get_track_info for '{track_id}': {e}", exc_info=True)
            self.printer.oprint(f"Spotify API error: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error in get_track_info for '{track_id}': {e}", exc_info=True)
            self.printer.oprint(f"An unexpected error occurred: {e}")

        self.logger.error(f"get_track_info in interface.py returning None at the very end for track_id: {track_id}")
        return None

    def get_album_info(self, album_id, metadata: Optional[AlbumInfo] = None) -> Optional[AlbumInfo]:
        """Fetches album information and parses it into an AlbumInfo object."""
        self.logger.info(f"Getting album info for ID: {album_id} (called from interface)")

        actual_album_id_str = None
        if isinstance(album_id, dict) and 'id' in album_id:
            actual_album_id_str = album_id['id']
            self.logger.debug(f"Extracted actual album ID '{actual_album_id_str}' from input dictionary.")
        elif isinstance(album_id, str):
            actual_album_id_str = album_id
        else:
            self.logger.error(f"Invalid album_id type received: {type(album_id)}. Expected str or dict with 'id' key.")
            return None

        if not actual_album_id_str:
            self.logger.error(f"Could not determine valid album ID string from input: {album_id}")
            return None

        try:
            if not self._ensure_authenticated(context_message=f"get album info for ID {actual_album_id_str}"):
                self.logger.error(f"Authentication failed for get_album_info with ID: {actual_album_id_str}")
                return None

            # Call the API method (which should return a dictionary)
            album_dict = self.spotify_api.get_album_info(actual_album_id_str, metadata)
            if not album_dict:
                self.logger.warning(f"Could not retrieve album dict for ID: {actual_album_id_str} from spotify_api")
                return None

            parsed_album_info = self._parse_album_info(album_dict) # Use the helper method
            if parsed_album_info:
                self.logger.info(f"Successfully parsed AlbumInfo for ID: {actual_album_id_str}, Name: {parsed_album_info.name}")
            else:
                self.logger.warning(f"Failed to parse AlbumInfo for ID: {actual_album_id_str} from dict: {album_dict}")
            return parsed_album_info

        except SpotifyItemNotFoundError:
            self.logger.warning(f"Album with ID {actual_album_id_str} not found.")
            self.printer.oprint(f"[Warning] Album {actual_album_id_str} not found.")
            print_exc()
        except SpotifyAuthError as sae:
            self.logger.error(f"Authentication error during Spotify get_album_info: {sae}")
            self.printer.oprint(f"[Error] Authentication error: {sae}")
            print_exc()
        except SpotifyApiError as sae:
            self.logger.error(f"API error during Spotify get_album_info: {sae}")
            self.printer.oprint(f"[Error] API error: {sae}")
            print_exc()
        except Exception as e:
            self.logger.error(f"Unexpected error in Spotify get_album_info for ID {actual_album_id_str}: {e}", exc_info=True)
            self.printer.oprint(f"[Error] Unexpected error: {e}")
            print_exc()
        return None

    def get_playlist_info(self, playlist_id: str, metadata: Optional[PlaylistInfo] = None) -> Optional[PlaylistInfo]:
        self.logger.info(f"Getting playlist info for ID: {playlist_id} (called from interface)")
        if not self._ensure_authenticated(f"get playlist info for ID {playlist_id}"):
            return None

        try:
            # spotify_api.get_playlist_info returns a dictionary
            playlist_dict = self.spotify_api.get_playlist_info(playlist_id, metadata)

            if not playlist_dict:
                self.logger.warning(f"Could not retrieve playlist dict for ID: {playlist_id} from spotify_api")
                return None

            self.logger.info(f"Successfully retrieved playlist dict for ID: {playlist_id} from spotify_api. Now parsing.")
            
            # Convert the dictionary to a PlaylistInfo object using the helper method            
            playlist_info_obj = self._parse_playlist_info(playlist_dict, playlist_id)
            
            if playlist_info_obj:
                self.logger.info(f"Successfully parsed PlaylistInfo for ID: {playlist_id}, Name: {playlist_info_obj.name}")
                self.metadata_cache['playlist'][playlist_id] = playlist_info_obj
            else:
                self.logger.warning(f"Failed to parse playlist dict to PlaylistInfo object for ID: {playlist_id}")
            
            return playlist_info_obj

        except SpotifyAuthError: 
            self.logger.error("get_playlist_info failed: Not authenticated.")
            self.printer.oprint("Failed to get playlist info: Spotify authentication is required.")
            self.logged_in = False
            return None
        except SpotifyItemNotFoundError:
            self.logger.warning(f"Playlist ID {playlist_id} not found on Spotify.")
            self.printer.oprint(f"Playlist ID {playlist_id} could not be found on Spotify.")
            return None
        except SpotifyApiError as e:
            self.logger.error(f"API error during Spotify get_playlist_info: {e}", exc_info=True)
            self.printer.oprint(f"Failed to get playlist info due to an API issue: {e}")
            return None
        except Exception as e: # Catches TypeErrors from PlaylistInfo instantiation or other parsing errors
            self.logger.error(f"Unexpected error during Spotify get_playlist_info (interface layer): {e}", exc_info=True)
            self.printer.oprint(f"An unexpected error occurred while getting playlist info: {e}")
            return None
        
    def get_artist_info(self, artist_id: str, metadata: Optional[ArtistInfo] = None, **kwargs) -> Optional[ArtistInfo]:
        # Ensure authentication before proceeding
        if not self._ensure_authenticated(context_message="get_artist_info"):
            return None
        
        try:
            return self.spotify_api.get_artist_info(artist_id, metadata=metadata)
        except SpotifyApiError as e:
            self.module_error(f"Failed to get artist info for {artist_id}: {e}")
            return None

    def get_track_cover(self, track_id: str, cover_options: CoverOptions, data=None) -> Optional[CoverInfo]:
        """Fetches the cover information for a given track ID."""
        if not self._ensure_authenticated(context_message="get_track_cover"):
            self.printer.oprint("Authentication required to fetch track cover.", drop_level=1)
            return None

        try:
            # Use the existing get_track_by_id method which should return metadata including the cover
            track_data = self.spotify_api.get_track_by_id(track_id)
            if not track_data:
                self.printer.oprint(f"Could not retrieve metadata for track_id: {track_id}", drop_level=1)
                return None

            # Extract cover URL from the track data
            # Based on spotify_api.py, the URL should be in track_data['album']['images'][0]['url']
            if track_data.get('album') and track_data['album'].get('images'):
                cover_url = track_data['album']['images'][0]['url']
                return CoverInfo(
                    url=cover_url,
                    # Assuming JPEG, but the API might provide this. For now, this is a safe bet.
                    file_type=ImageFileTypeEnum.jpg
                )
            else:
                self.printer.oprint(f"No cover art found for track_id: {track_id}", drop_level=1)
                return None

        except SpotifyItemNotFoundError:
            self.printer.oprint(f"Track with ID '{track_id}' not found.", drop_level=1)
            return None
        except SpotifyApiError as e:
            self.module_error(f"An API error occurred while fetching the track cover for {track_id}: {e}")
            return None
        except Exception as e:
            self.module_error(f"An unexpected error occurred in get_track_cover for {track_id}: {e}", drop_level=1)
            if self.debug_mode:
                print_exc()
            return None

    def _fetch_stream_with_retries(self, track_id_core: str) -> Optional[dict]:
        """Helper to fetch track stream info with retry logic for librespot errors."""
        stream_info = None
        max_retries = 3
        retry_delay_seconds = 10
        RATE_LIMIT_BACKOFF_SECONDS = 30

        for attempt in range(max_retries):
            try:
                stream_info = self.spotify_api.get_track_stream_info(track_id_core)
                if self.debug_mode:
                    logging.debug(f"Successfully received stream_info response for {track_id_core} on attempt {attempt + 1}")
                return stream_info
            except SpotifyTrackUnavailableError:
                raise
            except SpotifyRateLimitDetectedError as rlde:
                logging.warning(f"SpotifyRateLimitDetectedError caught directly for {track_id_core} on attempt {attempt + 1}: {rlde}. Re-raising.")
                raise
            except SpotifyLibrespotError as lspot_err:
                error_str = str(lspot_err)
                
                if "Failed fetching audio key!" in error_str:
                    if self.debug_mode:
                        logging.debug(f"Rate limit indicator (Failed fetching audio key) for track {track_id_core} on attempt {attempt + 1}. Escalating.")
                    self.printer.oprint(f"[Spotify Rate Limit] Possible rate limit detected (audio key). Waiting for {RATE_LIMIT_BACKOFF_SECONDS} seconds...")
                    time.sleep(RATE_LIMIT_BACKOFF_SECONDS)
                    raise SpotifyRateLimitDetectedError(f"Rate limit detected (audio key) for {track_id_core} after attempt {attempt + 1}") from lspot_err
                
                # Standard retry for other SpotifyLibrespotError types
                else:
                    logging.warning(f"Librespot failed for track {track_id_core} on attempt {attempt + 1}/{max_retries}: {error_str}")
                    if attempt < max_retries - 1:
                        logging.warning(f"Retrying (standard librespot error) for {track_id_core} in {retry_delay_seconds} seconds... (Attempt {attempt + 1}/{max_retries})")
                        time.sleep(retry_delay_seconds)
                    else:
                        logging.error(f"Librespot (standard error) failed permanently for track {track_id_core} after {max_retries} attempts: {error_str}")
                        return None
            except Exception as get_stream_err:                
                logging.error(f"Unexpected error calling get_track_stream_info for {track_id_core} on attempt {attempt + 1}: {get_stream_err}", exc_info=True)
                self.printer.oprint(f"[Spotify Error] Unexpected error getting stream info for track ID core {track_id_core}: {get_stream_err}")
                return None
        
        return stream_info

    def get_track_download(self, **kwargs) -> Optional[TrackDownloadInfo]:
        # Ensure authentication before proceeding
        if not self._ensure_authenticated("get_track_download"):
            self.logger.warning("Authentication failed in get_track_download, cannot proceed.")
            return None

        track_info = kwargs.get("track_info_obj")
        quality_tier = kwargs.get("quality_tier")
        # Essential arguments check for the interface layer's immediate needs
        if not track_info or not quality_tier:
            self.logger.error("ModuleInterface.get_track_download: Missing track_info_obj or quality_tier in provided kwargs.")
            return None
        try:
            return self.spotify_api.get_track_download(**kwargs)
        except SpotifyAuthError as e:
            self.printer.oprint(f"Spotify authentication error during track download: {e}")
            self.logger.error(f"SpotifyAuthError in get_track_download: {e}", exc_info=self.debug_mode)
            return None
        except SpotifyRateLimitDetectedError as e:
            self.printer.oprint(f"Spotify rate limit detected during track download: {e}")
            self.logger.warning(f"SpotifyRateLimitDetectedError in get_track_download: {e}")
            # Re-raise to be caught by music_downloader.py for deferral
            raise
        except SpotifyTrackUnavailableError as e:
            self.printer.oprint(f"Track is unavailable on Spotify: {e}")
            self.logger.warning(f"SpotifyTrackUnavailableError in get_track_download: {e}")
            return None # Or re-raise if music_downloader should handle it differently
        except SpotifyApiError as e:
            self.printer.oprint(f"Spotify API error during track download: {e}")
            self.logger.error(f"SpotifyApiError in get_track_download: {e}", exc_info=self.debug_mode)
            return None
        except Exception as e:
            self.printer.oprint(f"An unexpected error occurred during Spotify track download: {e}")
            self.logger.error(f"Unexpected exception in ModuleInterface.get_track_download: {e}", exc_info=True)
            return None

    def get_stream_url(self, track_id: str, quality: str = 'highest') -> dict | None:
        """Gets the stream URL for a track (Not Implemented)."""
        logging.warning("get_stream_url not yet implemented in Spotify module.")
        return None

    # --- URL Parsing (Handled by Orpheus Core) ---
    def parse_input(self, input_str: str) -> Tuple[DownloadTypeEnum, str] | None:
        return self.spotify_api.parse_url(input_str)
    
    def _parse_playlist_info(self, raw_playlist_data: dict, playlist_id: str) -> Optional[PlaylistInfo]:
        self.logger.debug(f"Parsing playlist: {raw_playlist_data.get('name', 'N/A')} ({playlist_id})")
        try:
            # track_gid_hex_list = raw_playlist_data.get('tracks', []) # OLD WAY
            playlist_track_items_list = []
            tracks_data_from_api = raw_playlist_data.get('tracks') # This is now {'items': [...]}
            if isinstance(tracks_data_from_api, dict) and 'items' in tracks_data_from_api:
                playlist_track_items_list = tracks_data_from_api['items']
            else:
                self.logger.warning(f"Expected raw_playlist_data['tracks']['items'] to be a list, but found {type(tracks_data_from_api)}. Playlist: {playlist_id}")

            if playlist_track_items_list:
                self.printer.oprint(f"Processing {len(playlist_track_items_list)} tracks in playlist... Please wait.") # Changed message slightly

            tracks: List[TrackInfo] = []
            # for i, gid_hex in enumerate(track_gid_hex_list): # OLD WAY
            for i, track_item_data in enumerate(playlist_track_items_list):
                # track_item_data is a playlist track object, which usually contains a 'track' field with the actual track data.
                if not isinstance(track_item_data, dict):
                    self.logger.warning(f"Skipping non-dict track item at index {i} in playlist {playlist_id}. Item: {track_item_data}")
                    continue

                actual_track_data = track_item_data.get('track')
                
                if not actual_track_data or not isinstance(actual_track_data, dict):
                    # This might be an episode, local file, or unavailable track not represented as a full track object.                    
                    track_type = actual_track_data.get('type') if isinstance(actual_track_data, dict) else 'unknown'
                    item_name = actual_track_data.get('name', 'N/A') if isinstance(actual_track_data, dict) else 'N/A'
                    self.logger.warning(f"Skipping item '{item_name}' (type: {track_type}) at index {i} in playlist {playlist_id} as it's not a standard track object or is missing.")
                    continue

                track_info = None
                try:
                    # _parse_track_info expects a dictionary of track data.                    
                    track_info = self._parse_track_info(actual_track_data, index=i)
                    if not track_info:
                         self.logger.warning(f"_parse_track_info returned None for track data: {actual_track_data.get('name', 'N/A')}")

                except Exception as e_parse:
                    self.logger.error(f"Error parsing actual track data for '{actual_track_data.get('name', 'N/A')}' in playlist {playlist_id}: {e_parse}", exc_info=True)

                if track_info:
                    tracks.append(track_info)
                else:
                    # Logged sufficiently inside the try-except block above
                    pass
            
            playlist_name = raw_playlist_data.get('name', 'Unknown Playlist')
            creator_name = raw_playlist_data.get('owner', {}).get('display_name', 'Unknown Creator') # Correctly get from owner object
            description = raw_playlist_data.get('description', None)
            cover_url = None # Initialize cover_url
            if isinstance(raw_playlist_data.get('images'), list) and raw_playlist_data['images']:
                cover_url = raw_playlist_data['images'][0].get('url') # Get from images list
            
            release_year = datetime.datetime.now().year # Default, as playlists don't have a specific release year
            # Check if a more specific year can be derived, e.g., from added_at of first track, if relevant (complex)
            is_explicit_playlist = raw_playlist_data.get('explicit', False) # Explicit is usually per-track for Spotify
            
            # num_tracks from raw_playlist_data is based on GID list, len(tracks) is based on successfully parsed TrackInfo objects
            num_tracks_from_api = raw_playlist_data.get('tracks', {}).get('total', 0) # Correctly get total from tracks object
            if len(tracks) != num_tracks_from_api:
                self.logger.warning(f"Playlist {playlist_id}: Number of tracks from API ({num_tracks_from_api}) differs from successfully parsed tracks ({len(tracks)}). Some tracks may have failed to parse or were unavailable.")

            playlist_info_obj = PlaylistInfo(
                name=playlist_name,
                creator=creator_name,
                tracks=tracks, # This is now a list of TrackInfo objects
                release_year=release_year,
                description=description,
                cover_url=cover_url,
                explicit=is_explicit_playlist,
            )
            self.logger.info(f"Successfully parsed playlist '{playlist_name}' ({playlist_id}) with {len(tracks)} tracks.")
            return playlist_info_obj

        except Exception as e:
            self.logger.error(f"Error parsing playlist info for ID {playlist_id}: {e}", exc_info=True)
            return None

    # --- Helper to parse TrackInfo ---
    def _parse_track_info(self, raw_track_data: dict, index: Optional[int] = None) -> Optional[TrackInfo]:
        track_id_for_logs = raw_track_data.get('id', 'UNKNOWN_ID_IN_PARSE') # Define early for logging
        self.logger.debug(f"Parsing track: {raw_track_data.get('name', 'N/A')} (ID: {track_id_for_logs}, index: {index})")
        try:
            # Basic track attributes
            track_name_str = raw_track_data.get('name')
            track_explicit_bool = raw_track_data.get('explicit', False)
            duration_ms = raw_track_data.get('duration_ms', 0)
            track_duration_seconds = int(duration_ms / 1000) if duration_ms else 0

            # Album related data
            raw_album_data = raw_track_data.get('album')
            album_name_str = "Unknown Album"
            album_id_str = None
            album_release_year_int = 0 # Default, TrackInfo expects int
            album_release_date_str_for_tags = None
            primary_album_artist_name_str = "Unknown Artist"
            track_cover_url_str = None

            if isinstance(raw_album_data, dict):
                album_name_str = raw_album_data.get('name', "Unknown Album")
                album_id_str = raw_album_data.get('id')
                
                album_release_date_full_str = raw_album_data.get('release_date')
                album_release_date_str_for_tags = album_release_date_full_str # For Tags object
                if album_release_date_full_str and isinstance(album_release_date_full_str, str) and len(album_release_date_full_str) >= 4:
                    try:
                        album_release_year_int = int(album_release_date_full_str[:4])
                    except ValueError:
                        self.logger.warning(f"Could not parse year from album release_date: {album_release_date_full_str}")
                
                raw_album_artists = raw_album_data.get('artists', [])
                if raw_album_artists and isinstance(raw_album_artists, list) and len(raw_album_artists) > 0:
                    if isinstance(raw_album_artists[0], dict):
                        primary_album_artist_name_str = raw_album_artists[0].get('name', "Unknown Artist")

                album_images = raw_album_data.get('images', [])
                if album_images and isinstance(album_images, list) and len(album_images) > 0:
                    if isinstance(album_images[0], dict):
                        track_cover_url_str = album_images[0].get('url')

            # Artists related data
            raw_artists_data = raw_track_data.get('artists', [])
            track_artist_names_list_str = []
            primary_track_artist_id_str = None # For TrackInfo.artist_id
            if isinstance(raw_artists_data, list):
                for i, art_data in enumerate(raw_artists_data):
                    if isinstance(art_data, dict):
                        artist_name = art_data.get('name')
                        if artist_name:
                            track_artist_names_list_str.append(artist_name)
                        if i == 0: # Assume first artist is primary
                            primary_track_artist_id_str = art_data.get('id')
                
            # Tags object
            tags_obj = Tags()
            tags_obj.track_number = raw_track_data.get('track_number')
            tags_obj.disc_number = raw_track_data.get('disc_number')
            tags_obj.album_artist = primary_album_artist_name_str
            tags_obj.release_date = album_release_date_str_for_tags # YYYY-MM-DD or YYYY            
            track_codec_enum = CodecEnum.VORBIS # Placeholder

            # Construct TrackInfo
            track_info_obj = TrackInfo(
                name=track_name_str,
                album=album_name_str,
                album_id=album_id_str,
                artists=track_artist_names_list_str,
                tags=tags_obj,
                codec=track_codec_enum,
                cover_url=track_cover_url_str,
                release_year=album_release_year_int,
                duration=track_duration_seconds,
                explicit=track_explicit_bool,
                artist_id=primary_track_artist_id_str                
            )
            
            # Get the b62 ID and GID hex from raw_track_data (from SpotifyAPI.get_track_info)
            b62_id_from_api = raw_track_data.get('id')
            gid_hex_from_api = None # Initialize
            if b62_id_from_api:
                gid_hex_from_api = self.spotify_api._convert_base62_to_gid_hex(b62_id_from_api)
            else:
                self.logger.warning(f"Cannot convert to GID hex: Base62 ID is missing in raw_track_data for {track_id_for_logs}")

            # Set the id (Base62) attribute
            if b62_id_from_api and isinstance(b62_id_from_api, str):
                setattr(track_info_obj, 'id', b62_id_from_api)
                self.logger.debug(f"Set TrackInfo.id='{b62_id_from_api}' for {track_info_obj.name if hasattr(track_info_obj, 'name') else 'N/A'}")
            else:
                self.logger.warning(f"Could not set TrackInfo.id: 'id' (b62) field missing or not a string in raw_track_data for {track_id_for_logs}")

            # Set the gid_hex attribute
            if gid_hex_from_api and isinstance(gid_hex_from_api, str):
                setattr(track_info_obj, 'gid_hex', gid_hex_from_api)
                self.logger.debug(f"Set TrackInfo.gid_hex='{gid_hex_from_api}' for {track_info_obj.name if hasattr(track_info_obj, 'name') else 'N/A'}")
            else:
                self.logger.warning(f"Could not set TrackInfo.gid_hex: 'gid_hex' field missing or not a string in raw_track_data for {track_id_for_logs}")

            # Keep spotify_gid for now if anything relies on it, but prioritize id and gid_hex
            # It should be the same as b62_id_from_api
            if b62_id_from_api and isinstance(b62_id_from_api, str):
                setattr(track_info_obj, 'spotify_gid', b62_id_from_api)
            
            # download_extra_kwargs should also use the correct fields
            current_download_extra_kwargs = getattr(track_info_obj, 'download_extra_kwargs', {})
            if not isinstance(current_download_extra_kwargs, dict):
                 current_download_extra_kwargs = {}
            current_download_extra_kwargs['track_id'] = b62_id_from_api # Ensure this uses the b62 ID
            current_download_extra_kwargs['gid_hex'] = gid_hex_from_api
            setattr(track_info_obj, 'download_extra_kwargs', current_download_extra_kwargs)

            self.logger.info(f"Parsed TrackInfo object for {track_id_for_logs}: Name='{track_info_obj.name}', ID='{getattr(track_info_obj, 'id', 'N/A')}', GID_HEX='{getattr(track_info_obj, 'gid_hex', 'N/A')}'")
            return track_info_obj
        except Exception as e:
            self.logger.error(f"Error parsing track info for ID {track_id_for_logs}: {e}", exc_info=True)
            return None

    def _parse_track_from_search(self, item_dict: dict) -> Optional[TrackInfo]:        
        pass

    def _parse_album_info(self, raw_album_data: dict) -> Optional[AlbumInfo]:
        album_id_for_logs = raw_album_data.get('id', 'UNKNOWN_ALBUM_ID_IN_PARSE')
        self.logger.debug(f"Parsing album data for: {raw_album_data.get('name', 'N/A')} (ID: {album_id_for_logs})")
        try:
            album_name = raw_album_data.get('name', "Unknown Album")
            album_id = raw_album_data.get('id') # Keep the album's own ID
            album_type = raw_album_data.get('album_type', 'album')
            total_tracks_api = raw_album_data.get('total_tracks', 0) # From API, might differ from parsed tracks
            is_explicit_album = False # Defaulting, as we only have track IDs initially from album_data['tracks']

            primary_artist_name = "Unknown Artist"
            album_artist_ids = [] # For multiple album artists if needed later
            if raw_album_data.get('artists') and isinstance(raw_album_data['artists'], list) and len(raw_album_data['artists']) > 0:
                primary_artist_name = raw_album_data['artists'][0].get('name', "Unknown Artist")
                for art_data in raw_album_data['artists']:
                    if isinstance(art_data, dict) and art_data.get('id'):
                        album_artist_ids.append(art_data.get('id'))
            
            release_year = 0
            release_date_str = raw_album_data.get('release_date')
            if release_date_str and isinstance(release_date_str, str) and len(release_date_str) >= 4:
                try: release_year = int(release_date_str[:4])
                except ValueError: self.logger.warning(f"Could not parse year from album release_date: {release_date_str}")

            cover_url = None
            if raw_album_data.get('images') and isinstance(raw_album_data['images'], list) and len(raw_album_data['images']) > 0:
                cover_url = raw_album_data['images'][0].get('url')

            parsed_tracks: List[TrackInfo] = []
            # Correctly get the list of track IDs from raw_album_data['tracks']
            track_ids_from_album_data = raw_album_data.get('tracks', [])
            if not isinstance(track_ids_from_album_data, list):
                self.logger.warning(f"Expected raw_album_data['tracks'] to be a list of IDs for album {album_name}, but got {type(track_ids_from_album_data)}. Setting to empty list.")
                track_ids_from_album_data = []
            
            self.logger.debug(f"Album '{album_name}' has {len(track_ids_from_album_data)} track IDs from API response.")

            if self.controller and hasattr(self.controller, 'settings'): # Check if controller and settings exist
                codec_opts = self.controller.settings.get_codec_options(self.name) # type: ignore
                if self.debug_mode:
                    self.logger.debug(f"_parse_album_info: Codec options for {self.name}: {codec_opts}")
            else:
                if self.debug_mode:
                    self.logger.warning("_parse_album_info: Module controller or settings not available, cannot get codec options. Defaulting to None.")

            for i, track_id_simple in enumerate(track_ids_from_album_data):
                if not isinstance(track_id_simple, str):
                    self.logger.warning(f"Skipping non-string track ID at index {i} in album {album_name}: {track_id_simple}")
                    continue
                
                if track_id_simple:
                    self.logger.debug(f"Fetching full TrackInfo for track ID {track_id_simple} from album {album_name} (index {i})")
                    full_track_info = self.get_track_info(track_id=track_id_simple, quality_tier=QualityEnum.HIGH)
                    if full_track_info:
                        parsed_tracks.append(full_track_info)
                    else:
                        self.logger.warning(f"Failed to get full TrackInfo for track ID {track_id_simple} from album {album_name}")
                else:
                    self.logger.warning(f"Skipping empty track ID in album {album_name} at index {i}.")
            
            if parsed_tracks: # After fetching all tracks, determine if album is explicit
                is_explicit_album = any(track.explicit for track in parsed_tracks if hasattr(track, 'explicit'))
                self.logger.info(f"Determined album explicit status as: {is_explicit_album} based on parsed tracks.")

            self.logger.info(f"Successfully parsed {len(parsed_tracks)} full TrackInfo objects for album '{album_name}'. API reported {total_tracks_api} tracks initially.")

            # Construct AlbumInfo object            
            album_info = AlbumInfo(
                name=album_name,
                artist=primary_artist_name, # Primary artist string
                artist_id=album_artist_ids[0] if album_artist_ids else None, # Add primary artist_id
                tracks=parsed_tracks,        # List of TrackInfo objects
                release_year=release_year,
                cover_url=cover_url,
                id=album_id,                 # Album's own Spotify ID
                explicit=is_explicit_album
                # Other fields like `album_artist_ids` can be added if AlbumInfo model supports them
            )
            self.logger.info(f"Successfully created AlbumInfo object for '{album_name}' (ID: {album_id})")
            return album_info
        except Exception as e:
            self.logger.error(f"Error parsing album data for ID {album_id_for_logs}: {e}", exc_info=True)
            return None