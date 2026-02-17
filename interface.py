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
    SpotifyConfigError,
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
        "download_pause_seconds": 30,
        "client_id": "",
        "client_secret": ""
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
        "artist": DownloadTypeEnum.artist,
        "show": DownloadTypeEnum.album,
        "episode": DownloadTypeEnum.track
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
                    # Check if credentials are missing (should have raised SpotifyConfigError, but handle edge case)
                    cfg = self.spotify_api.config or {}
                    username = (cfg.get('username') or '').strip()
                    client_id = (cfg.get('client_id') or '').strip()
                    client_secret = (cfg.get('client_secret') or '').strip()
                    missing = []
                    if not username:
                        missing.append("username")
                    if not client_id:
                        missing.append("client ID")
                    if not client_secret:
                        missing.append("client secret")
                    if missing:
                        error_msg = (
                            "Spotify credentials are missing in settings.json. "
                            f"Please fill in: {', '.join(missing)}. "
                            "Use the OrpheusDL GUI Settings tab (Spotify) or edit config/settings.json directly."
                        )
                    else:
                        # Credentials present but auth failed - likely expired tokens
                        oauth_error = None
                        if (self.spotify_api.librespot_oauth_handler and
                            hasattr(self.spotify_api.librespot_oauth_handler, 'error_message') and
                            self.spotify_api.librespot_oauth_handler.error_message):
                            oauth_error = self.spotify_api.librespot_oauth_handler.error_message
                        credentials_path = self.spotify_api.credentials_file_path
                        if oauth_error:
                            error_msg = f"Spotify authentication failed: {oauth_error}\n\n"
                        else:
                            error_msg = "Spotify authentication failed or session could not be refreshed.\nYour tokens may have expired.\n\n"
                        error_msg += f"If this problem persists, try manually deleting the credentials file:\n{credentials_path}\n"
                        error_msg += "Then run the command again to trigger a fresh authentication."
                    self.printer.oprint(error_msg)
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
            except SpotifyConfigError:
                # Re-raise so caller (e.g. search) can propagate to GUI and show credentials message
                raise
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
        query_type_str = query_type.name if hasattr(query_type, 'name') else str(query_type)
        self.logger.info(f"Searching for {query_type_str}: {query}{f', with limit: {limit}' if limit else ''}")


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
                            'preview_url': None, # Initialize, will be populated below for tracks
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
                            # For albums, show track count in additional; optionally genres
                            total_tracks = item_dict.get('total_tracks')
                            if total_tracks and total_tracks > 0:
                                kwargs_for_sr['additional'] = [f"1 track" if total_tracks == 1 else f"{total_tracks} tracks"]
                            if item_dict.get('genres') and isinstance(item_dict['genres'], list):
                                genres.extend(item_dict['genres'])
                        elif item_type == 'artist':
                            # Do not show genres in Additional for artist search (intentionally left blank)
                            pass
                        elif item_type == 'playlist':
                            # Playlist track count in additional
                            total_tracks = item_dict.get('total_tracks')
                            tracks_obj = item_dict.get('tracks', {})
                            tracks_total = None
                            if total_tracks is not None:
                                tracks_total = total_tracks
                            elif isinstance(tracks_obj, dict):
                                tracks_total = tracks_obj.get('total')
                                
                            if tracks_total is not None and tracks_total > 0:
                                kwargs_for_sr['additional'] = [f"1 track" if tracks_total == 1 else f"{tracks_total} tracks"]
                        
                        # Remove duplicates and populate additional field (for albums/playlists we already set "X tracks", don't overwrite)
                        if genres and item_type != 'playlist' and not (item_type == 'album' and kwargs_for_sr.get('additional')):
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
                            release_date = str(item_dict['release_date'])
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

                        # Extract preview_url for tracks (Spotify provides 30-second previews)
                        # Note: preview_url is deprecated in most Spotify API endpoints.
                        # The GUI uses lazy-loading to fetch previews from embed page when clicked.
                        # See: https://community.spotify.com/t5/Spotify-for-Developers/Preview-URLs-Deprecated/td-p/6791368
                        if item_dict.get('type') == 'track':
                            # Use API preview_url if available (some tracks still have it)
                            # If null, the GUI will lazy-load from embed page when user clicks
                            track_preview_url = item_dict.get('preview_url')
                            kwargs_for_sr['preview_url'] = track_preview_url
                            
                            if self.debug_mode:
                                track_name = item_dict.get('name', 'Unknown')
                                if track_preview_url:
                                    self.logger.debug(f"[Spotify Preview] Track '{track_name}' has API preview")
                                else:
                                    self.logger.debug(f"[Spotify Preview] Track '{track_name}' - no API preview, will lazy-load")

                        if item_type == 'playlist':
                            tracks_total = (item_dict.get('tracks') or {}).get('total')
                            # Relaxed check: Only skip if we are certain it has 0 tracks. 
                            # If total is None (api didn't return it), we should still show the playlist.
                            if tracks_total is not None and tracks_total == 0:
                                continue

                        processed_results.append(SearchResult(**kwargs_for_sr))
                    except Exception as e_create_sr:
                        self.logger.error(f"Error creating SearchResult for item: {item_dict.get('name')}. Error: {e_create_sr}", exc_info=True)                        
                else:
                    self.logger.warning(f"Skipping non-dict item in raw_results: {type(item_dict)}")

            # Log summary for track searches
            if processed_results and raw_results and raw_results[0].get('type') == 'track':
                tracks_with_api_preview = sum(1 for r in processed_results if getattr(r, 'preview_url', None))
                total_tracks = len(processed_results)
                if tracks_with_api_preview > 0:
                    self.logger.info(f"Processed {total_tracks} track results. API previews: {tracks_with_api_preview}/{total_tracks} (others will lazy-load)")
                else:
                    self.logger.info(f"Processed {total_tracks} track results. Previews will be lazy-loaded from embed page when clicked.")
            else:
                self.logger.info(f"Processed {len(processed_results)} SearchResult objects.")
            return processed_results
        except SpotifyRateLimitDetectedError:
            self.logger.warning("Search failed: Rate limit detected.")
            self.printer.oprint("Search failed: Spotify rate limit detected. Please try again later.")
            return []
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

    def get_track_info(self, track_id: str, quality_tier: QualityEnum, codec_options: CodecOptions, **extra_kwargs) -> Optional[TrackInfo]:
        """Fetches track information and parses it into a TrackInfo object. Also handles episode IDs via fallback."""
        self.logger.info(f"Getting track info for ID: {track_id} (called from interface)")
        
        try:
            # First, attempt to get track info from spotify_api
            track_info_result = self.spotify_api.get_track_info(track_id, quality_tier, codec_options, **extra_kwargs)
            if track_info_result:
                self.logger.info(f"Successfully retrieved TrackInfo for track ID: {track_id}, Name: {track_info_result.name}")
                return track_info_result
            
            # If track_info_result is None, try episode fallback
            self.logger.info(f"Track info returned None for {track_id}, trying as episode...")
            episode_info_result = self.spotify_api.get_episode_info(track_id, quality_tier, codec_options, **extra_kwargs)
            if episode_info_result:
                self.logger.info(f"Successfully fetched episode as TrackInfo object for ID: {track_id}")
                return episode_info_result
            
            # If both failed, return None
            self.logger.warning(f"Failed to get track or episode info for ID: {track_id}")
            return None
            
        except SpotifyConfigError:
            raise
        except SpotifyItemNotFoundError:
            self.logger.warning(f"Track/Episode ID {track_id} not found")
            return None
        except Exception as e:
            self.logger.error(f"Error getting track/episode info for {track_id}: {e}")
            return None

    def get_album_info(self, album_id, metadata: Optional[AlbumInfo] = None) -> Optional[AlbumInfo]:
        """Fetches album information and parses it into an AlbumInfo object. Also handles show IDs."""
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


            # First try to get as album
            try:
                album_dict = self.spotify_api.get_album_info(actual_album_id_str, metadata)
                if album_dict:
                    parsed_album_info = self._parse_album_info(album_dict)
                    if parsed_album_info:
                        self.logger.info(f"Successfully parsed AlbumInfo for ID: {actual_album_id_str}, Name: {parsed_album_info.name}")
                    else:
                        self.logger.warning(f"Failed to parse AlbumInfo for ID: {actual_album_id_str} from dict: {album_dict}")
                    return parsed_album_info
                else:
                    pass
            except SpotifyItemNotFoundError:
                # If album not found, try as show
                self.logger.info(f"Album {actual_album_id_str} not found, trying as show...")
                try:
                    show_dict = self.spotify_api.get_show_info(actual_album_id_str, metadata)
                    if show_dict:
                        # Parse show as album-like object
                        parsed_album_info = self._parse_album_info(show_dict)
                        if parsed_album_info:
                            self.logger.info(f"Successfully parsed show as AlbumInfo for ID: {actual_album_id_str}, Name: {parsed_album_info.name}")
                        else:
                            self.logger.warning(f"Failed to parse show as AlbumInfo for ID: {actual_album_id_str} from dict: {show_dict}")
                        return parsed_album_info
                    else:
                        pass
                except SpotifyItemNotFoundError:
                    self.logger.warning(f"Neither album nor show found for ID {actual_album_id_str}")
                    self.printer.oprint(f"[Warning] Album/Show {actual_album_id_str} not found.")
                    return None
                except Exception as show_error:
                    self.logger.error(f"Error processing show {actual_album_id_str}: {show_error}")
                    return None
            except SpotifyRateLimitDetectedError:
                # Rate limit must propagate to GUI for popup, never swallow
                raise
            except Exception as album_error:
                # If album processing fails, try show as fallback
                try:
                    show_dict = self.spotify_api.get_show_info(actual_album_id_str, metadata)
                    if show_dict:
                        parsed_album_info = self._parse_album_info(show_dict)
                        return parsed_album_info
                    else:
                        pass
                except Exception as fallback_error:
                    pass
                self.logger.error(f"Both album and show processing failed for {actual_album_id_str}")
                return None

        except SpotifyConfigError:
            raise
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

        except SpotifyConfigError:
            raise
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


        try:
            return self.spotify_api.get_artist_info(artist_id, metadata=metadata)
        except SpotifyConfigError:
            raise
        except SpotifyRateLimitDetectedError:
            # Rate limit must propagate to GUI for popup, never swallow
            raise
        except SpotifyApiError as e:
            self.module_error(f"Failed to get artist info for {artist_id}: {e}")
            return None

    def get_track_cover(self, track_id: str, cover_options: CoverOptions, data=None) -> Optional[CoverInfo]:
        """Fetches the cover information for a given track ID."""
        try:
             # Use Embed Client directly for cover Art (no auth required)
             metadata = self.spotify_api.embed_client.get_track_metadata(track_id)
             track = metadata.get('trackUnion') if metadata else None
             
             cover_url = None
             if track:
                 cover_sources = track.get('albumOfTrack', {}).get('coverArt', {}).get('sources', [])
                 if cover_sources:
                     cover_url = cover_sources[0].get('url')
             
             if cover_url:
                 return CoverInfo(
                     url=cover_url, 
                     file_type=ImageFileTypeEnum.jpg
                 )
             
             self.printer.oprint(f"No cover art found for track_id: {track_id}", drop_level=1)
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

    def get_track_download(self, track_id: str = None, quality_tier: QualityEnum = None, **kwargs) -> Optional[TrackDownloadInfo]:
        # Ensure authentication before proceeding
        if not self._ensure_authenticated("get_track_download"):
            self.logger.warning("Authentication failed in get_track_download, cannot proceed.")
            return None

        # Handle both positional arguments (standard) and kwargs (legacy)
        if track_id is None:
            track_id = kwargs.get("track_id")
        if quality_tier is None:
            quality_tier = kwargs.get("quality_tier")
            
        track_info = kwargs.get("track_info_obj")
        
        # Essential arguments check for the interface layer's immediate needs
        if not track_id or not quality_tier:
            self.logger.error("ModuleInterface.get_track_download: Missing track_id or quality_tier.")
            return None
        
        # Check if this is known to be an episode from download_extra_kwargs
        is_episode = False
        if track_info and hasattr(track_info, 'download_extra_kwargs'):
            download_kwargs = track_info.download_extra_kwargs
            if isinstance(download_kwargs, dict):
                is_episode = download_kwargs.get('is_episode', False)
        
        try:
            # Pass track_id and quality_tier along with other kwargs
            kwargs['track_id'] = track_id
            kwargs['quality_tier'] = quality_tier
            
            # If we know it's an episode, try episode download first
            if is_episode:
                self.logger.info(f"Detected episode from TrackInfo, using episode download for {track_id}")
                try:
                    return self.spotify_api.get_episode_download(**kwargs)
                except Exception as episode_error:
                    self.logger.warning(f"Episode download failed for {track_id}, trying as track: {episode_error}")
                    # Fall through to try track download as fallback
            
            # First try as a regular track
            try:
                return self.spotify_api.get_track_download(**kwargs)
            except SpotifyTrackUnavailableError as track_error:
                # If track download fails, try as episode
                self.logger.info(f"Track download failed for {track_id}, trying as episode: {track_error}")
                try:
                    return self.spotify_api.get_episode_download(**kwargs)
                except Exception as episode_error:
                    self.logger.warning(f"Episode download also failed for {track_id}: {episode_error}")
                    # Re-raise the original track error since that was the first attempt
                    raise track_error
            except SpotifyApiError as api_error:
                # Check if this is a 404 error from Extended Metadata (likely an episode)
                error_str = str(api_error).lower()
                error_repr = repr(api_error).lower()
                # Check for various 404 error patterns - check both str() and repr() to catch all cases
                is_404_error = (
                    "status code 404" in error_str or 
                    "extended metadata request failed" in error_str or
                    "status code 404" in error_repr or
                    "extended metadata request failed" in error_repr or
                    ("404" in error_str and ("metadata" in error_str or "extended" in error_str))
                )
                
                if is_404_error:
                    self.logger.info(f"Track download returned 404 for {track_id}, trying as episode. Original error: {api_error}")
                    self.logger.debug(f"Error string: {error_str}, Error repr: {error_repr}")
                    try:
                        episode_result = self.spotify_api.get_episode_download(**kwargs)
                        self.logger.info(f"Successfully downloaded as episode for {track_id}")
                        return episode_result
                    except Exception as episode_error:
                        self.logger.warning(f"Episode download also failed for {track_id}: {episode_error}")
                        # Re-raise the original API error
                        raise api_error
                else:
                    # For other API errors, don't try episode download
                    self.logger.debug(f"SpotifyApiError for {track_id} is not a 404, not trying episode fallback. Error: {api_error}")
                    raise api_error
            except Exception as other_error:
                # For other errors (like auth errors), don't try episode download
                raise other_error
                
        except SpotifyRateLimitDetectedError as e:
            # Don't print the full technical error message to the user - it will be handled by music_downloader.py
            # self.printer.oprint(f"Spotify rate limit detected during track download: {e}", drop_level=0)
            self.logger.warning(f"SpotifyRateLimitDetectedError in get_track_download: {e}")
            # Re-raise to be caught by music_downloader.py for deferral
            raise
        except SpotifyTrackUnavailableError as e:
            self.printer.oprint(f"Track/Episode is unavailable on Spotify: {e}", drop_level=0)
            self.logger.warning(f"SpotifyTrackUnavailableError in get_track_download: {e}")
            return None # Or re-raise if music_downloader should handle it differently
        except SpotifyAuthError as e:
            self.printer.oprint(f"Spotify authentication error during track download: {e}", drop_level=0)
            self.logger.error(f"SpotifyAuthError in get_track_download: {e}", exc_info=self.debug_mode)
            return None
        except SpotifyApiError as e:
            self.printer.oprint(f"Spotify API error during track download: {e}", drop_level=0)
            self.logger.error(f"SpotifyApiError in get_track_download: {e}", exc_info=self.debug_mode)
            return None
        except Exception as e:
            self.printer.oprint(f"An unexpected error occurred during Spotify track download: {e}", drop_level=0)
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

                # Check if this is an episode instead of a track
                item_type = actual_track_data.get('type', 'track')
                track_info = None
                
                try:
                    if item_type == 'episode':
                        # Handle episode: get episode info using get_episode_info
                        episode_id = actual_track_data.get('id')
                        if not episode_id:
                            self.logger.warning(f"Episode at index {i} in playlist {playlist_id} has no ID. Skipping.")
                            continue
                        
                        # Get codec options and quality tier for episode info
                        if self.controller and hasattr(self.controller, 'settings'):
                            codec_opts = self.controller.settings.get_codec_options(self.name)
                        else:
                            codec_opts = None
                        
                        self.logger.info(f"Processing episode '{actual_track_data.get('name', 'N/A')}' (ID: {episode_id}) in playlist {playlist_id}")
                        track_info = self.get_track_info(episode_id, quality_tier=QualityEnum.HIGH, codec_options=codec_opts)
                        if not track_info:
                            self.logger.warning(f"get_track_info (episode fallback) returned None for episode ID: {episode_id}")
                        elif track_info:
                            # Mark this TrackInfo as an episode so we know to use episode download
                            download_kwargs = getattr(track_info, 'download_extra_kwargs', {})
                            if not isinstance(download_kwargs, dict):
                                download_kwargs = {}
                            download_kwargs['is_episode'] = True
                            setattr(track_info, 'download_extra_kwargs', download_kwargs)
                    else:
                        # Handle regular track: use _parse_track_info
                        track_info = self._parse_track_info(actual_track_data, index=i)
                        if not track_info:
                            self.logger.warning(f"_parse_track_info returned None for track data: {actual_track_data.get('name', 'N/A')}")

                except Exception as e_parse:
                    item_name = actual_track_data.get('name', 'N/A')
                    self.logger.error(f"Error parsing {'episode' if item_type == 'episode' else 'track'} data for '{item_name}' in playlist {playlist_id}: {e_parse}", exc_info=True)

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

    def _parse_album_info(self, album_dict: dict) -> Optional[AlbumInfo]:
        """Parse album dictionary into AlbumInfo object. Now supports show data too."""
        if not album_dict:
            return None

        album_id_for_logs = album_dict.get('id', 'UNKNOWN_ALBUM_ID_IN_PARSE')
        self.logger.debug(f"Parsing album data for: {album_dict.get('name', 'N/A')} (ID: {album_id_for_logs})")
        try:
            album_name = album_dict.get('name', "Unknown Album")
            album_id = album_dict.get('id') # Keep the album's own ID
            album_type = album_dict.get('album_type', 'album')
            total_tracks_api = album_dict.get('total_tracks', 0) # From API, might differ from parsed tracks
            is_explicit_album = False # Defaulting, as we only have track IDs initially from album_data['tracks']

            primary_artist_name = "Unknown Artist"
            album_artist_ids = [] # For multiple album artists if needed later
            if album_dict.get('artists') and isinstance(album_dict['artists'], list) and len(album_dict['artists']) > 0:
                primary_artist_name = album_dict['artists'][0].get('name', "Unknown Artist")
                for art_data in album_dict['artists']:
                    if isinstance(art_data, dict) and art_data.get('id'):
                        album_artist_ids.append(art_data.get('id'))
            
            # Handle show data that doesn't have artists field
            if 'publisher' in album_dict and not album_dict.get('artists'):
                primary_artist_name = album_dict.get('publisher', 'Unknown Publisher')
            
            release_year = 0
            release_date_str = album_dict.get('release_date')
            if release_date_str and isinstance(release_date_str, str) and len(release_date_str) >= 4:
                try: release_year = int(release_date_str[:4])
                except ValueError: self.logger.warning(f"Could not parse year from album release_date: {release_date_str}")

            cover_url = None
            if album_dict.get('images') and isinstance(album_dict['images'], list) and len(album_dict['images']) > 0:
                cover_url = album_dict['images'][0].get('url')

            parsed_tracks: List[TrackInfo] = []
            # Use full track items from API when available to avoid N get_track_info API calls (same pattern as Apple Music)
            track_items_from_api = None
            track_ids_from_album_data = album_dict.get('tracks', [])

            if isinstance(track_ids_from_album_data, dict) and 'items' in track_ids_from_album_data:
                track_items_from_api = track_ids_from_album_data.get('items', [])
                self.logger.debug(f"Album '{album_name}' has {len(track_items_from_api)} full track items from API (no extra get_track_info calls).")
            elif isinstance(track_ids_from_album_data, list):
                self.logger.debug(f"Album '{album_name}' has {len(track_ids_from_album_data)} track IDs from API response.")
            else:
                track_ids_from_album_data = []

            if self.controller and hasattr(self.controller, 'settings'):
                codec_opts = self.controller.settings.get_codec_options(self.name)  # type: ignore
                if self.debug_mode:
                    self.logger.debug(f"_parse_album_info: Codec options for {self.name}: {codec_opts}")
            else:
                codec_opts = None
                if self.debug_mode:
                    self.logger.warning("_parse_album_info: Module controller or settings not available, cannot get codec options. Defaulting to None.")

            if track_items_from_api:
                for i, item in enumerate(track_items_from_api):
                    if not item or not isinstance(item, dict):
                        continue
                    try:
                        track_info = self._parse_track_info(item, index=i + 1)
                        if track_info:
                            parsed_tracks.append(track_info)
                        else:
                            self.logger.warning(f"Failed to parse track at index {i + 1} in album {album_name}")
                    except Exception as parse_err:
                        self.logger.error(f"Error parsing track in album {album_name}: {parse_err}")
            else:
                for track_id in track_ids_from_album_data:
                    if not track_id:
                        continue
                    try:
                        track_info = self.get_track_info(track_id, quality_tier=QualityEnum.HIGH, codec_options=codec_opts)
                        if track_info:
                            parsed_tracks.append(track_info)
                        else:
                            self.logger.warning(f"Failed to get track info for track ID {track_id} in album {album_name}")
                    except Exception as track_error:
                        self.logger.error(f"Error getting track info for track ID {track_id} in album {album_name}: {track_error}")
            
            if parsed_tracks: # After fetching all tracks, determine if album is explicit
                is_explicit_album = any(track.explicit for track in parsed_tracks if hasattr(track, 'explicit'))
                self.logger.info(f"Determined album explicit status as: {is_explicit_album} based on parsed tracks.")

            self.logger.info(f"Successfully parsed {len(parsed_tracks)} full TrackInfo objects for album '{album_name}'. API reported {total_tracks_api} tracks initially.")

            total_duration_s = sum(track.duration for track in parsed_tracks if track.duration) if parsed_tracks else 0
            self.logger.info(f"Album parsing successful for: {album_name} (ID: {album_id}), Artist: {primary_artist_name}, Release Year: {release_year}, Tracks: {len(parsed_tracks)}")
            
            return AlbumInfo(
                name=album_name,
                artist=primary_artist_name,
                artist_id=album_artist_ids[0] if album_artist_ids else None,
                tracks=parsed_tracks,
                all_track_cover_jpg_url=cover_url,
                release_year=release_year,
                explicit=is_explicit_album,
                duration=total_duration_s,
                track_extra_kwargs=codec_opts if codec_opts is not None else {},
                id=album_id
            )
        except Exception as parse_error:
            self.logger.error(f"Failed to parse album data for ID {album_id_for_logs}: {parse_error}")
            return None