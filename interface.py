import datetime
import logging
import os
import shutil
import sys
import tempfile
import time
from typing import List, Optional, Tuple

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
        ModuleInformation, ModuleFlags, ManualEnum, ModuleModes,
        DownloadTypeEnum, TrackDownloadInfo, SearchResult, TrackInfo,
        AlbumInfo, PlaylistInfo, ArtistInfo, CoverInfo, Tags,
        QualityEnum, CodecOptions, CoverOptions, DownloadEnum, CodecEnum,
        MediaIdentification, ModuleController, codec_data
    )
    from utils.exceptions import ModuleGeneralError, ModuleAPIError # Corrected imports

except ImportError as e:    
    logging.warning(f"Could not import OrpheusDL core modules from utils. Error: {e}. Using dummy placeholders.")
    
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
    class ModuleFlags:
        stable = "stable_dummy"
        needs_auth = "needs_auth_dummy"
        supports_search = "supports_search_dummy"
        supports_track_download = "supports_track_download_dummy"
        supports_album_download = "supports_album_download_dummy"
        supports_playlist_download = "supports_playlist_download_dummy"
        supports_artist_download = "supports_artist_download_dummy"
        enable_jwt_system = "enable_jwt_system_dummy"
        uses_data = "uses_data_dummy"
        private = "private_dummy"
        startup_load = "startup_load_dummy"    
    class DummyContainer: name = 'tmp'
    class DummyCodecData: container = DummyContainer()
    codec_data = {CodecEnum.VORBIS: DummyCodecData(), CodecEnum.AAC: DummyCodecData(), CodecEnum.FLAC: DummyCodecData(), CodecEnum.MP3: DummyCodecData()}

# Local API wrapper import
from .spotify_api import (
    SpotifyAPI,
    SpotifyApiError,
    SpotifyAuthError,
    SpotifyConfigError,
    SpotifyNeedsUserRedirectError,
    SpotifyLibrespotNeedsRedirectError,
    SpotifyLibrespotError,
    SpotifyRateLimitDetectedError,
    SpotifyRateLimitError,
    SpotifyItemNotFoundError,
    SpotifyContentUnavailableError,
    SpotifyTrackUnavailableError,
)

# Define the module information object
module_information = ModuleInformation(
    service_name="Spotify",
    flags=[
    ],
    login_behaviour=ManualEnum.manual,
    global_settings={
        "username": "",
        "redirect_uri": "http://127.0.0.1:8888/callback",
        "client_id": "",
        "client_secret": "",
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

        logging.info(f"[Spotify Interface __init__] Received module_controller.gui_handlers: {getattr(module_controller, 'gui_handlers', 'N/A')}")

        self.metadata_cache = {
            'track': {},
            'album': {},
            'playlist': {},
            'artist': {}
        }

        # Initialize the Spotify API wrapper
        try:            
            self.session = SpotifyAPI(settings_manager=module_controller)
            logging.info("Spotify module initialized successfully.")
        except Exception as e:
            logging.error(f"Failed to initialize SpotifyAPI: {e}", exc_info=True)
            self.printer.oprint(f"[Spotify Error] Failed to initialize: {e}")
            raise self.module_error(f"Initialization failed: {e}")

    def login(self,
              username: str = None, # Not directly used by current auth flows but kept for interface compatibility
              password: str = None, # Not directly used
              client_id: str = None,
              client_secret: str = None,
              web_api_redirect_url: str = None, # For Spotipy OAuth if needed
              librespot_redirect_url: str = None # Kept for interface, though PKCE handles its own
              ) -> bool:
        """Attempts login/authentication: First Stream API (librespot), then Web API (OAuth)."""
        logging.info("Spotify module login called: Attempting Stream API first, then Web API.")

        # Update internal config from parameters if provided (e.g., from GUI)
        if client_id is not None: self.settings['client_id'] = client_id
        if client_secret is not None: self.settings['client_secret'] = client_secret
        if username is not None: self.settings['username'] = username # For PKCE/librespot username
        if password is not None: self.settings['password'] = password # For librespot user/pass fallback

        try:
            # --- 1. Attempt Stream API authentication (librespot) first --- 
            logging.info("Login Step 1: Attempting Stream API (librespot) authentication with initial setup check...")
            if not self.session.authenticate_stream_api(is_initial_setup_check=True):
                logging.error("Initial Stream API authentication failed. Login aborted.")
                self.printer.oprint("[Spotify Error] Stream API (for downloading) could not be authenticated. Please complete any browser steps if prompted, or check credentials.")
                return False
            logging.info("Login Step 1: Stream API authentication successful or user interaction completed.")

            # --- 2. Attempt Web API authentication (OAuth) --- 
            logging.info("Login Step 2: Attempting Web API (Spotipy) authentication...")
            if not self.session.authenticate_web_api(response_url=web_api_redirect_url):
                logging.error("Web API authentication failed after Stream API was successful. Login aborted.")
                self.printer.oprint("[Spotify Error] Web API (for metadata) could not be authenticated even after stream setup.")
                return False
            logging.info("Login Step 2: Web API authentication successful.")

            logging.info("Spotify login successful: Both Stream and Web APIs are authenticated.")
            return True

        except SpotifyNeedsUserRedirectError as e:
            # This exception is from authenticate_web_api()
            logging.warning(f"Spotify Web API OAuth requires user interaction: {e.auth_url}")
            self.printer.oprint("\n--- Spotify Web API Authorization Needed ---")
            self.printer.oprint("(Step 1/2) Open the following URL in your browser to grant access to Spotify's WebAPI:")
            self.printer.oprint(f"{e.auth_url}")
            self.printer.oprint("After authorizing, copy the full URL you are redirected to.")
            self.printer.oprint("Then, trigger the operation again (it will use the redirected URL).")
            self.printer.oprint("-------------------------------------------\n")
            return False

        except SpotifyLibrespotNeedsRedirectError as e:
            # This exception might be raised by authenticate_stream_api if it used a flow that raises it.
            logging.warning(f"Spotify Stream (librespot) auth requires user interaction: {e.auth_url}")
            self.printer.oprint("\n--- Spotify Stream Authorization Needed (Librespot) ---")
            self.printer.oprint(f"Please open this URL in your browser:\n{e.auth_url}")
            self.printer.oprint("Authorize the application and follow any instructions.")
            self.printer.oprint("Then, trigger the operation again.")
            self.printer.oprint("----------------------------------------------------------\n")
            return False
        
        except SpotifyAuthError as e:
            # General authentication error from either stream or web API calls
            logging.error(f"Spotify authentication failed: {e}", exc_info=True)
            self.printer.oprint(f"[Spotify Login Error] Authentication failed: {e}")
            return False

        except Exception as e:
            # Catch-all for other unexpected errors during the login process
            logging.error(f"Unexpected error during Spotify login: {e}", exc_info=True)
            self.printer.oprint(f"[Spotify Login Error] An unexpected error occurred: {e}")
            return False

    def valid_account(self) -> bool:
        """Checks if the current session/credentials are valid."""
        # Basic check: Premium required for downloads via librespot
        try:
            if self.session.web_client:
                 user_info = self.session.web_client.current_user()
                 is_premium = user_info.get('product') == 'premium'
                 if not is_premium:
                     logging.warning("Spotify account is not Premium. Downloads may fail.")
                 return is_premium
            else:
                if self.login():
                    user_info = self.session.web_client.current_user()
                    is_premium = user_info.get('product') == 'premium'
                    if not is_premium:
                        logging.warning("Spotify account is not Premium after silent login. Downloads may fail.")
                    return is_premium
                else:
                    return False
        except SpotifyAuthError as e:
             logging.warning(f"Valid account check failed due to auth error: {e}")
             return False
        except Exception as e:
             logging.error(f"Error during valid_account check: {e}", exc_info=True)
             return False

    def logout(self):
        """Logs the user out by clearing cached credentials."""
        logging.info("Spotify module logout called.")
        try:
            self.session.clear_credentials()
            self.printer.oprint("[Spotify] Logged out successfully. Cached credentials cleared.")
        except Exception as e:
            logging.error(f"Error during Spotify logout: {e}", exc_info=True)
            self.printer.oprint(f"[Spotify Error] Failed to clear credentials during logout: {e}")

    def unload(self):
        """Perform any cleanup needed when the module is unloaded."""
        pass

    def search(self, query_type: DownloadTypeEnum, query: str, limit: int = 20) -> List[SearchResult]:
        """Searches Spotify for tracks, albums, artists, or playlists."""

        search_type_str = query_type.name.lower()
        valid_search_types = ['track', 'album', 'artist', 'playlist']
        if search_type_str not in valid_search_types:
            logging.error(f"Invalid search type provided: {search_type_str}")
            self.printer.oprint(f"[Spotify Error] Invalid search type '{search_type_str}'. Valid types are: {', '.join(valid_search_types)}")
            return []

        logging.info(f"Interface: Searching for {search_type_str} with query: '{query}', desired limit: {limit}")

        parsed_results: List[SearchResult] = []
        current_offset = 0
        MAX_SPOTIFY_ITEM_LIMIT_PER_CALL = 50 # Spotify API's own max limit per page        
        MAX_API_CALL_ITERATIONS = 5 
        api_calls_made = 0

        try:
            while len(parsed_results) < limit and api_calls_made < MAX_API_CALL_ITERATIONS:
                api_calls_made += 1
                # Determine how many items to request in this API call.                
                # The `limit` param to `self.session.search` is effectively `page_size` here.
                page_size_to_request = min(limit, MAX_SPOTIFY_ITEM_LIMIT_PER_CALL) 
                
                logging.debug(f"Spotify search iteration {api_calls_made}: offset={current_offset}, requesting_page_size={page_size_to_request}")
                
                results_page = self.session.search(query, search_type=search_type_str, limit=page_size_to_request, offset=current_offset)

                if not results_page or search_type_str + 's' not in results_page or 'items' not in results_page[search_type_str + 's']:
                    logging.warning(f"No further results or unexpected format from Spotify API on iteration {api_calls_made}.")
                    break

                items_key = f"{search_type_str}s"
                items_this_page = results_page[items_key].get('items', [])

                if not items_this_page:
                    logging.info(f"Spotify API returned no items on iteration {api_calls_made} with offset {current_offset}. Assuming end of results.")
                    break

                items_processed_this_page = 0
                for item in items_this_page:
                    items_processed_this_page += 1
                    if item is None:
                        logging.info("Spotify search result item was None, skipping.")
                        continue
                    
                    if len(parsed_results) >= limit:
                        break

                    try:
                        item_id = item.get('id')
                        if not item_id: continue

                        search_result_args = {
                            'result_id': item_id,
                            'name': item.get('name'),
                            'explicit': item.get('explicit', False),
                            'extra_kwargs': {'raw_spotify_item': item} 
                        }
                        # Type-specific fields
                        if search_type_str == 'track':
                            search_result_args['artists'] = [a.get('name') for a in item.get('artists', []) if a.get('name')]
                            search_result_args['year'] = item.get('album', {}).get('release_date', '').split('-')[0]
                            search_result_args['duration'] = item.get('duration_ms', 0) // 1000
                            art_url = item.get('album', {}).get('images', [{}])[0].get('url') if item.get('album', {}).get('images') else None
                            if art_url: search_result_args['extra_kwargs']['art_url'] = art_url
                        elif search_type_str == 'album':
                            search_result_args['artists'] = [a.get('name') for a in item.get('artists', []) if a.get('name')]
                            search_result_args['year'] = item.get('release_date', '').split('-')[0]
                            art_url = item.get('images', [{}])[0].get('url') if item.get('images') else None
                            if art_url: search_result_args['extra_kwargs']['art_url'] = art_url
                        elif search_type_str == 'playlist':
                            search_result_args['artists'] = [item.get('owner', {}).get('display_name', 'N/A')]
                            art_url = item.get('images', [{}])[0].get('url') if item.get('images') else None
                            if art_url: search_result_args['extra_kwargs']['art_url'] = art_url
                        elif search_type_str == 'artist':
                            search_result_args['additional'] = item.get('genres', [])
                            art_url = item.get('images', [{}])[0].get('url') if item.get('images') else None
                            if art_url: search_result_args['extra_kwargs']['art_url'] = art_url
                        else:
                            continue
                        
                        parsed_results.append(SearchResult(**search_result_args))
                    except Exception as parse_error:
                        logging.error(f"Error parsing Spotify search result item: {item}. Error: {parse_error}", exc_info=True)
                        self.printer.oprint(f"[Spotify Warning] Could not parse one of the search results.")
                
                current_offset += items_processed_this_page
                if items_processed_this_page < page_size_to_request:
                    # If API returned fewer items than we asked for a page, assume it's the last page of results
                    logging.info(f"Spotify API returned fewer items ({items_processed_this_page}) than requested for page ({page_size_to_request}). Assuming end of relevant results.")
                    break

            if api_calls_made >= MAX_API_CALL_ITERATIONS and len(parsed_results) < limit:
                logging.warning(f"Reached max API call iterations ({MAX_API_CALL_ITERATIONS}) for Spotify search but still have only {len(parsed_results)}/{limit} results.")
            
            # Ensure we don't return more than the originally requested limit
            return parsed_results[:limit]

        except SpotifyAuthError as e:
            logging.error(f"Authentication error during Spotify search: {e}")
            self.printer.oprint(f"[Spotify Error] Authentication failed: {e}. Please login.")
            return []
        except SpotifyRateLimitError as e:
            logging.warning(f"Rate limit hit during Spotify search: {e}")
            self.printer.oprint(f"[Spotify Warning] Spotify API rate limit exceeded. Please wait and try again.")
            return []
        except SpotifyItemNotFoundError as e:
            logging.warning(f"Item not found during Spotify search (unexpected): {e}")
            self.printer.oprint(f"[Spotify Info] Search query did not find specific items: {e}")
            return []
        except ValueError as e:
             logging.error(f"Invalid search parameter: {e}")
             self.printer.oprint(f"[Spotify Error] {e}")
             raise self.module_error(f"Invalid search parameter: {e}") # Re-raise critical config errors
        except SpotifyApiError as e:
            logging.error(f"API error during Spotify search: {e}")
            self.printer.oprint(f"[Spotify Error] Search failed due to an API issue: {e}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error during Spotify search processing: {e}", exc_info=True)
            self.printer.oprint(f"[Spotify Error] An unexpected error occurred during search: {e}")
            return []

    def get_track_info(self, track_id: str, quality_tier: QualityEnum = None, codec_options: CodecOptions = None, data=None, **kwargs) -> TrackInfo | None:
        """Gets detailed information for a specific track and formats it.
        (Note: quality_tier and codec_options are accepted but not currently used in this method)
        """
        # --- Handle potentially incorrect track_id type ---
        actual_track_id = None
        if isinstance(track_id, TrackInfo):
            track_id_from_extra = track_id.download_extra_kwargs.get('track_id') if hasattr(track_id, 'download_extra_kwargs') else None
            logging.debug(f"get_track_info received a TrackInfo object. Extracted ID from extra_kwargs: {track_id_from_extra}")
            actual_track_id = track_id_from_extra
        else:
            actual_track_id = track_id

        if not actual_track_id:
             logging.error(f"get_track_info could not determine a valid track ID from input: {track_id}")
             return None

        if actual_track_id in self.metadata_cache['track']:
            logging.debug(f"Returning cached track info for ID: {actual_track_id}")
            return self.metadata_cache['track'][actual_track_id]

        logging.info(f"Interface: Getting track info for ID: {actual_track_id} (not cached)")
        try:
            raw_track_data = self.session.get_track_info(actual_track_id)

            if not raw_track_data:
                logging.warning(f"No raw track data returned from API for ID: {actual_track_id}")
                self.printer.oprint(f"[Spotify Error] Failed to fetch data for track ID: {actual_track_id}")
                return None

            logging.debug(f"Raw track data received for {actual_track_id}: {raw_track_data}")

            is_playable = raw_track_data.get('is_playable')
            logging.debug(f"Checking availability for {actual_track_id}: is_playable flag is {is_playable}")

            if is_playable is False:
                logging.warning(f"Track {actual_track_id} found but API explicitly marked is_playable=False.")
                track_name = raw_track_data.get('name', actual_track_id)
                self.printer.oprint(f"[Spotify Info] Track '{track_name}' ({actual_track_id}) is marked as not playable by Spotify.")
                return None
            else:
                logging.debug(f"Track {actual_track_id} determined to be playable based on is_playable flag ('{is_playable}').")

            # Caching raw data itself, formatting done below
            self.metadata_cache['track'][actual_track_id] = raw_track_data

            try:
                album_data = raw_track_data.get('album', {})
                album_name = album_data.get('name', 'N/A')
                album_id = album_data.get('id')

                track_artists = raw_track_data.get('artists', [])
                track_artists_list = [artist.get('name') for artist in track_artists if artist.get('name')]
                primary_artist_id = track_artists[0].get('id') if track_artists else None

                duration_ms = raw_track_data.get('duration_ms')
                duration_sec = int(duration_ms / 1000) if duration_ms else None

                track_tags = Tags(
                    album_artist=album_name,
                    composer=raw_track_data.get('composer'),
                    track_number=raw_track_data.get('track_number'),
                    total_tracks=raw_track_data.get('total_tracks'),
                    disc_number=raw_track_data.get('disc_number'),
                    total_discs=raw_track_data.get('total_discs'),
                    copyright=raw_track_data.get('copyright'),
                    isrc=raw_track_data.get('external_ids', {}).get('isrc'),
                    release_date=raw_track_data.get('album', {}).get('release_date'),
                )

                album_release_date = raw_track_data.get('album', {}).get('release_date', '')
                calculated_year = int(album_release_date.split('-')[0]) if album_release_date else None

                track_info_args = {
                    'name': raw_track_data.get('name', 'N/A'),
                    'album': album_name,
                    'album_id': album_id,
                    'artists': track_artists_list,
                    'tags': track_tags,
                    'codec': CodecEnum.VORBIS,
                    'cover_url': album_data['images'][0]['url'] if album_data.get('images') else None,
                    'release_year': calculated_year,
                    'duration': duration_sec,
                    'explicit': raw_track_data.get('explicit', False),
                    'artist_id': primary_artist_id,
                    'download_extra_kwargs': {'track_id': actual_track_id}
                }

                track_info = TrackInfo(**track_info_args)                
                self.metadata_cache['track'][actual_track_id] = track_info
                logging.debug(f"Formatted and cached track info for ID: {actual_track_id}")

                return track_info

            except Exception as track_fmt_e:
                logging.error(f"Error formatting track info for {actual_track_id}: {track_fmt_e}", exc_info=True)
                self.printer.oprint(f"[Spotify Error] An unexpected error occurred formatting track info: {track_fmt_e}")
                if actual_track_id in self.metadata_cache['track']:
                     del self.metadata_cache['track'][actual_track_id]
                return None

        except SpotifyAuthError as e:
            logging.error(f"Authentication error during Spotify get_track_info: {e}")
            self.printer.oprint(f"[Spotify Error] Authentication failed: {e}. Please login.")
            return None
        except SpotifyItemNotFoundError as e:
            logging.warning(f"Track not found: {e}")
            self.printer.oprint(f"[Spotify Info] Track with ID '{actual_track_id}' was not found.")
            return None
        except SpotifyContentUnavailableError as e:
             logging.warning(f"Track content unavailable: {e}")
             self.printer.oprint(f"[Spotify Info] Track '{actual_track_id}' is unavailable: {e}")
             return None
        except SpotifyRateLimitError as e:
            logging.warning(f"Rate limit hit during Spotify get_track_info: {e}")
            self.printer.oprint(f"[Spotify Warning] Spotify API rate limit exceeded. Please wait and try again.")
            return None
        except SpotifyApiError as e:
            logging.error(f"API error during Spotify get_track_info: {e}")
            self.printer.oprint(f"[Spotify Error] Failed to get track info due to an API issue: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error during Spotify get_track_info processing: {e}", exc_info=True)
            self.printer.oprint(f"[Spotify Error] An unexpected error occurred getting track info: {e}")
            return None

    def get_album_info(self, album_id: str, data=None, **kwargs) -> AlbumInfo | None:
        """Gets detailed information for a specific album and formats it.
        Additional **kwargs are accepted but not currently used by this Spotify implementation.
        """
        if album_id in self.metadata_cache['album']:
            logging.debug(f"Returning cached album info for ID: {album_id}")
            return self.metadata_cache['album'][album_id]

        logging.info(f"Interface: Getting album info for ID: {album_id} (not cached)")
        
        # Log if unexpected kwargs are received, for debugging purposes
        if kwargs:
            logging.debug(f"Spotify get_album_info received unexpected kwargs: {kwargs}")

        try:
            if data and isinstance(data, dict) and data.get('id') == album_id:
                raw_album_data = data
                logging.info("Using provided raw data (from 'data' parameter) for album info.")            
            else:
                 raw_album_data = self.session.get_album_info(album_id)

            if not raw_album_data:
                logging.warning(f"No album data found for ID: {album_id}")
                self.printer.oprint(f"[Spotify] Could not find album info for ID: {album_id}")
                return None

            album_artists = ', '.join([a.get('name') for a in raw_album_data.get('artists', []) if a.get('name')])
            release_date = raw_album_data.get('release_date')
            year = release_date.split('-')[0] if release_date else None
            cover_url = raw_album_data['images'][0]['url'] if raw_album_data.get('images') else None
            upc = raw_album_data.get('external_ids', {}).get('upc')

            tracks_data = raw_album_data.get('tracks', {}).get('items', [])
            # Note: Pagination for albums > 50 tracks is not handled here yet.

            album_tracks = []
            for track_item in tracks_data:
                 try:
                     track_artists_list = [a.get('name') for a in track_item.get('artists', []) if a.get('name')]
                     track_duration_ms = track_item.get('duration_ms')
                     track_duration_sec = int(track_duration_ms / 1000) if track_duration_ms else None
                     album_release_year = int(year) if year else None
                     track_cover_url = cover_url
                     track_id = track_item.get('id')

                     track_tags_for_album = Tags(
                         track_number=track_item.get('track_number'),
                         disc_number=track_item.get('disc_number'),
                     )

                     track_info_args = {
                         'name': track_item.get('name', 'N/A'),
                         'album': raw_album_data.get('name'),
                         'album_id': raw_album_data.get('id'),
                         'artists': track_artists_list,
                         'tags': track_tags_for_album,
                         'codec': CodecEnum.VORBIS,
                         'cover_url': track_cover_url,
                         'release_year': album_release_year,
                         'duration': track_duration_sec,
                         'explicit': track_item.get('explicit', False),
                         'artist_id': track_item.get('artists', [{}])[0].get('id') if track_item.get('artists') else None,
                         'download_extra_kwargs': {'track_id': track_id, 'raw_data': track_item}
                     }
                     album_tracks.append(TrackInfo(**track_info_args))
                 except Exception as track_fmt_e:
                      logging.warning(f"Failed to format album track item: {track_fmt_e}\nItem: {track_item}", exc_info=True)

            album_info_args = {
                'name': raw_album_data.get('name', 'N/A'),
                'artist': album_artists,
                'tracks': album_tracks,
                'release_year': int(year) if year else 0,
                'explicit': raw_album_data.get('explicit', False),
                'artist_id': raw_album_data.get('artists', [{}])[0].get('id'),
                'cover_url': cover_url,
                'upc': upc,
                'description': raw_album_data.get('description'),
                'track_extra_kwargs': {'raw_album_data': raw_album_data}
            }
            album_info = AlbumInfo(**album_info_args)
            
            self.metadata_cache['album'][album_id] = album_info
            logging.debug(f"Formatted and cached album info for ID: {album_id}")

            return album_info

        except SpotifyAuthError as e:
            logging.error(f"Authentication error during Spotify get_album_info: {e}")
            self.printer.oprint(f"[Spotify Error] Authentication failed: {e}. Please login.")
            return None
        except SpotifyItemNotFoundError as e:
            logging.warning(f"Album not found: {e}")
            self.printer.oprint(f"[Spotify Info] Album with ID '{album_id}' was not found.")
            return None
        except SpotifyRateLimitError as e:
            logging.warning(f"Rate limit hit during Spotify get_album_info: {e}")
            self.printer.oprint(f"[Spotify Warning] Spotify API rate limit exceeded. Please wait and try again.")
            return None
        except SpotifyApiError as e:
            logging.error(f"API error during Spotify get_album_info: {e}")
            self.printer.oprint(f"[Spotify Error] Failed to get album info due to an API issue: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error during Spotify get_album_info processing: {e}", exc_info=True)
            self.printer.oprint(f"[Spotify Error] An unexpected error occurred getting album info: {e}")
            return None

    def get_playlist_info(self, playlist_id: str, **kwargs) -> Optional[PlaylistInfo]:
        """Gets and parses information for a given Spotify playlist ID."""
        logging.info(f"Attempting to get playlist info for ID: {playlist_id}")
        if not self.session:
            logging.error("Spotify session not initialized. Cannot get playlist info.")
            return None

        cached_playlist_info = self.metadata_cache['playlist'].get(playlist_id)
        if cached_playlist_info:
            logging.info(f"Returning cached playlist info for ID: {playlist_id}")
            return cached_playlist_info

        try:
            raw_playlist_data = self.session.get_playlist_info(playlist_id)

            if not raw_playlist_data:
                logging.warning(f"No data returned from Spotify API for playlist ID: {playlist_id}")
                return None

            parsed_info = self._parse_playlist_info(raw_playlist_data)

            if parsed_info:
                self.metadata_cache['playlist'][playlist_id] = parsed_info
            return parsed_info

        except ModuleAPIError as e:
            logging.error(f"API Error getting playlist info for {playlist_id}: {e}")            
            if "Web client not available" in str(e) or "authentication" in str(e).lower():
                 gui_handler = self.module_controller.get_gui_handler('show_spotify_auth_dialog')
                 if gui_handler:
                     logging.info(f"Auth error detected during get_playlist_info (ID: {playlist_id}). GUI handler exists.")                     
                 else:
                     logging.warning("No GUI handler available for Spotify auth during get_playlist_info.")
            return None
        except Exception as e:
            logging.error(f"Unexpected error getting playlist info for {playlist_id}: {e}", exc_info=True)
            return None

    def get_artist_info(self, artist_id: str, **kwargs) -> Optional[ArtistInfo]:
        """Gets artist information from Spotify."""
        logging.info(f"Interface: Getting artist info for ID: {artist_id}. Received kwargs: {kwargs}")
        if 'get_credited_albums' in kwargs:
            logging.warning(f"'get_credited_albums' was passed to Spotify ModuleInterface.get_artist_info but is not directly used by the Spotify API call for basic artist info.")

        if artist_id in self.metadata_cache['artist']:
            logging.debug(f"Returning cached artist info for ID: {artist_id}")
            return self.metadata_cache['artist'][artist_id]
        
        raw_artist_data = self.session.get_artist_info(artist_id=artist_id)
        
        if not raw_artist_data: 
            logging.warning(f"No raw artist data received for ID: {artist_id}")
            return None
        
        parsed_info = self._parse_artist_info(raw_artist_data) 
        if parsed_info:
            self.metadata_cache['artist'][artist_id] = parsed_info
            logging.debug(f"Successfully parsed and cached artist info for ID: {artist_id}")
        else:
            logging.warning(f"Failed to parse artist info for ID: {artist_id}")
        return parsed_info

    def _parse_artist_info(self, raw_data: dict) -> ArtistInfo | None:
        if not raw_data: 
            logging.warning("_parse_artist_info: Received empty raw_data.")
            return None
        try:
            artist_name = raw_data.get('name')
            artist_id = raw_data.get('id') 
            
            if not artist_name or not artist_id:
                logging.warning(f"_parse_artist_info: Artist name or ID missing in raw_data. Name: {artist_name}, ID: {artist_id}")
                return None

            if logging.getLogger().isEnabledFor(logging.DEBUG):
                cover_url_debug = raw_data.get('images')[0]['url'] if raw_data.get('images') else None
                genres_debug = raw_data.get('genres', [])
                logging.debug(f"_parse_artist_info: Raw data for {artist_name} (ID: {artist_id}) includes cover_url: {cover_url_debug}, genres: {genres_debug}")

            album_ids_list = []
            try:
                # include_groups can be adjusted if needed, e.g., 'album,single,appears_on,compilation'                
                artist_albums_data = self.session.get_artist_albums(artist_id=artist_id, include_groups='album,single', limit=50)
                if artist_albums_data and isinstance(artist_albums_data, list):
                    for album_item in artist_albums_data:
                        if isinstance(album_item, dict) and album_item.get('id'):
                            album_ids_list.append(album_item['id'])
                    logging.info(f"_parse_artist_info: Fetched {len(album_ids_list)} album IDs for artist {artist_name} (ID: {artist_id}).")
                else:
                    logging.warning(f"_parse_artist_info: No album data or unexpected format received from get_artist_albums for artist ID: {artist_id}")
            except Exception as e_albums:
                logging.error(f"_parse_artist_info: Error fetching albums for artist ID {artist_id}: {e_albums}", exc_info=True)                

            return ArtistInfo(
                name=artist_name,
                albums=album_ids_list
            )
        except Exception as e:
            logging.error(f"Error parsing raw artist data: {e} for data: {raw_data}", exc_info=True)
            return None

    def get_track_cover(self, track_id: str, cover_options: CoverOptions, data=None) -> Optional[CoverInfo]:
        """Gets cover art information for a track. (Not Implemented)"""
        logging.warning("get_track_cover not yet implemented in Spotify module. Cover URL provided via get_track_info.")
        return None

    def _fetch_stream_with_retries(self, track_id_core: str) -> Optional[dict]:
        """Helper to fetch track stream info with retry logic for librespot errors."""
        stream_info = None
        max_retries = 3
        retry_delay_seconds = 2
        RATE_LIMIT_BACKOFF_SECONDS = 30

        for attempt in range(max_retries):
            try:
                stream_info = self.session.get_track_stream_info(track_id_core)
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

    def _save_stream_to_temp_file(self, stream_object, codec: CodecEnum) -> Optional[str]:
        """Helper to save a stream object to a temporary file, returning the file path."""
        temp_file_path = None
        try:
            project_root_from_interface = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
            target_temp_dir = os.path.join(project_root_from_interface, 'temp')
            os.makedirs(target_temp_dir, exist_ok=True)
            logging.debug(f"Target temp directory for saving stream: {target_temp_dir}")

            file_suffix = f'.{codec_data[codec].container.name}'                        
            
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_suffix, dir=target_temp_dir) as temp_file:
                temp_file_path = temp_file.name
                logging.info(f"Attempting to save stream to {temp_file_path}...")
                shutil.copyfileobj(stream_object, temp_file)
                logging.info(f"Finished writing stream via copyfileobj to {temp_file_path}.")

            file_size = os.path.getsize(temp_file_path)
            logging.info(f"Temporary file size for {temp_file_path}: {file_size} bytes.")
            if file_size == 0:
                logging.error(f"Temporary file {temp_file_path} is empty after saving!")
                if os.path.exists(temp_file_path): os.unlink(temp_file_path)
                return None
            return temp_file_path

        except Exception as save_err:
            logging.error(f"Failed during stream saving to temp file: {save_err}", exc_info=True)
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except OSError as e:
                    logging.error(f"Error removing temp file {temp_file_path} after save error: {e}")
            return None
        finally:
            if stream_object and hasattr(stream_object, 'close') and callable(stream_object.close):
                try:
                    stream_object.close()
                except Exception as close_err:
                    logging.warning(f"Error closing original stream object after saving: {close_err}")

    def get_track_download(self, **kwargs) -> TrackDownloadInfo | None:
        track_id = kwargs.get('track_id')
        quality_tier = kwargs.get('quality_tier')

        if not track_id:
            logging.error("get_track_download called without track_id in kwargs!")
            return None
        if not quality_tier:
            logging.debug("get_track_download called without quality_tier! Using default from Orpheus settings.")
            quality_tier = self.controller.orpheus_options.quality_tier

        quality_name = getattr(quality_tier, 'name', str(quality_tier))
        logging.info(f"Interface: Getting track download stream for ID: {track_id}, Quality: {quality_name}")

        try:
            # 1. Ensure Stream API is authenticated
            logging.debug(f"Checking Stream API authentication status before attempting download for {track_id}...")
            if not self.session.authenticate_stream_api():
                logging.debug(f"Stream API authentication check failed for track {track_id}.")                
            else:                
                # 2. Fetch stream info using helper method
                track_id_core = track_id.split(':')[-1]
                logging.info(f"Attempting to get stream info via helper for track_id_core: {track_id_core}")
                
                stream_info_dict = self._fetch_stream_with_retries(track_id_core)

                if not stream_info_dict or not stream_info_dict.get('stream'):
                    error_reason = stream_info_dict.get('error', 'No stream object found') if stream_info_dict else '_fetch_stream_with_retries helper failed'
                    logging.warning(f"Failed to get valid stream for track {track_id} using helper. Reason: {error_reason}")
                    return None

                # 3. Determine Codec
                codec_str = stream_info_dict.get('codec', 'ogg_vorbis').lower()
                codec = CodecEnum.VORBIS # Default
                if codec_str == 'ogg_vorbis':
                    codec = CodecEnum.VORBIS
                elif codec_str == 'aac':
                    codec = CodecEnum.AAC
                else:
                    logging.warning(f"Unknown codec '{codec_str}' reported by librespot, defaulting to VORBIS")
                
                # 4. Save stream to temp file using helper method
                stream_object_from_dict = stream_info_dict['stream']
                temp_file_path = self._save_stream_to_temp_file(stream_object_from_dict, codec)

                if not temp_file_path:
                    logging.error(f"Failed to save stream to temporary file for track {track_id}.")
                    return None

                # 5. Return TrackDownloadInfo
                download_info = TrackDownloadInfo(
                    download_type=DownloadEnum.TEMP_FILE_PATH,
                    temp_file_path=temp_file_path,
                )
                logging.info(f"Returning TEMP_FILE_PATH download info for track {track_id} using path: {temp_file_path}")
                return download_info

        except SpotifyTrackUnavailableError:
            return None
        except SpotifyRateLimitDetectedError: 
            logging.debug(f"Propagating SpotifyRateLimitDetectedError for track {track_id} from get_track_download.")
            raise 
        except Exception as e:
            logging.error(f"Unexpected error during Spotify get_track_download for {track_id}: {e}", exc_info=True)
            self.printer.oprint(f"[Spotify Error] An unexpected error occurred getting download info for {track_id}: {e}")
            return None

    def get_stream_url(self, track_id: str, quality: str = 'highest') -> dict | None:
        """Gets the stream URL for a track (Not Implemented)."""
        logging.warning("get_stream_url not yet implemented in Spotify module.")
        return None

    # --- URL Parsing (Handled by Orpheus Core) ---
    def parse_input(self, input_str: str) -> Tuple[DownloadTypeEnum, str] | None:
        """Parses a Spotify URL. Relies on Orpheus core for actual parsing via url_constants."""        
        logging.debug("parse_input called, but Orpheus Core handles parsing via url_constants.")
        return None
    
    def _parse_playlist_info(self, raw_playlist_data: dict) -> Optional[PlaylistInfo]:
        """Parses raw playlist data from Spotify API into a PlaylistInfo object."""
        if not raw_playlist_data:
            logging.warning("Cannot parse playlist info: raw_playlist_data is empty.")
            return None

        try:
            playlist_name = raw_playlist_data.get('name', 'Unknown Playlist')
            playlist_id = raw_playlist_data.get('id', 'UnknownID')
            logging.debug(f"Parsing playlist: {playlist_name} ({playlist_id})")

            creator_name = raw_playlist_data.get('owner', {}).get('display_name', 'Unknown Creator')
            description = raw_playlist_data.get('description', None)
            if description is not None and not description.strip():
                description = None

            # Get cover URL (Spotify provides a list of images, take the first/largest if available)
            cover_url = None
            images = raw_playlist_data.get('images')
            if images and isinstance(images, list) and len(images) > 0:
                largest_image_candidate = None
                max_found_height = -1

                for img_item in images:
                    if not isinstance(img_item, dict):
                        continue

                    current_height_val = img_item.get('height')
                    current_height = 0
                    if isinstance(current_height_val, int):
                        current_height = current_height_val
                    elif current_height_val is None:
                        current_height = 0                    

                    if current_height > max_found_height:
                        max_found_height = current_height
                        largest_image_candidate = img_item
                
                if largest_image_candidate:
                    cover_url = largest_image_candidate.get('url')
                elif images[0] and isinstance(images[0], dict):
                    logging.debug("Could not determine largest image by height, or all heights were 0/None. Falling back to first image.")
                    cover_url = images[0].get('url')

            track_ids = []
            items = raw_playlist_data.get('tracks', {}).get('items', [])
            for item in items:
                track = item.get('track')
                if track and isinstance(track, dict) and track.get('id'):
                    track_ids.append(track['id'])
                elif track and isinstance(track, dict) and track.get('is_local'):
                    logging.warning(f"Skipping local track in playlist {playlist_name}: {track.get('name', 'Unknown local track')}")

            # Placeholder for release_year, as playlists don't have a fixed one
            # Using current year. A more sophisticated approach might be needed if a specific behavior is desired.
            current_year = datetime.datetime.now().year

            # Explicit flag - playlists themselves aren't marked explicit by Spotify API at the playlist level.
            # This would require checking all tracks. For now, defaulting to False.
            is_explicit_playlist = False


            playlist_info_obj = PlaylistInfo(
                name=playlist_name,
                creator=creator_name,
                tracks=track_ids,
                release_year=current_year,
                description=description,
                cover_url=cover_url,
                explicit=is_explicit_playlist,
                creator_id=raw_playlist_data.get('owner', {}).get('id'),
                track_extra_kwargs={}
            )
            logging.info(f"Successfully parsed playlist '{playlist_name}' with {len(track_ids)} tracks.")
            return playlist_info_obj

        except Exception as e:
            playlist_id_for_log = raw_playlist_data.get('id', 'UNKNOWN_ID')
            logging.error(f"Error parsing playlist info for ID {playlist_id_for_log}: {e}", exc_info=True)
            return None