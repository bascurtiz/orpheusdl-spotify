"""
Spotify Embed API Client - Fetches metadata without OAuth credentials.

This module provides an alternative to the OAuth-based Web API by using
Spotify's internal GraphQL API accessed through embed pages. This allows
metadata operations (search, browse) without requiring user credentials.

Based on the approach used by SpotiFLAC:
https://github.com/afkarxyz/SpotiFLAC/blob/main/backend/spotify_metadata.go
"""

import json
import logging
import re
import time
from typing import Optional, Dict, List, Any
import requests


# GraphQL endpoint for Spotify's internal API
GRAPHQL_ENDPOINT = "https://api-partner.spotify.com/pathfinder/v1/query"

# Persisted query hashes for different operations
# These are stable hashes used by Spotify's web client
PERSISTED_QUERIES = {
    "getTrack": "612585ae06ba435ad26369870deaae23b5c8800a256cd8a57e08eddc25a37294",
    "getAlbum": "b9bfabef66ed756e5e13f68a942deb60bd4125ec1f1be8cc42769dc0259b4b10",
    "fetchPlaylist": "bb67e0af06e8d6f52b531f97468ee4acd44cd0f82b988e15c2ea47b1148efc77",
    "queryArtistOverview": "446130b4a0aa6522a686aafccddb0ae849165b5e0436fd802f96e0243617b5d8",
    "queryArtistDiscographyAll": "5e07d323febb57b4a56a42abbf781490e58764aa45feb6e3dc0591564fc56599",
    "searchDesktop": "fcad5a3e0d5af727fb76966f06971c19cfa2275e6ff7671196753e008611873c",
}

DEFAULT_REQUEST_TIMEOUT = 30  # seconds


class SpotifyEmbedError(Exception):
    """Base exception for Spotify Embed API errors."""
    pass


class SpotifyEmbedAuthError(SpotifyEmbedError):
    """Exception for authentication/token errors."""
    pass


class SpotifyEmbedClient:
    """Client for fetching Spotify metadata via embed pages and GraphQL API."""
    
    def __init__(self, logger_instance: Optional[logging.Logger] = None):
        """
        Initialize the Spotify Embed Client.
        
        Args:
            logger_instance: Optional logger instance. If not provided, creates a new one.
        """
        self.logger = logger_instance if logger_instance else logging.getLogger(__name__)
        self.access_token: Optional[str] = None
        self.token_expires_at: float = 0
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Origin': 'https://open.spotify.com',
            'Referer': 'https://open.spotify.com/',
        })
    
    def get_anonymous_token(self, force_refresh: bool = False) -> str:
        """
        Get an anonymous access token from Spotify's embed page.
        
        This token can be used for metadata queries without OAuth authentication.
        The token is cached and reused until it expires.
        
        Args:
            force_refresh: If True, forces fetching a new token even if cached one is valid.
            
        Returns:
            Access token string.
            
        Raises:
            SpotifyEmbedAuthError: If token extraction fails.
        """
        # Check if we have a valid cached token
        if not force_refresh and self.access_token and time.time() < self.token_expires_at:
            self.logger.debug("Using cached anonymous access token")
            return self.access_token
        
        self.logger.info("Fetching new anonymous access token from embed page")
        
        try:
            # Fetch a sample embed page to extract the token
            # Using a well-known track ID (Blinding Lights by The Weeknd)
            embed_url = "https://open.spotify.com/embed/track/0VjIjW4GlUZAMYd2vXMi3b"
            
            response = self.session.get(embed_url, timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            
            html_content = response.text
            
            # Try multiple patterns to extract the access token
            # Pattern 1: Look for accessToken in embedded JSON
            token_pattern_1 = r'"accessToken":"([^"]+)"'
            match = re.search(token_pattern_1, html_content)
            
            if match:
                self.access_token = match.group(1)
                self.logger.info(f"Successfully extracted access token (pattern 1): {self.access_token[:20]}...")
            else:
                # Pattern 2: Look for token in script tags
                token_pattern_2 = r'accessToken["\']?\s*:\s*["\']([^"\']+)["\']'
                match = re.search(token_pattern_2, html_content)
                
                if match:
                    self.access_token = match.group(1)
                    self.logger.info(f"Successfully extracted access token (pattern 2): {self.access_token[:20]}...")
                else:
                    # Pattern 3: Look for any JWT-like token in the page
                    token_pattern_3 = r'([A-Za-z0-9_-]{100,}\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'
                    match = re.search(token_pattern_3, html_content)
                    
                    if match:
                        self.access_token = match.group(1)
                        self.logger.info(f"Successfully extracted access token (pattern 3): {self.access_token[:20]}...")
                    else:
                        self.logger.error("Failed to extract access token from embed page")
                        # Log a snippet of the HTML for debugging
                        self.logger.debug(f"HTML snippet: {html_content[:500]}")
                        raise SpotifyEmbedAuthError("Could not extract access token from embed page")
            
            # Set expiration time (tokens typically last 1 hour, we'll refresh after 50 minutes)
            self.token_expires_at = time.time() + (50 * 60)
            
            return self.access_token
            
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch embed page: {e}")
            raise SpotifyEmbedAuthError(f"Failed to fetch embed page: {e}")
    
    def _graphql_query(self, operation_name: str, variables: Dict[str, Any], 
                       retry_on_auth_error: bool = True) -> Dict[str, Any]:
        """
        Execute a GraphQL query against Spotify's internal API.
        
        Args:
            operation_name: Name of the GraphQL operation (e.g., "getTrack").
            variables: Variables to pass to the query.
            retry_on_auth_error: If True, retries once with a fresh token on auth errors.
            
        Returns:
            Parsed JSON response from the API.
            
        Raises:
            SpotifyEmbedError: If the query fails.
        """
        # Ensure we have a valid token
        token = self.get_anonymous_token()
        
        # Get the persisted query hash
        query_hash = PERSISTED_QUERIES.get(operation_name)
        if not query_hash:
            raise SpotifyEmbedError(f"Unknown operation name: {operation_name}")
        
        # Build the GraphQL request payload
        payload = {
            "variables": variables,
            "operationName": operation_name,
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": query_hash
                }
            }
        }
        
        # Set authorization header
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        
        try:
            self.logger.debug(f"Executing GraphQL query: {operation_name} with variables: {variables}")
            
            response = self.session.post(
                GRAPHQL_ENDPOINT,
                json=payload,
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            
            # Check for auth errors
            if response.status_code == 401 and retry_on_auth_error:
                self.logger.warning("GraphQL query returned 401, refreshing token and retrying")
                # Force refresh token and retry once
                self.get_anonymous_token(force_refresh=True)
                return self._graphql_query(operation_name, variables, retry_on_auth_error=False)
            
            response.raise_for_status()
            
            data = response.json()
            
            # Check for GraphQL errors
            if "errors" in data:
                error_messages = [err.get("message", str(err)) for err in data["errors"]]
                self.logger.error(f"GraphQL query returned errors: {error_messages}")
                raise SpotifyEmbedError(f"GraphQL errors: {', '.join(error_messages)}")
            
            return data
            
        except requests.RequestException as e:
            self.logger.error(f"GraphQL query failed: {e}")
            raise SpotifyEmbedError(f"GraphQL query failed: {e}")
    
    def get_track_metadata(self, track_id: str) -> Dict[str, Any]:
        """
        Fetch metadata for a single track.
        
        Args:
            track_id: Spotify track ID (base62 format).
            
        Returns:
            Dictionary containing track metadata.
        """
        self.logger.info(f"Fetching track metadata for ID: {track_id}")
        
        variables = {
            "uri": f"spotify:track:{track_id}"
        }
        
        response = self._graphql_query("getTrack", variables)
        
        # Extract track data from response
        if "data" not in response:
            raise SpotifyEmbedError("Invalid response: missing 'data' field")
        
        return response["data"]
    
    def get_album_metadata(self, album_id: str) -> Dict[str, Any]:
        """
        Fetch metadata for an album, including all tracks.
        
        Handles pagination automatically to fetch all tracks.
        
        Args:
            album_id: Spotify album ID (base62 format).
            
        Returns:
            Dictionary containing album metadata with all tracks.
        """
        self.logger.info(f"Fetching album metadata for ID: {album_id}")
        
        all_items = []
        offset = 0
        limit = 1000  # Spotify's max per request
        
        # First request to get album info and first batch of tracks
        variables = {
            "uri": f"spotify:album:{album_id}",
            "locale": "",
            "offset": offset,
            "limit": limit
        }
        
        response = self._graphql_query("getAlbum", variables)
        
        if "data" not in response or "albumUnion" not in response["data"]:
            raise SpotifyEmbedError("Invalid album response structure")
        
        album_data = response["data"]["albumUnion"]
        
        # Get tracks from first response
        if "tracksV2" in album_data and "items" in album_data["tracksV2"]:
            items = album_data["tracksV2"]["items"]
            all_items.extend(items)
            total_count = album_data["tracksV2"].get("totalCount", len(items))
            
            # Paginate if there are more tracks
            while len(all_items) < total_count and len(items) == limit:
                offset += limit
                self.logger.debug(f"Fetching next page of album tracks (offset: {offset})")
                
                variables["offset"] = offset
                page_response = self._graphql_query("getAlbum", variables)
                
                page_items = page_response.get("data", {}).get("albumUnion", {}).get("tracksV2", {}).get("items", [])
                if not page_items:
                    break
                
                all_items.extend(page_items)
                items = page_items
            
            # Update the album data with all tracks
            album_data["tracksV2"]["items"] = all_items
            album_data["tracksV2"]["totalCount"] = len(all_items)
        
        return response["data"]
    
    def get_playlist_metadata(self, playlist_id: str) -> Dict[str, Any]:
        """
        Fetch metadata for a playlist, including all tracks.
        
        Handles pagination automatically to fetch all tracks.
        
        Args:
            playlist_id: Spotify playlist ID (base62 format).
            
        Returns:
            Dictionary containing playlist metadata with all tracks.
        """
        self.logger.info(f"Fetching playlist metadata for ID: {playlist_id}")
        
        all_items = []
        offset = 0
        limit = 1000
        
        variables = {
            "uri": f"spotify:playlist:{playlist_id}",
            "offset": offset,
            "limit": limit,
            "enableWatchFeedEntrypoint": False
        }
        
        response = self._graphql_query("fetchPlaylist", variables)
        
        if "data" not in response or "playlistV2" not in response["data"]:
            raise SpotifyEmbedError("Invalid playlist response structure")
        
        playlist_data = response["data"]["playlistV2"]
        
        # Get tracks from first response
        if "content" in playlist_data and "items" in playlist_data["content"]:
            items = playlist_data["content"]["items"]
            all_items.extend(items)
            total_count = playlist_data["content"].get("totalCount", len(items))
            
            # Paginate if there are more tracks
            while len(all_items) < total_count and len(items) == limit:
                offset += limit
                self.logger.debug(f"Fetching next page of playlist tracks (offset: {offset})")
                
                variables["offset"] = offset
                page_response = self._graphql_query("fetchPlaylist", variables)
                
                page_items = page_response.get("data", {}).get("playlistV2", {}).get("content", {}).get("items", [])
                if not page_items:
                    break
                
                all_items.extend(page_items)
                items = page_items
            
            # Update the playlist data with all tracks
            playlist_data["content"]["items"] = all_items
            playlist_data["content"]["totalCount"] = len(all_items)
        
        return response["data"]
    
    def get_artist_metadata(self, artist_id: str) -> Dict[str, Any]:
        """
        Fetch metadata for an artist, including overview and discography.
        
        Args:
            artist_id: Spotify artist ID (base62 format).
            
        Returns:
            Dictionary containing artist metadata and discography.
        """
        self.logger.info(f"Fetching artist metadata for ID: {artist_id}")
        
        # First, get artist overview
        overview_variables = {
            "uri": f"spotify:artist:{artist_id}",
            "locale": ""
        }
        
        overview_response = self._graphql_query("queryArtistOverview", overview_variables)
        
        if "data" not in overview_response or "artistUnion" not in overview_response["data"]:
            raise SpotifyEmbedError("Invalid artist response structure")
        
        artist_data = overview_response["data"]["artistUnion"]
        
        # Then, fetch discography with pagination
        all_discography_items = []
        offset = 0
        limit = 50
        
        while True:
            discography_variables = {
                "uri": f"spotify:artist:{artist_id}",
                "offset": offset,
                "limit": limit,
                "order": "DATE_DESC"
            }
            
            try:
                discography_response = self._graphql_query("queryArtistDiscographyAll", discography_variables)
                
                discography_data = discography_response.get("data", {}).get("artistUnion", {}).get("discography", {}).get("all", {})
                items = discography_data.get("items", [])
                
                if not items:
                    break
                
                all_discography_items.extend(items)
                total_count = discography_data.get("totalCount", len(items))
                
                if len(all_discography_items) >= total_count or len(items) < limit:
                    break
                
                offset += limit
                
            except SpotifyEmbedError as e:
                self.logger.warning(f"Failed to fetch discography page at offset {offset}: {e}")
                break
        
        # Add discography to artist data
        if "discography" not in artist_data:
            artist_data["discography"] = {}
        
        if all_discography_items:
            artist_data["discography"]["all"] = {
                "items": all_discography_items,
                "totalCount": len(all_discography_items)
            }
        
        return overview_response["data"]
    
    def search(self, query: str, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        """
        Search for tracks, albums, artists, and playlists using GraphQL.
        
        Args:
            query: Search query string.
            limit: Maximum number of results to return.
            offset: Number of items to skip.
            
        Returns:
            Dictionary containing search results from GraphQL.
        """
        self.logger.info(f"Searching for query: {query} (limit: {limit}, offset: {offset})")
        
        variables = {
            "searchTerm": query,
            "offset": offset,
            "limit": limit,
            "numberOfTopResults": 5,
            "includeAudiobooks": True,
            "includeArtistHasConcertsField": False,
            "includePreReleases": True,
            "includeAuthors": False,
        }
        
        return self._graphql_query("searchDesktop", variables)
