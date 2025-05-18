# OrpheusDL - Spotify

A Spotify module for the OrpheusDL modular achival music program

## Requirements

1.  **Spotify Premium Account:** Essential for accessing audio streams in high quality.
2.  **Spotify Application Credentials:** You need to register an application on the [Spotify Developer Dashboard](https://developer.spotify.com/dashboard) to get a **Client ID** and **Client Secret**.
3.  **`librespot-python` Based Backend:** This module integrates `librespot-python` functionality internally to handle audio streaming.
4.  **OrpheusDL:** [My fork](https://github.com/bascurtiz/orpheusdl) is needed to make Spotify's module work

## Installation

1.  Go to your orpheusdl/ directory and run the following command:
2.  ```
    git clone https://github.com/bascurtiz/orpheusdl-spotify.git modules/spotify
    ```
3.  Run OrpheusDL once to allow it to recognize the new module and update its main configuration:
    ```
    python orpheus.py
    ```
    After this, the `config/settings.json` file should be updated to include a section for Spotify (or if you are using the GUI, the Spotify module should appear in settings).
4.  Enter your Spotify username in settings.json (or through the GUI)
5.  Create a new app here: https://developer.spotify.com/dashboard  
    a. Enter a name (orpheusdl-spotify for ex.) & app description (same)<br>
    b. Copy/paste the Callback URL stated in settings.json at Redirect URIs. Hit Add.<br>
    c. Click Web API + Agree with Spotify's terms & conditions. Hit Save.<br>
    d. Copy/paste the Client ID + Client Secret into settings.json. Hit Save.<br>


    
    After this, the `config/settings.json` file should be updated to include a section for Spotify (or if you are using the GUI, the Spotify module should appear in settings).

## Quick Usage Example (CLI)

Once the module is installed, configured, and you have successfully authenticated (see Configuration and Authentication sections below), you can download a track using a command like this from your main OrpheusDL directory:

```
python orpheus.py https://open.spotify.com/track/55jxzrIhEupVy1l6RDJaO5
```
Follow up the instructions displayed.

## Configuration

When enabling the Spotify module in OrpheusDL (e.g., via `settings.json` or the GUI), you will need to configure the following:

*   **`username` (Required):** Your Spotify username (usually your email address).
*   **`redirect_uri` (Required for Web API):** The Redirect URI for the **Web API** OAuth flow.
    *   This URI **must be added *exactly*** to the "Redirect URIs" section of your application settings on the Spotify Developer Dashboard.
    *   A common and recommended default is `http://127.0.0.1:8888/callback`. If you use this, ensure `http://127.0.0.1:8888/callback` is listed in your Spotify app settings.
*   **`client_id` (Required):** Your Spotify application's Client ID.
*   **`client_secret` (Required):** Your Spotify application's Client Secret.    

## Authentication

This module employs a two-stage authentication process:

### 1. Web API Authentication (for Metadata & Search)

*   **Purpose:** Used for searching, retrieving metadata (track, album, playlist, artist info), and other general API interactions.

### 2. Stream API Authentication (for Downloads via Librespot)

*   **Purpose:** Used for accessing the actual audio streams for downloading tracks.

Clearing the cache files (both `/config/.spotify_cache/spotipy_token_cache.json` and the contents of `/config/.spotify_cache/librespot_cache/`) will trigger a full re-authentication process for both Web and Stream APIs.

## Usage

Once configured and authenticated:

*   **Search:** Use the standard OrpheusDL search commands/UI. The module supports searching for `track`, `album`, `artist`, and `playlist`.
*   **Download:** Provide Spotify URLs for tracks, albums, artists, or playlists to the OrpheusDL download command/UI.
    *   Example Track URL: `https://open.spotify.com/track/yourTrackId`
    *   Example Album URL: `https://open.spotify.com/album/yourAlbumId`
    *   Example Playlist URL: `https://open.spotify.com/playlist/yourPlaylistId`
    *   Example Artist URL: `https://open.spotify.com/artist/yourArtistId`

## Limitations & Considerations

*   **Audio Quality:** Downloads are obtained by capturing the audio stream. Spotify typically streams in Ogg Vorbis format (qualities around ~96kbps, ~160kbps, or ~320kbps). **Lossless (HiFi/FLAC) downloads are NOT supported** as the underlying stream from Spotify to third-party clients like this is (still) lossy.
*   **Terms of Service:** Downloading streams may violate Spotify\'s Terms of Service. Use this module responsibly and at your own risk.
*   **Premium Required:** This module **will not work** with Spotify Free accounts.
*   **Rate Limiting:** A 30 seconds pause in between downloads is recommended, see: [here](https://developer.spotify.com/documentation/web-api/concepts/rate-limits) and [here](https://github.com/zotify-dev/zotify/issues/186#issuecomment-2608381052)
*   **Internal Stability:** Relies on the internally integrated `librespot-python` derived logic.

## Known Issues

*   Rate-limiting. 30 seconds pause in between downloads is recommended, when you download more than ~20 tracks in one-go. If not, 1 second will suffice.

## Known Limitations

*   Genre tag will be absent due to Orpheus core model structure.
*   Only works with [My fork](https://github.com/bascurtiz/orpheusdl) of OrpheusDL