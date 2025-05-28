# OrpheusDL - Spotify

A Spotify module for the OrpheusDL modular archival music program

**This module requires a Spotify Premium account.**<br>
Using this module with a non-Premium account will likely result in authentication failures or an inability to download content.

## Requirements

1.  **Spotify Premium Account:** Essential for accessing audio streams in high quality.
2.  **OrpheusDL:** [My fork](https://github.com/bascurtiz/orpheusdl) is needed to make Spotify's module work

## Installation

1.  Go to your orpheusdl/ directory and run the following command:
2.  ```
    git clone https://github.com/bascurtiz/orpheusdl-spotify.git modules/spotify
    ```
3.  ```
    cd modules/spotify
    pip install -r requirements.txt
    cd..
    cd..
    ```
4.  Run OrpheusDL once (to allow it to recognize the new module and update its main configuration):
    ```
    python orpheus.py
    ```
## Quick Usage Example (CLI)

```
python orpheus.py https://open.spotify.com/track/55jxzrIhEupVy1l6RDJaO5
```
Follow any on-screen instructions for the initial authentication.

## Configuration

When enabling the Spotify module in OrpheusDL (e.g., via `config/settings.json` or the GUI), the following settings are relevant:

*   **`username` (Informational):** After a successful OAuth authentication, your Spotify username might be displayed here or used for informational purposes. It is not used as a primary credential input for authentication.
*   **`download_pause_seconds` (30s by default):** A 30 seconds pause in between downloads is recommended, see: [here](https://developer.spotify.com/documentation/web-api/concepts/rate-limits) and [here](https://github.com/zotify-dev/zotify/issues/186#issuecomment-2608381052)

## Authentication

This module primarily uses a unified OAuth 2.0 PKCE (Proof Key for Code Exchange) flow for both:
*   **Web API Access:** For searching, retrieving metadata (track, album, playlist, artist info).
*   **Stream API Access:** For accessing audio streams for downloads via the integrated Librespot functionality.

**Process:**

1.  **Initiation:** The first time you perform an action requiring Spotify access (e.g., searching, downloading), the module will initiate the authentication flow.
2.  **Browser Authorization:** It will automatically attempt to open an authorization URL in your default web browser.
    *   If the browser doesn't open automatically, a URL will be displayed in the console for you to copy and paste manually.
3.  **Spotify Login & Approval:** In your browser, log in to your Spotify Premium account (if not already logged in) and authorize the app.
4.  **Automatic Code Capture:** After your approval, Spotify redirects to an internal URI (e.g., `http://127.0.0.1:4381/login`). The module runs a temporary local web server to automatically capture the authorization code from this redirect. **You do not need to copy any URL or code manually**
5.  **Token Acquisition:** The module exchanges the captured code for an access token and a refresh token.

**Caching:**

*   Successful authentication tokens (access token, refresh token, expiry information, and associated username) are securely cached in the `config/spotify/credentials.json` file within your OrpheusDL directory.
*   On subsequent runs, the module will attempt to use these cached tokens. If the access token is expired, it will use the refresh token to obtain a new one automatically.
*   If both tokens are invalid or the cache file is missing, the full browser-based OAuth flow will be re-initiated.

**Important:**

*   If you wish to switch Spotify accounts or force a full re-authentication, you can delete the `spotify` folder inside `config` folder.
*   **Audio Quality:** Downloads are obtained by capturing the audio stream. Spotify typically streams in Ogg Vorbis format (~320kbps).<br>
**Lossless (HiFi/FLAC) downloads are NOT supported** as the underlying stream from Spotify to third-party clients like this is (still) lossy.
*   **Terms of Service:** Downloading streams may violate Spotify\'s Terms of Service. Use this module responsibly and at your own risk.
*   **Premium Required:** This module **will not work** with Spotify Free accounts.
*   **Internal Stability:** Relies on the internally integrated `librespot-python` derived logic.

## Usage

Once configured and authenticated:

*   **Search:** Use the standard OrpheusDL search commands/UI. The module supports searching for tracks, albums, artists, and playlists.
*   **Download:** Provide a Spotify URL (track, album, playlist, artist) to OrpheusDL.
Example Track URL: https://open.spotify.com/track/yourTrackId\n
Example Album URL: https://open.spotify.com/album/yourAlbumId\n
Example Playlist URL: https://open.spotify.com/playlist/yourPlaylistId\n
Example Artist URL: https://open.spotify.com/artist/yourArtistId