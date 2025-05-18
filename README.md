# OrpheusDL - Spotify

A Spotify module for the OrpheusDL modular achival music program

**This module requires a Spotify Premium account.**<br>
Using this module with a non-Premium account will likely result in authentication failures or an inability to download content.

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
*   **Mechanism:** Standard OAuth 2.0 Authorization Code Flow.
*   **Process:**
    1.  Requires your `client_id`, `client_secret`, and the `redirect_uri` you configured.
    2.  The first time you use a feature requiring Web API access (or after credentials expire), OrpheusDL (console or GUI) will typically prompt you to open a Spotify authorization URL in your browser.
    3.  In your browser, log in to Spotify and authorize the application.
    4.  After authorization, Spotify will redirect you to your specified `redirect_uri`. **Copy the *entire* URL** from your browser's address bar (it will look something like `http://your-redirect-uri/?code=A_LONG_CODE_HERE...`).
    5.  Paste this full redirected URL back into OrpheusDL when prompted.
*   **Caching:** Successful Web API authentication tokens are cached by the underlying `spotipy` library (`/config/.spotify_cache/web_api_credentials.json` in your OrpheusDL directory) to minimize re-authentication.

### 2. Stream API Authentication (for Downloads via Librespot)

*   **Purpose:** Used for accessing the actual audio streams for downloading tracks.
*   **Mechanism:** Primarily uses an interactive PKCE-based OAuth flow, with fallbacks to cached credentials.
*   **Process (Interactive PKCE OAuth - Recommended & Preferred):**
    1.  This is generally the **default and most reliable** method for authenticating the streaming component.
    2.  When a download is initiated and stream authentication is needed, the module (via its internal Librespot integration) will attempt to start this flow.
    3.  It automatically opens an authorization URL in your web browser.
    4.  You will need to log in and authorize the "app" (which in this context is the Librespot client).
    5.  The flow uses a temporary local web server (typically on `http://127.0.0.1:4381/login`) to automatically capture the authorization code. **You do not need to configure this local redirect URI in your Spotify app settings.**
    6.  If using the OrpheusDL GUI, this process can be more seamless with integrated dialogs.
*   **Process (Cached Librespot Credentials):**
    1.  After a successful PKCE authentication, Librespot caches its own stream access credentials.
    2.  These are stored in `credentials.json` file within a directory like `/config/.spotify_cache/librespot_cache/` (relative to your OrpheusDL directory).
    3.  On subsequent runs, the module will attempt to use these cached credentials automatically.*   
*   **Important:**
    *   Manual creation or placement of a `credentials.json` file is **not required** for the primary PKCE authentication flow.
    *   Follow any prompts from OrpheusDL (console or GUI) during the first download attempt.

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