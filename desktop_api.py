"""
Spotify Desktop API — aligned with spotify-dl-cli architecture.

Uses sp_dc cookie + device flow for authentication, and presents as the actual
Spotify desktop client (not a browser/WebPlayer) to ensure PlayPlay returns
correct key material for Spotify.dll-based decryption.
"""
# Client token used by the WebPlayer lyrics endpoint (separate from the desktop download flow)
DEVICE_CLIENT_TOKEN = "AAAyQwhc1wWtqYH7spRtLROv2auz6t7xi6xV0OIlc62hyvNrbjR3Lky8Lh2s7fi8jbjX1k31NBQ6d+mpEcAyXCvrNDmZSgTjuJ1QBVzqHOpP5t4E4kDvB36AfvXmcgZltN5dYgbiHal/R2LNupoZvT1fKocen24bUAHsInYgCtKy+kft4OWN1kaFo8LfNZymZzmXBXfxKfCiO1dKBQPz7Rv5hVPpcoyxkfAl4R5aNdap3iuRdAcaB4Udx28Eu98yrA=="
import base64
import hashlib
import json
import logging
import os
import re
import struct
import subprocess
import sys
import threading
import time
import binascii
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from Crypto.Cipher import AES
from Crypto.Util import Counter

from .proto.extendedmetadata_pb2 import (
    BatchedEntityRequest, BatchedExtensionResponse, EntityRequest,
    ExtensionQuery, ExtensionKind,
)
from .proto.playplay_pb2 import (
    PlayPlayLicenseRequest, PlayPlayLicenseResponse,
    Interactivity, ContentType,
)
from .proto.audio_files_extension_pb2 import AudioFilesExtensionResponse
from .proto.storage_resolve_pb2 import StorageResolveResponse

try:
    from unplayplay import PLAYPLAY_TOKEN, EMULATOR_SIZES, SP_CLT_VERSION, AUDIO_AES
except ImportError:
    PLAYPLAY_TOKEN = None
    EMULATOR_SIZES = None
    SP_CLT_VERSION = "1.2.88.483"
    AUDIO_AES = None

logger = logging.getLogger(__name__)

# ─── Desktop Client Identity ───────────────────────────────────────────────────
# Must match the Spotify.dll version to receive correct PlayPlay key material.
# spotify-dl-cli uses these exact headers; OrpheusDL was sending browser/WebPlayer
# headers which caused PlayPlay to return wrong obfuscated keys.
CLIENT_ID = "65b708073fc0480ea92a077233ca87bd"
SP_VERSION = SP_CLT_VERSION.replace(".", "") if SP_CLT_VERSION else "128800483"
USER_AGENT = f"Spotify/{SP_VERSION} Win32_x86_64/Windows 10 (10.0.19044; x64)"
APP_PLATFORM = "Win32"

BASE_HEADERS = {
    "user-agent": USER_AGENT,
    "spotify-app-version": SP_VERSION,
    "app-platform": APP_PLATFORM,
}

APRESOLVE_URL = "https://apresolve.spotify.com/"
TIMEOUT = 30

# ─── Device flow constants (kept from original) ────────────────────────────────
DEVICE_AUTH_URL = "https://accounts.spotify.com/oauth2/device/authorize"
DEVICE_TOKEN_URL = "https://accounts.spotify.com/api/token"
DEVICE_RESOLVE_URL = "https://accounts.spotify.com/pair/api/resolve"
DEVICE_SCOPE = (
    "app-remote-control,playlist-modify,playlist-modify-private,playlist-modify-public,"
    "playlist-read,playlist-read-collaborative,playlist-read-private,streaming,"
    "transfer-auth-session,ugc-image-upload,user-follow-modify,user-follow-read,"
    "user-library-modify,user-library-read,user-modify,user-modify-playback-state,"
    "user-modify-private,user-personalized,user-read-birthdate,user-read-currently-playing,"
    "user-read-email,user-read-play-history,user-read-playback-position,"
    "user-read-playback-state,user-read-private,user-read-recently-played,user-top-read"
)

# ─── Decryption IV ──────────────────────────────────────────────────────────────
FLAC_IV = "72e067fbddcbcf77ebe8bc643f630d93"

# ─── OGG page parsing constants ─────────────────────────────────────────────────
OGG_CAPTURE = b"OggS"
OGG_HEADER_STRUCT = struct.Struct("<4sBBQIIIB")
OGG_HEADER_FIXED = 27


# ═══════════════════════════════════════════════════════════════════════════════
#  Service Resolver (apresolve)
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_spclient() -> str:
    """Dynamically resolve the spclient endpoint via apresolve."""
    r = requests.get(
        APRESOLVE_URL,
        headers=BASE_HEADERS,
        params={"type": ("dealer", "spclient")},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    data = r.json()
    endpoints = data.get("spclient", [])
    if not endpoints:
        raise RuntimeError("apresolve returned no spclient endpoints")
    raw = endpoints[0]
    parsed = urlparse(f"https://{raw}")
    return f"{parsed.scheme}://{parsed.netloc}/"


# ═══════════════════════════════════════════════════════════════════════════════
#  Device Flow Auth (sp_dc cookie based — kept from original)
# ═══════════════════════════════════════════════════════════════════════════════

class SpotifyDeviceFlow:
    """Authenticate via device flow using sp_dc cookie."""

    def __init__(self, sp_dc: str) -> None:
        self._session = requests.Session()
        self._session.cookies.set("sp_dc", sp_dc, domain=".spotify.com")
        # Use desktop client headers for the device flow too
        self._session.headers.update(BASE_HEADERS)

    def get_token(self) -> dict:
        auth_data = self._initiate_device_authorization()
        device_code = auth_data["device_code"]
        user_code = auth_data["user_code"]
        verification_url = auth_data["verification_uri_complete"]

        flow_ctx, csrf_token = self._parse_verification_page(verification_url)
        self._submit_user_code(user_code, flow_ctx, csrf_token, verification_url)
        token_data = self._exchange_device_code(device_code)
        return token_data

    def _initiate_device_authorization(self) -> dict:
        response = requests.post(
            DEVICE_AUTH_URL,
            data={"client_id": CLIENT_ID, "scope": DEVICE_SCOPE},
            headers={**BASE_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def _parse_verification_page(self, verification_url: str) -> tuple:
        import urllib.parse
        response = self._session.get(verification_url, allow_redirects=True, timeout=TIMEOUT)
        try:
            flow_ctx_full = urllib.parse.parse_qs(
                urllib.parse.urlparse(response.url).query
            )["flow_ctx"][0]
            flow_ctx = flow_ctx_full.split(":")[0]
        except (KeyError, IndexError):
            raise ValueError("Failed to extract flow_ctx")

        pattern = r'<script id="__NEXT_DATA__" type="application/json"[^>]*>(.*?)</script>'
        match = re.search(pattern, response.text, re.DOTALL)
        try:
            json_data = json.loads(match.group(1))
            csrf_token = json_data["props"]["initialToken"]
        except Exception:
            raise ValueError("Failed to extract CSRF token")

        return flow_ctx, csrf_token

    def _submit_user_code(self, user_code: str, flow_ctx: str, csrf_token: str, referer_url: str) -> None:
        current_ts = int(time.time())
        response = self._session.post(
            DEVICE_RESOLVE_URL,
            params={"flow_ctx": f"{flow_ctx}:{current_ts}"},
            json={"code": user_code},
            headers={
                "x-csrf-token": csrf_token,
                "referer": referer_url,
                "origin": "https://accounts.spotify.com",
                "content-type": "application/json",
            },
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        if response.json().get("result") != "ok":
            raise ValueError("Failed to submit user code (result not ok)")

    def _exchange_device_code(self, device_code: str) -> dict:
        response = requests.post(
            DEVICE_TOKEN_URL,
            data={
                "client_id": CLIENT_ID,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
            headers={**BASE_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        return response.json()


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP Client  (requests-based, desktop identity)
# ═══════════════════════════════════════════════════════════════════════════════

class DesktopHttpClient:
    """HTTP client that presents as the Spotify desktop app."""

    def __init__(self, bearer: str):
        self._session = requests.Session()
        self._session.verify = True
        hdrs = BASE_HEADERS.copy()
        hdrs["authorization"] = f"Bearer {bearer}"
        self._session.headers.update(hdrs)

    def update_token(self, bearer: str):
        self._session.headers["authorization"] = f"Bearer {bearer}"

    def post_protobuf(self, url: str, payload: bytes) -> requests.Response:
        resp = self._session.post(
            url, data=payload,
            headers={"content-type": "application/x-protobuf"},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        return resp

    def get_protobuf(self, url: str) -> bytes:
        resp = self._session.get(
            url,
            headers={"accept": "application/x-protobuf"},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        return resp.content

    def head(self, url: str) -> requests.Response:
        resp = self._session.head(url, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp

    def stream(self, url: str) -> requests.Response:
        return self._session.get(url, stream=True, headers={"Range": "bytes=0-"}, timeout=TIMEOUT)


# ═══════════════════════════════════════════════════════════════════════════════
#  OGG Stream Reconstruction
# ═══════════════════════════════════════════════════════════════════════════════

def _skip_spotify_custom_page(chunk: bytes) -> bytes:
    """Skip Spotify's non-standard first OGG page if present."""
    if len(chunk) >= 4 and chunk[:4] == OGG_CAPTURE:
        idx = chunk.find(OGG_CAPTURE, 4)
        if idx != -1:
            return chunk[idx:]
    return chunk


def reconstruct_ogg_from_chunks(chunks):
    """
    Incrementally reconstruct a valid Ogg stream from fragmented decrypted chunks.
    Based on the libogg streaming pattern used in Soggfy/spotify-dl-cli.
    """
    buf = bytearray()
    probed = False

    for data in chunks:
        if not data:
            continue

        if not probed:
            probed = True
            if data[:4] != OGG_CAPTURE:
                raise RuntimeError(
                    f"Unrecognized codec: first chunk does not start with OggS (first16={data[:16].hex(' ')})"
                )
            data = _skip_spotify_custom_page(data)

        buf.extend(data)

        # Yield complete OGG pages from the buffer
        while True:
            start = buf.find(OGG_CAPTURE)
            if start == -1:
                buf.clear()
                break

            if start > 0:
                del buf[:start]

            if len(buf) < OGG_HEADER_FIXED:
                break

            (capture, version, _htype, _gpos, _serial, _pageno, _crc,
             page_segments) = OGG_HEADER_STRUCT.unpack_from(buf, 0)

            if capture != OGG_CAPTURE or version != 0:
                del buf[:4]
                continue

            header_len = OGG_HEADER_FIXED + page_segments
            if len(buf) < header_len:
                break

            body_len = sum(memoryview(buf)[OGG_HEADER_FIXED:header_len])
            total_len = header_len + body_len

            if len(buf) < total_len:
                break

            yield bytes(buf[:total_len])
            del buf[:total_len]


# ═══════════════════════════════════════════════════════════════════════════════
#  Desktop Spotify API
# ═══════════════════════════════════════════════════════════════════════════════

class DesktopSpotifyApi:
    """
    Desktop Spotify API using sp_dc cookie + device flow auth.

    Key differences from the previous version:
    - Uses `requests` with Spotify desktop User-Agent (not httpx with browser UA)
    - Dynamically resolves spclient via apresolve (not hardcoded endpoints)
    - Includes `timestamp` in PlayPlay license request
    - Uses protobuf for storage-resolve (not JSON)
    - Proper OGG page reconstruction (not naive byte-skip)
    """

    def __init__(self, sp_dc: str, spotify_dll_path: str):
        self.sp_dc = sp_dc
        self.spotify_dll_path = spotify_dll_path
        if not Path(spotify_dll_path).exists():
            raise FileNotFoundError(f"Spotify.dll not found: {spotify_dll_path}")

        # Resolve spclient endpoint dynamically
        self._spclient_base = resolve_spclient()
        logger.info("Using spclient endpoint: %s", self._spclient_base)

        # HTTP client — initialized in authenticate()
        self._http: Optional[DesktopHttpClient] = None
        self._access_token: Optional[str] = None
        self._token_expire_time: int = 0

        # KeyEmu (try direct, fallback to subprocess bridge)
        self.key_emu = None
        if not getattr(sys, 'frozen', False):
            try:
                from unplayplay.key_emu import KeyEmu
                self.key_emu = KeyEmu(Path(spotify_dll_path))
            except Exception as e:
                logger.warning("Could not initialize local KeyEmu: %s. Will use subprocess bridge.", e)

        self._emu_lock = threading.Lock()

    def authenticate(self):
        """Obtain access token via device flow and initialize the HTTP client."""
        flow = SpotifyDeviceFlow(self.sp_dc)
        token_data = flow.get_token()
        self._access_token = token_data["access_token"]
        self._token_expire_time = int(time.time()) + int(token_data.get("expires_in", 3600))

        if self._http is None:
            self._http = DesktopHttpClient(self._access_token)
        else:
            self._http.update_token(self._access_token)
        logger.info("Desktop API authenticated via device flow.")

    def _ensure_auth(self):
        """Refresh auth if token is expired or about to expire."""
        now = int(time.time())
        if not self._access_token or now >= max(0, self._token_expire_time - 60):
            self.authenticate()

    def _build_url(self, path: str) -> str:
        return urljoin(self._spclient_base, path)

    # ─── Extended Metadata ──────────────────────────────────────────────────────

    def get_track_stream_info(self, track_id_base62: str, target_format_id: int):
        """Fetch file ID and CDN URLs for a specific format ID.
        Returns (file_id_hex, file_id_bytes, cdn_urls) or None."""
        self._ensure_auth()

        request = BatchedEntityRequest(
            header={},
            entity_request=[
                EntityRequest(
                    entity_uri=f"spotify:track:{track_id_base62}",
                    query=[
                        ExtensionQuery(extension_kind=ExtensionKind.TRACK_V4),
                        ExtensionQuery(extension_kind=ExtensionKind.AUDIO_FILES),
                    ],
                ),
            ],
        )

        url = self._build_url("/extended-metadata/v0/extended-metadata")
        resp = self._http.post_protobuf(url, request.SerializeToString())

        extended = BatchedExtensionResponse()
        extended.ParseFromString(resp.content)

        audio_ext = next(
            (e for e in extended.extended_metadata if e.extension_kind == ExtensionKind.AUDIO_FILES),
            None,
        )
        if not audio_ext:
            return None

        audio_files = AudioFilesExtensionResponse()
        audio_files.ParseFromString(audio_ext.extension_data[0].extension_data.value)

        audio_file = next((f for f in audio_files.files if f.file.format == target_format_id), None)
        if not audio_file:
            return None

        file_id = audio_file.file.file_id
        file_id_hex = file_id.hex()

        # Resolve CDN URLs via storage-resolve (protobuf, like spotify-dl-cli)
        resolve_url = self._build_url(
            f"/storage-resolve/v2/files/audio/interactive/{target_format_id}/{file_id_hex}"
        )
        resolve_blob = self._http.get_protobuf(resolve_url)

        sr_resp = StorageResolveResponse()
        sr_resp.ParseFromString(resolve_blob)

        if sr_resp.result != StorageResolveResponse.CDN:
            raise RuntimeError(f"storage-resolve failed: result={sr_resp.result}")

        cdnurls = list(sr_resp.cdnurl)
        if not cdnurls:
            raise RuntimeError("storage-resolve returned no CDN URLs")

        return file_id_hex, file_id, cdnurls

    def get_available_formats(self, track_id_base62: str) -> list[int]:
        """Return all available format IDs for a track."""
        self._ensure_auth()

        request = BatchedEntityRequest(
            header={},
            entity_request=[
                EntityRequest(
                    entity_uri=f"spotify:track:{track_id_base62}",
                    query=[
                        ExtensionQuery(extension_kind=ExtensionKind.AUDIO_FILES),
                    ],
                ),
            ],
        )

        try:
            url = self._build_url("/extended-metadata/v0/extended-metadata")
            resp = self._http.post_protobuf(url, request.SerializeToString())

            extended = BatchedExtensionResponse()
            extended.ParseFromString(resp.content)

            audio_ext = next(
                (e for e in extended.extended_metadata if e.extension_kind == ExtensionKind.AUDIO_FILES),
                None,
            )
            if not audio_ext:
                return []

            audio_files = AudioFilesExtensionResponse()
            audio_files.ParseFromString(audio_ext.extension_data[0].extension_data.value)

            return [f.file.format for f in audio_files.files]
        except Exception:
            return []

    # ─── PlayPlay License ───────────────────────────────────────────────────────

    def get_playplay_key(self, file_id_hex: str, file_id_bytes: Optional[bytes] = None) -> bytes:
        """
        Obtain the obfuscated key from PlayPlay, then deobfuscate via KeyEmu.
        """
        self._ensure_auth()

        if file_id_bytes is None:
            file_id_bytes = bytes.fromhex(file_id_hex)

        request = PlayPlayLicenseRequest(
            version=5,
            token=PLAYPLAY_TOKEN,
            interactivity=Interactivity.INTERACTIVE,
            content_type=ContentType.AUDIO_TRACK,
            timestamp=int(time.time()),  # Critical: CLI includes this, old code was missing it
        )

        url = self._build_url(f"/playplay/v1/key/{file_id_hex}")
        resp = self._http.post_protobuf(url, request.SerializeToString())

        license_resp = PlayPlayLicenseResponse()
        license_resp.ParseFromString(resp.content)

        if not license_resp.obfuscated_key:
            raise RuntimeError("PlayPlay returned empty obfuscated_key")

        obfuscated_key = license_resp.obfuscated_key
        logger.debug("Obfuscated key: %s", obfuscated_key.hex())

        # Deobfuscate using KeyEmu
        return self._extract_aes_key(obfuscated_key, file_id_bytes)

    def _extract_aes_key(self, obfuscated_key: bytes, file_id_bytes: bytes) -> bytes:
        """Deobfuscate the PlayPlay key using KeyEmu (direct or subprocess bridge)."""
        with self._emu_lock:
            # Try direct KeyEmu first (dev mode)
            if self.key_emu is not None:
                try:
                    aes_key = self.key_emu.get_aes_key(
                        obfuscated_key=obfuscated_key,
                        content_id=file_id_bytes[:EMULATOR_SIZES.CONTENT_ID] if EMULATOR_SIZES else file_id_bytes[:16],
                    )
                    logger.info("AES key (direct): %s", aes_key.hex())
                    return bytes(aes_key)
                except Exception as e:
                    logger.warning("Direct KeyEmu failed: %s. Falling back to subprocess bridge.", e)

            # Subprocess bridge (frozen app or fallback)
            return self._extract_aes_key_bridge(obfuscated_key, file_id_bytes)

    def _extract_aes_key_bridge(self, obfuscated_key: bytes, file_id_bytes: bytes) -> bytes:
        """Use the subprocess bridge for KeyEmu (for frozen builds)."""
        if getattr(sys, 'frozen', False):
            cmd = [sys.executable, "--spotify-decrypt-worker"]
        else:
            worker_path = Path(__file__).parent / "decrypt_worker.py"
            if not worker_path.exists():
                raise FileNotFoundError(f"Decryption worker not found at {worker_path}")
            cmd = [sys.executable, str(worker_path)]

        cmd.extend([
            str(self.spotify_dll_path),
            obfuscated_key.hex(),
            file_id_bytes.hex(),
        ])

        try:
            result = subprocess.check_output(
                cmd,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            out_str = result.decode('utf-8', 'ignore').strip()
            try:
                if '\n' in out_str:
                    output = json.loads(out_str.splitlines()[-1].strip())
                else:
                    output = json.loads(out_str)
            except ValueError:
                raise RuntimeError(f"Worker output was not valid JSON. Raw: {out_str}")

            if "error" in output:
                raise RuntimeError(f"Worker Error: {output['error']}\n{output.get('traceback', '')}")

            aes_key = binascii.unhexlify(output["key"])
            logger.info("AES key (bridge): %s", aes_key.hex())
            return aes_key

        except subprocess.CalledProcessError as e:
            error_msg = e.output.decode() if e.output else str(e)
            raise RuntimeError(f"Python Bridge failed: {error_msg}")

    # ─── Download & Decrypt ─────────────────────────────────────────────────────

    def download_and_decrypt(
        self,
        stream_urls: list[str],
        decryption_key: bytes,
        output_path: str,
        is_ogg: bool = False,
    ):
        """
        Download and decrypt audio stream using AES-128-CTR.
        For OGG, reconstructs the Ogg page structure instead of naive byte-skip.
        """
        # Use the IV from unplayplay if available, otherwise fallback
        if AUDIO_AES is not None:
            iv_int = AUDIO_AES.IV
        else:
            iv_int = int.from_bytes(bytes.fromhex(FLAC_IV), "big")

        last_error = None
        for idx, url in enumerate(stream_urls, 1):
            try:
                self._download_single_url(url, decryption_key, output_path, iv_int, is_ogg)
                return  # Success
            except Exception as exc:
                last_error = exc
                if os.path.exists(output_path):
                    try:
                        os.unlink(output_path)
                    except OSError:
                        pass
                logger.warning(
                    "Download failed for CDN URL %d/%d: %s",
                    idx, len(stream_urls), exc,
                )

        raise RuntimeError("All CDN download URLs failed") from last_error

    def _download_single_url(
        self,
        url: str,
        aes_key: bytes,
        output_path: str,
        iv_int: int,
        is_ogg: bool,
    ):
        """Download from a single CDN URL, decrypt, and write to output."""
        cipher = AES.new(
            key=aes_key,
            mode=AES.MODE_CTR,
            counter=Counter.new(128, initial_value=iv_int),
        )

        with self._http.stream(url) as resp:
            resp.raise_for_status()

            def decrypt_chunks():
                for chunk in resp.iter_content(chunk_size=65536):
                    yield cipher.decrypt(chunk)

            with open(output_path, "wb") as f:
                if is_ogg:
                    for page in reconstruct_ogg_from_chunks(decrypt_chunks()):
                        f.write(page)
                else:
                    for chunk in decrypt_chunks():
                        f.write(chunk)
