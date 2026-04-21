import json
import logging
import re
from pathlib import Path
import time
from urllib.parse import parse_qs
import requests
from Crypto.Cipher import AES
from Crypto.Util import Counter

from .proto.extendedmetadata_pb2 import BatchedEntityRequest, BatchedExtensionResponse, EntityRequest, ExtensionQuery, ExtensionKind
from .proto.playplay_pb2 import PlayPlayLicenseRequest, PlayPlayLicenseResponse, Interactivity, ContentType
from .proto.audio_files_extension_pb2 import AudioFilesExtensionResponse
import subprocess
import binascii
import sys
import os

try:
    from unplayplay.key_emu import KeyEmu
    from unplayplay.consts import PLAYPLAY_TOKEN, EMULATOR_SIZES
except ImportError:
    KeyEmu = None
    PLAYPLAY_TOKEN = None
    EMULATOR_SIZES = None

logger = logging.getLogger(__name__)

TIMEOUT = 30
DEVICE_AUTH_URL = "https://accounts.spotify.com/oauth2/device/authorize"
DEVICE_TOKEN_URL = "https://accounts.spotify.com/api/token"
DEVICE_RESOLVE_URL = "https://accounts.spotify.com/pair/api/resolve"
DEVICE_CLIENT_ID = "65b708073fc0480ea92a077233ca87bd"
DEVICE_SCOPE = "app-remote-control,playlist-modify,playlist-modify-private,playlist-modify-public,playlist-read,playlist-read-collaborative,playlist-read-private,streaming,transfer-auth-session,ugc-image-upload,user-follow-modify,user-follow-read,user-library-modify,user-library-read,user-modify,user-modify-playback-state,user-modify-private,user-personalized,user-read-birthdate,user-read-currently-playing,user-read-email,user-read-play-history,user-read-playback-position,user-read-playback-state,user-read-private,user-read-recently-played,user-top-read"
DEVICE_FLOW_USER_AGENT = "Spotify/128600502 Win32_x86_64/0 (PC desktop)"
DEVICE_CLIENT_TOKEN = "AADYATyeSD/y5/hrnY8iTzYaPodQdTzz/ffPg5WV8tD5KN53Yi/93r5TSMLRYo4aQCNgzl/1ckCkhFbOjPBWigpOdpvOZxfgJ3mov8/1IBpg05yWPKxwB7xV8SjNIlphPfj9LbrfbLZczrdYD0Wa++z+7sioGtI+m2GcgkOiRQgFqwEn8kP/PkIc/vHADZ1Zs3SZKif+5pXLlJ/0SDr8eZ+xECOXtfCw6jBAkl4r+wOMFrAMmE2JuLGFLg5PDD0="

EXTENDED_METADATA_API_URL = "https://spclient.wg.spotify.com/extended-metadata/v0/extended-metadata"
AUDIO_STREAM_URLS_API_URL = "https://gue1-spclient.spotify.com/storage-resolve/v2/files/audio/interactive/{format_id}/{file_id}?version=10000000&product=9&platform=39&alt=json"
PLAYPLAY_LICENSE_API_URL = "https://spclient.wg.spotify.com/playplay/v1/key/{file_id}"

# Decryption IVs
FLAC_IV = "72e067fbddcbcf77ebe8bc643f630d93"
OGG_IV  = "00000000000000000000000000000000"


class SpotifyDeviceFlow:
    def __init__(self, sp_dc: str) -> None:
        import httpx
        self.client = httpx.Client(timeout=TIMEOUT)
        self.client.cookies.set("sp_dc", sp_dc, domain=".spotify.com")

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
        import httpx
        response = httpx.post(
            DEVICE_AUTH_URL,
            data={"client_id": DEVICE_CLIENT_ID, "scope": DEVICE_SCOPE},
            headers={"User-Agent": DEVICE_FLOW_USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"},
            timeout=TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    def _parse_verification_page(self, verification_url: str) -> tuple[str, str]:
        import requests # using requests here just for urlparse if needed, or stick to standard urllib
        import urllib.parse
        response = self.client.get(verification_url, follow_redirects=True, timeout=TIMEOUT)
        try:
            flow_ctx_full = urllib.parse.parse_qs(urllib.parse.urlparse(str(response.url)).query)["flow_ctx"][0]
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
        response = self.client.post(
            DEVICE_RESOLVE_URL,
            params={"flow_ctx": f"{flow_ctx}:{current_ts}"},
            json={"code": user_code},
            headers={
                "x-csrf-token": csrf_token,
                "referer": referer_url,
                "origin": "https://accounts.spotify.com",
                "content-type": "application/json",
            },
            timeout=TIMEOUT
        )
        response.raise_for_status()
        if response.json().get("result") != "ok":
            raise ValueError("Failed to submit user code (result not ok)")

    def _exchange_device_code(self, device_code: str) -> dict:
        import httpx
        response = httpx.post(
            DEVICE_TOKEN_URL,
            data={
                "client_id": DEVICE_CLIENT_ID,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
            headers={"User-Agent": DEVICE_FLOW_USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"},
            timeout=TIMEOUT
        )
        response.raise_for_status()
        return response.json()

class DesktopSpotifyApi:
    def __init__(self, sp_dc: str, spotify_dll_path: str):
        self.sp_dc = sp_dc
        self.spotify_dll_path = spotify_dll_path
        if not Path(spotify_dll_path).exists():
            raise FileNotFoundError(f"Spotify.dll not found at specified path: {spotify_dll_path}")
        
        # Don't initialize KeyEmu directly if we are likely to use the bridge
        self.key_emu = None
        if not getattr(sys, 'frozen', False):
            try:
                self.key_emu = KeyEmu(Path(spotify_dll_path))
            except Exception as e:
                logger.warning(f"Could not initialize local KeyEmu: {e}. Will fall back to Python Bridge.")

        import httpx
        # Enforce httpx as Votify's underlying client to prevent TLS fingerprint blocking
        self.client = httpx.Client(timeout=TIMEOUT)
        # Add required headers to mock WebPlayer client exactly as Votify
        self.client.headers.update({
            "accept": "application/json",
            "accept-language": "en-US",
            "content-type": "application/json",
            "origin": "https://open.spotify.com/",
            "priority": "u=1, i",
            "referer": "https://open.spotify.com/",
            "sec-ch-ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "spotify-app-version": "1.2.82.471.gfc8488e1",
            "app-platform": "WebPlayer",
        })
        self.client.cookies.set("sp_dc", sp_dc, domain=".spotify.com")
        self._access_token = None
        import threading
        self._emu_lock = threading.Lock()
        
    def authenticate(self):
        flow = SpotifyDeviceFlow(self.sp_dc)
        token_data = flow.get_token()
        self._access_token = token_data["access_token"]
        self.client.headers.update({
            "authorization": f"Bearer {self._access_token}",
            "client-token": DEVICE_CLIENT_TOKEN
        })

    def get_track_stream_info(self, track_id_base62: str, target_format_id: int):
        """Fetches stream URL and file ID for a specific format ID.
        Common IDs: 16 (FLAC 16-bit), 22 (FLAC 24-bit), 4 (Vorbis 320k), 3 (Vorbis 160k)."""
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
        
        response = self.client.post(
            EXTENDED_METADATA_API_URL,
            content=request.SerializeToString(),
            headers={
                "Accept": "application/x-protobuf",
                "Content-Type": "application/x-protobuf",
            },
            timeout=TIMEOUT
        )
        response.raise_for_status()
        
        extended_metadata = BatchedExtensionResponse()
        extended_metadata.ParseFromString(response.content)
        
        audio_files_ext = next((ext for ext in extended_metadata.extended_metadata if ext.extension_kind == ExtensionKind.AUDIO_FILES), None)
        if not audio_files_ext:
            return None
            
        audio_files = AudioFilesExtensionResponse()
        audio_files.ParseFromString(audio_files_ext.extension_data[0].extension_data.value)
        
        audio_file_info = next((f for f in audio_files.files if f.file.format == target_format_id), None)
        if not audio_file_info:
            return None
            
        file_id_hex = audio_file_info.file.file_id.hex()
        
        # Get CDN URL
        url_resp = self.client.get(
            AUDIO_STREAM_URLS_API_URL.format(format_id=str(target_format_id), file_id=file_id_hex),
            timeout=TIMEOUT
        )
        url_resp.raise_for_status()
        stream_url = url_resp.json()["cdnurl"][0]
        
        return file_id_hex, stream_url

    def get_available_formats(self, track_id_base62: str) -> list[int]:
        """Returns a list of all available format IDs for a track."""
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
            response = self.client.post(
                EXTENDED_METADATA_API_URL,
                content=request.SerializeToString(),
                headers={
                    "Accept": "application/x-protobuf",
                    "Content-Type": "application/x-protobuf",
                },
                timeout=TIMEOUT
            )
            response.raise_for_status()
            
            extended_metadata = BatchedExtensionResponse()
            extended_metadata.ParseFromString(response.content)
            
            audio_files_ext = next((ext for ext in extended_metadata.extended_metadata if ext.extension_kind == ExtensionKind.AUDIO_FILES), None)
            if not audio_files_ext:
                return []
                
            audio_files = AudioFilesExtensionResponse()
            audio_files.ParseFromString(audio_files_ext.extension_data[0].extension_data.value)
            
            return [f.file.format for f in audio_files.files]
        except Exception:
            return []

    def get_playplay_key(self, file_id_hex: str) -> bytes:
        file_id_bytes = bytes.fromhex(file_id_hex)
        request = PlayPlayLicenseRequest(
            version=5,
            token=PLAYPLAY_TOKEN,
            interactivity=Interactivity.INTERACTIVE,
            content_type=ContentType.AUDIO_TRACK,
        )
        
        response = self.client.post(
            PLAYPLAY_LICENSE_API_URL.format(file_id=file_id_hex),
            content=request.SerializeToString(),
            headers={
                "Accept": "application/x-protobuf",
                "Content-Type": "application/x-protobuf",
            },
            timeout=TIMEOUT
        )
        response.raise_for_status()
        
        license_resp = PlayPlayLicenseResponse()
        license_resp.ParseFromString(response.content)
        


        with self._emu_lock:
            # Determine path to worker script
            if getattr(sys, 'frozen', False):
                # In frozen app, we use sys.executable with a worker flag
                cmd = [sys.executable, "--spotify-decrypt-worker"]
            else:
                # In development, we use sys.executable (usually python.exe) with the worker script path
                worker_path = Path(__file__).parent / "decrypt_worker.py"
                if not worker_path.exists():
                    raise FileNotFoundError(f"Decryption worker not found at {worker_path}")
                cmd = [sys.executable, str(worker_path)]

            # Call the worker (either via script or the app itself in worker mode)
            try:
                cmd.extend([
                    str(self.spotify_dll_path),
                    license_resp.obfuscated_key.hex(),
                    file_id_hex
                ])
                
                result = subprocess.check_output(
                    cmd,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                )
                
                out_str = result.decode('utf-8', 'ignore').strip()
                try:
                    # In case other modules printed to stdout, try to extract just the last line
                    if '\n' in out_str:
                        last_line = out_str.splitlines()[-1].strip()
                        output = json.loads(last_line)
                    else:
                        output = json.loads(out_str)
                except ValueError as json_err:
                    raise RuntimeError(f"Worker output was not valid JSON. Raw output: {out_str}")
                    
                if "error" in output:
                    raise RuntimeError(f"Worker Error: {output['error']}\n{output.get('traceback', '')}")
                
                decryption_key = binascii.unhexlify(output["key"])

                return decryption_key

            except subprocess.CalledProcessError as e:
                error_msg = e.output.decode() if e.output else str(e)
                logger.error(f"Python Bridge failed: {error_msg}")
                raise RuntimeError(f"Python Bridge failed to execute: {error_msg}")
            except Exception as e:
                logger.error(f"Failed to call Python Bridge: {e}")
                raise



    def download_and_decrypt(self, stream_url: str, decryption_key: bytes, output_path: str, iv_hex: str = FLAC_IV):
        iv_bytes = bytes.fromhex(iv_hex)
        cipher = AES.new(
            key=decryption_key,
            mode=AES.MODE_CTR,
            counter=Counter.new(
                128,
                initial_value=int.from_bytes(iv_bytes, "big"),
            ),
        )
        
        import httpx
        with httpx.stream("GET", stream_url, timeout=TIMEOUT) as response:
            response.raise_for_status()
            with open(output_path, "wb") as f:
                for chunk in response.iter_bytes(chunk_size=16384):
                    if chunk:
                        f.write(cipher.decrypt(chunk))
