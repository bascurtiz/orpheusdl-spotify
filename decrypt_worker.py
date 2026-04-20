import sys
import json
import binascii
from pathlib import Path

# This script is designed to be called by the main application 
# using the system's python.exe to bypass PyInstaller-specific security blocks.

try:
    from unplayplay.key_emu import KeyEmu
    from unplayplay.consts import EMULATOR_SIZES
except ImportError:
    print(json.dumps({"error": "unplayplay not installed in system Python"}))
    sys.exit(1)

def main():
    if len(sys.argv) < 4:
        print(json.dumps({"error": "Insufficient arguments"}))
        sys.exit(1)

    spotify_dll_path = sys.argv[1]
    obfuscated_key_hex = sys.argv[2]
    content_id_hex = sys.argv[3]

    try:
        if not Path(spotify_dll_path).exists():
            print(json.dumps({"error": f"Spotify.dll not found at {spotify_dll_path}"}))
            sys.exit(1)

        key_emu = KeyEmu(Path(spotify_dll_path))
        
        obfuscated_key = binascii.unhexlify(obfuscated_key_hex)
        content_id = binascii.unhexlify(content_id_hex)

        decryption_key = key_emu.get_aes_key(
            obfuscated_key=obfuscated_key,
            content_id=content_id[:EMULATOR_SIZES.CONTENT_ID]
        )

        print(json.dumps({"key": binascii.hexlify(decryption_key).decode()}))
    except Exception as e:
        import traceback
        print(json.dumps({
            "error": str(e),
            "traceback": traceback.format_exc()
        }))
        sys.exit(1)

if __name__ == "__main__":
    main()
