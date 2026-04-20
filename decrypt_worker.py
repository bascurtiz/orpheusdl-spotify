import sys
import json
import binascii
from pathlib import Path

# This script is designed to be called by the main application 
# using the system's python.exe to bypass PyInstaller-specific security blocks.
# In frozen mode, it is called using sys.executable with a flag.

def run_worker(args):
    """
    Core logic for the decryption worker.
    args: [spotify_dll_path, obfuscated_key_hex, content_id_hex]
    """
    if len(args) < 3:
        print(json.dumps({"error": "Insufficient arguments for worker"}))
        return

    spotify_dll_path = args[0]
    obfuscated_key_hex = args[1]
    content_id_hex = args[2]

    try:
        from unplayplay.key_emu import KeyEmu
        from unplayplay.consts import EMULATOR_SIZES
        
        if not Path(spotify_dll_path).exists():
            print(json.dumps({"error": f"Spotify.dll not found at {spotify_dll_path}"}))
            return

        key_emu = KeyEmu(Path(spotify_dll_path))
        
        obfuscated_key = binascii.unhexlify(obfuscated_key_hex)
        content_id = binascii.unhexlify(content_id_hex)

        decryption_key = key_emu.get_aes_key(
            obfuscated_key=obfuscated_key,
            content_id=content_id[:EMULATOR_SIZES.CONTENT_ID]
        )

        print(json.dumps({"key": binascii.hexlify(decryption_key).decode()}))
    except ImportError:
        print(json.dumps({"error": "unplayplay not found in the current environment"}))
    except Exception as e:
        import traceback
        print(json.dumps({
            "error": str(e),
            "traceback": traceback.format_exc()
        }))

def main():
    if len(sys.argv) < 4:
        print(json.dumps({"error": "Insufficient arguments"}))
        sys.exit(1)

    # Use arguments from index 1 onwards
    run_worker(sys.argv[1:])

if __name__ == "__main__":
    main()
