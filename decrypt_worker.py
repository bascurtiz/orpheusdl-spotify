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

    debug_log = Path("worker_debug.log")
    with open(debug_log, "a") as f:
        f.write("=== WORKER STARTED ===\n")
        f.write(f"Args: {args}\n")

    spotify_dll_path = args[0]
    obfuscated_key_hex = args[1]
    content_id_hex = args[2]

    try:
        # Prefer the production fix if available in the app root
        try:
            from key_emu_prod import KeyEmu
            with open(debug_log, "a") as f: f.write("Loaded KeyEmu from key_emu_prod\n")
        except ImportError as e:
            with open(debug_log, "a") as f: f.write(f"Failed to load key_emu_prod: {e}. Falling back to unplayplay.key_emu\n")
            from unplayplay.key_emu import KeyEmu
            with open(debug_log, "a") as f: f.write("Loaded KeyEmu from unplayplay.key_emu\n")
            
        from unplayplay.consts import EMULATOR_SIZES
    except ImportError as e:
        with open(debug_log, "a") as f: f.write(f"Import error: {e}\n")
        print(json.dumps({"error": f"Required decryption libraries not found: {e}"}))
        return

    try:
        if not Path(spotify_dll_path).exists():
            print(json.dumps({"error": f"Spotify.dll not found at {spotify_dll_path}"}))
            return

        key_emu = KeyEmu(Path(spotify_dll_path))
        with open(debug_log, "a") as f: f.write("Instantiated KeyEmu successfully.\n")
        
        obfuscated_key = binascii.unhexlify(obfuscated_key_hex)
        content_id = binascii.unhexlify(content_id_hex)

        with open(debug_log, "a") as f: f.write("Starting emulation to get AES key...\n")
        decryption_key = key_emu.get_aes_key(
            obfuscated_key=obfuscated_key,
            content_id=content_id[:EMULATOR_SIZES.CONTENT_ID]
        )
        with open(debug_log, "a") as f: f.write("Emulation finished successfully.\n")

        print(json.dumps({"key": binascii.hexlify(decryption_key).decode()}))
    except ImportError:
        with open(debug_log, "a") as f: f.write("Error: unplayplay not found.\n")
        print(json.dumps({"error": "unplayplay not found in the current environment"}))
    except Exception as e:
        import traceback
        with open(debug_log, "a") as f: f.write(f"Exception: {e}\n{traceback.format_exc()}\n")
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
