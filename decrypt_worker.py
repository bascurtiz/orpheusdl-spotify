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
    debug_enabled = False
    try:
        settings_path = Path("config") / "settings.json"
        if settings_path.is_file():
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
            debug_enabled = bool(settings.get("globals", {}).get("advanced", {}).get("debug_mode", False))
    except Exception:
        debug_enabled = False

    if not debug_enabled:
        try:
            if debug_log.is_file():
                debug_log.unlink()
        except Exception:
            pass

    def _write_debug(message: str) -> None:
        if not debug_enabled:
            return
        try:
            with open(debug_log, "a", encoding="utf-8") as f:
                f.write(message)
        except Exception:
            pass

    _write_debug("=== WORKER STARTED ===\n")
    _write_debug(f"Args: {args}\n")

    spotify_dll_path = args[0]
    obfuscated_key_hex = args[1]
    content_id_hex = args[2]

    try:
        # Prefer the production fix if available in the app root
        try:
            from key_emu_prod import KeyEmu
            _write_debug("Loaded KeyEmu from key_emu_prod\n")
        except ImportError as e:
            _write_debug(f"Failed to load key_emu_prod: {e}. Falling back to unplayplay.key_emu\n")
            from unplayplay.key_emu import KeyEmu
            _write_debug("Loaded KeyEmu from unplayplay.key_emu\n")
            
        from unplayplay.consts import EMULATOR_SIZES
    except ImportError as e:
        _write_debug(f"Import error: {e}\n")
        print(json.dumps({"error": f"Required decryption libraries not found: {e}"}))
        return

    try:
        if not Path(spotify_dll_path).exists():
            print(json.dumps({"error": f"Spotify.dll not found at {spotify_dll_path}"}))
            return

        key_emu = KeyEmu(Path(spotify_dll_path))
        _write_debug("Instantiated KeyEmu successfully.\n")
        
        obfuscated_key = binascii.unhexlify(obfuscated_key_hex)
        content_id = binascii.unhexlify(content_id_hex)

        _write_debug("Starting emulation to get AES key...\n")
        decryption_key = key_emu.get_aes_key(
            obfuscated_key=obfuscated_key,
            content_id=content_id[:EMULATOR_SIZES.CONTENT_ID]
        )
        _write_debug("Emulation finished successfully.\n")

        print(json.dumps({"key": binascii.hexlify(decryption_key).decode()}))
    except ImportError:
        _write_debug("Error: unplayplay not found.\n")
        print(json.dumps({"error": "unplayplay not found in the current environment"}))
    except Exception as e:
        import traceback
        _write_debug(f"Exception: {e}\n{traceback.format_exc()}\n")
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
