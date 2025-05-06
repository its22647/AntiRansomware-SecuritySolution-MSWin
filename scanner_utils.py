# scanner_utils.py

import clamd
import os

def scan_and_delete(file_path):
    """
    Scan a file using ClamAV daemon via network socket.
    If a threat is found, returns threat details.
    Otherwise, confirms no threat.
    """
    try:
        if not os.path.exists(file_path):
            return "Error: File does not exist."

        # Connect to ClamAV daemon
        cd = clamd.ClamdNetworkSocket(host='127.0.0.1', port=3310)

        # Perform the scan
        result = cd.scan(file_path)
        print(f"[DEBUG] Scan result for {file_path}: {result}")  # Debug info for VS Code terminal

        if result is None:
            return "Error: Scan failed or ClamAV daemon not running."

        # Check if scan found a threat
        status, signature = result.get(file_path, (None, None))

        if status == 'FOUND':
            return f"❌ Threat detected: {signature}"
        elif status == 'OK':
            return "✅ No threat detected."
        else:
            return "⚠️ Unknown scan result."

    except clamd.ConnectionError:
        return "Error: Cannot connect to ClamAV daemon. Ensure clamd is running."
    except Exception as e:
        return f"Error during scanning: {str(e)}"
