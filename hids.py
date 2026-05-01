"""
Host Intrusion Detection System (HIDS)
Main entry point - coordinates all modules
"""

import sys
import logging
import atexit
import signal

# Import modules
from hids_core import HIDS
from api import create_api


# Configure logging
log_handler = logging.FileHandler('hids.log', mode='w', encoding='utf-8')
logging.basicConfig(
    handlers=[log_handler],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize HIDS
hids = HIDS()

# Create Flask app with API routes
app = create_api(hids)


if __name__ == "__main__":
    # Register shutdown handler
    def signal_handler(sig, frame):
        print("\nShutdown signal received, cleaning up...")
        hids.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(hids.shutdown)
    
    # If run with --learn, build anomaly baseline
    if '--learn' in sys.argv:
        hids.build_baseline()
        print("Baseline learning complete. Restart HIDS in normal mode.")
        sys.exit(0)
    
    print("HIDS Server starting on http://0.0.0.0:5000")
    print("Press Ctrl+C to stop")
    app.run(host="0.0.0.0", port=5000, debug=False)