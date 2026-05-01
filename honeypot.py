"""
Honeypot Manager for HIDS
Manages creation, tracking and deletion of decoy files used to detect intruders.
"""

import os
import json
import uuid
import logging
import time
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

# Decoy file templates: (filename, content)
HONEYPOT_TEMPLATES = [
    {
        "id": "passwords",
        "label": "passwords.txt",
        "filename": "passwords.txt",
        "content": (
            "=== SYSTEM PASSWORDS ===\n"
            "Admin: P@ssw0rd!2024\n"
            "DB_ROOT: Sup3rS3cr3t#\n"
            "SSH_KEY: /home/admin/.ssh/id_rsa\n"
            "VPN: vpn-secret-2024\n"
        )
    },
    {
        "id": "credentials",
        "label": "credentials.json",
        "filename": "credentials.json",
        "content": json.dumps({
            "aws": {"access_key": "AKIAIOSFODNN7EXAMPLE", "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
            "db": {"host": "db.internal", "user": "root", "password": "secret123"},
            "api_key": "sk-proj-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        }, indent=2)
    },
    {
        "id": "backup",
        "label": "backup_keys.txt",
        "filename": "backup_keys.txt",
        "content": (
            "BACKUP ENCRYPTION KEYS - CONFIDENTIAL\n"
            "Primary:   aK9#mP2$vL5@nQ8\n"
            "Secondary: xR3!wE6^yT0*uI4\n"
            "Recovery:  hJ7&bN1%cF4(gD2\n"
        )
    },
    {
        "id": "ssh_key",
        "label": "id_rsa (SSH Private Key)",
        "filename": "id_rsa",
        "content": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAAADECOYFAKEKEY123\n"
            "FAKEKEYDATA+THISISADECOYFILEPLANTEDBYHIDS+DONOTUSE+FAKEFAKEFAKE\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
    },
    {
        "id": "database",
        "label": "database_dump.sql",
        "filename": "database_dump.sql",
        "content": (
            "-- MySQL Database Dump\n"
            "-- Host: localhost  Database: production\n"
            "CREATE TABLE users (id INT, username VARCHAR(50), password_hash VARCHAR(255));\n"
            "INSERT INTO users VALUES (1,'admin','$2y$10$FAKEHASHFORHONEYPOTFILE');\n"
        )
    },
    {
        "id": "config",
        "label": "config_secrets.env",
        "filename": "config_secrets.env",
        "content": (
            "SECRET_KEY=django-insecure-FAKESECRET1234567890\n"
            "DATABASE_URL=postgresql://admin:password@localhost:5432/prod\n"
            "SMTP_PASSWORD=EmailP@ss2024\n"
            "JWT_SECRET=jwt-super-secret-honeypot-key\n"
        )
    },
]

HONEYPOT_STORE = "honeypots.json"


class HoneypotManager:
    """Manages honeypot (decoy) files for intrusion detection."""

    def __init__(self):
        self.store_path = HONEYPOT_STORE
        self.honeypots = {}  # id -> honeypot dict
        self._access_callback = None  # set by hids_core
        self._poll_thread = None
        self._poll_stop = threading.Event()
        self._load()

    # ------------------------------------------------------------------ #
    #  Persistence                                                          #
    # ------------------------------------------------------------------ #

    def _load(self):
        """Load honeypot records from disk."""
        if os.path.exists(self.store_path):
            try:
                with open(self.store_path, "r") as f:
                    self.honeypots = json.load(f)
                logger.info(f"Loaded {len(self.honeypots)} honeypot records")
            except Exception as e:
                logger.error(f"Failed to load honeypots store: {e}")
                self.honeypots = {}

    def _save(self):
        """Persist honeypot records to disk."""
        try:
            with open(self.store_path, "w") as f:
                json.dump(self.honeypots, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save honeypots store: {e}")

    # ------------------------------------------------------------------ #
    #  Public API                                                           #
    # ------------------------------------------------------------------ #

    def plant(self, directory: str, template_id: str) -> dict:
        """
        Plant a honeypot decoy file in the given directory.
        Returns the newly created honeypot record.
        """
        template = next((t for t in HONEYPOT_TEMPLATES if t["id"] == template_id), None)
        if template is None:
            return {"success": False, "message": f"Unknown template: {template_id}"}

        if not os.path.isdir(directory):
            return {"success": False, "message": f"Directory does not exist: {directory}"}

        filepath = os.path.join(directory, template["filename"])
        if os.path.exists(filepath):
            return {"success": False, "message": f"File already exists: {filepath}"}

        try:
            with open(filepath, "w") as f:
                f.write(template["content"])
            logger.info(f"Honeypot planted: {filepath}")
        except Exception as e:
            logger.error(f"Failed to plant honeypot: {e}")
            return {"success": False, "message": str(e)}

        honeypot_id = str(uuid.uuid4())
        # Snapshot the current atime so we can detect reads later
        try:
            current_atime = os.stat(filepath).st_atime
        except Exception:
            current_atime = time.time()
        record = {
            "id": honeypot_id,
            "filename": template["filename"],
            "template_id": template_id,
            "template_label": template["label"],
            "directory": directory,
            "filepath": filepath,
            "planted_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "planted_atime": current_atime,
            "accessed": False,
            "access_events": [],
        }
        self.honeypots[honeypot_id] = record
        self._save()
        return {"success": True, "honeypot": record}

    def delete(self, honeypot_id: str) -> dict:
        """Delete a honeypot file and remove its record."""
        record = self.honeypots.get(honeypot_id)
        if record is None:
            return {"success": False, "message": "Honeypot not found"}

        filepath = record["filepath"]
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                logger.info(f"Honeypot file deleted: {filepath}")
            except Exception as e:
                logger.error(f"Failed to delete honeypot file: {e}")
                return {"success": False, "message": str(e)}

        del self.honeypots[honeypot_id]
        self._save()
        return {"success": True, "message": f"Honeypot {filepath} deleted"}

    def record_access(self, filepath: str, event_type: str = "accessed") -> bool:
        """
        Record an access event for a honeypot.
        Returns True if the file is a known honeypot.
        """
        normalized = os.path.normcase(os.path.abspath(filepath))
        for hp in self.honeypots.values():
            if os.path.normcase(os.path.abspath(hp["filepath"])) == normalized:
                event = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "event_type": event_type,
                }
                hp["accessed"] = True
                hp["access_events"].append(event)
                # Keep last 20 events only
                hp["access_events"] = hp["access_events"][-20:]
                self._save()
                logger.warning(
                    f"HONEYPOT TRIGGERED: {filepath} ({event_type}) at {event['timestamp']}"
                )
                return True
        return False

    def is_honeypot(self, filepath: str) -> bool:
        """Check if a given path is a registered honeypot."""
        normalized = os.path.normcase(os.path.abspath(filepath))
        for hp in self.honeypots.values():
            if os.path.normcase(os.path.abspath(hp["filepath"])) == normalized:
                return True
        return False

    def get_all(self) -> list:
        """Return all honeypot records as a list."""
        return list(self.honeypots.values())

    def get_templates(self) -> list:
        """Return available decoy file templates (id + label only)."""
        return [{"id": t["id"], "label": t["label"], "filename": t["filename"]}
                for t in HONEYPOT_TEMPLATES]

    # ------------------------------------------------------------------ #
    #  Access Polling (detects file reads via atime changes)               #
    # ------------------------------------------------------------------ #

    def start_access_monitor(self, callback):
        """
        Start background thread that polls st_atime of every honeypot file.
        callback(filepath, event_type) is called when access is detected.
        """
        self._access_callback = callback
        self._poll_stop.clear()
        self._poll_thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="HoneypotPoller"
        )
        self._poll_thread.start()
        logger.info("Honeypot access monitor started (atime polling)")

    def stop_access_monitor(self):
        """Stop the polling thread."""
        self._poll_stop.set()

    def _poll_loop(self):
        """Poll every 3 seconds; fire callback if any honeypot atime changed."""
        POLL_INTERVAL = 3
        while not self._poll_stop.wait(POLL_INTERVAL):
            for hp in list(self.honeypots.values()):
                filepath = hp.get("filepath", "")
                if not os.path.exists(filepath):
                    continue
                try:
                    current_atime = os.stat(filepath).st_atime
                    stored_atime = hp.get("planted_atime", 0)
                    if current_atime > stored_atime + 0.5:  # tolerance
                        logger.warning(
                            f"Honeypot atime changed: {filepath} "
                            f"({stored_atime:.2f} -> {current_atime:.2f})"
                        )
                        # Update stored atime so we don't fire repeatedly
                        hp["planted_atime"] = current_atime
                        self._save()
                        if self._access_callback:
                            self._access_callback(filepath, "read")
                except Exception as e:
                    logger.debug(f"atime poll error for {filepath}: {e}")
