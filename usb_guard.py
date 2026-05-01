"""
USB Device Guard Module
Monitors for USB drive insertions via WMI, scans drive contents with YARA,
and reports threats to the HIDS core.
"""

import os
import json
import time
import logging
import threading
import pythoncom
import wmi
from datetime import datetime

USB_EVENTS_FILE = 'usb_events.json'

# Files/patterns that are inherently suspicious on a USB root
SUSPICIOUS_EXTENSIONS = {'.exe', '.bat', '.cmd', '.vbs', '.ps1', '.scr', '.pif', '.com', '.msi', '.jar'}
SUSPICIOUS_ROOT_FILES = {'autorun.inf', 'autorun.bat', 'autoplay.exe'}

class UsbGuardManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._hids = None
        self.events = self._load_events()

    # ------------------------------------------------------------------ #
    #  Persistence                                                          #
    # ------------------------------------------------------------------ #

    def _load_events(self):
        try:
            if os.path.exists(USB_EVENTS_FILE):
                with open(USB_EVENTS_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logging.warning(f"Could not load usb_events.json: {e}")
        return []

    def _save_events(self):
        try:
            with open(USB_EVENTS_FILE, 'w') as f:
                json.dump(self.events, f, indent=2)
        except Exception as e:
            logging.warning(f"Could not save usb_events.json: {e}")

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                            #
    # ------------------------------------------------------------------ #

    def start(self, hids=None):
        """Start WMI USB detection thread."""
        self._stop_event.clear()
        self._hids = hids
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name='UsbGuard')
        self._thread.start()
        logging.info("USB Guard started — monitoring for USB insertions")

    def stop(self):
        """Stop the USB monitor thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        logging.info("USB Guard stopped")

    # ------------------------------------------------------------------ #
    #  WMI Monitor Loop                                                     #
    # ------------------------------------------------------------------ #

    def _monitor_loop(self):
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            # EventType 2 = insertion
            watcher = c.Win32_VolumeChangeEvent.watch_for(EventType=2)
            logging.info("USB WMI watcher registered (Win32_VolumeChangeEvent)")
            while not self._stop_event.is_set():
                try:
                    event = watcher(timeout_ms=2000)
                    if event:
                        drive_letter = event.DriveName  # e.g. "E:"
                        self._handle_insertion(drive_letter)
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as e:
                    if not self._stop_event.is_set():
                        logging.error(f"USB WMI watcher error: {e}")
                    break
        except Exception as e:
            logging.error(f"USB Guard WMI init failed: {e}")
        finally:
            pythoncom.CoUninitialize()

    # ------------------------------------------------------------------ #
    #  Insertion Handler                                                    #
    # ------------------------------------------------------------------ #

    def _handle_insertion(self, drive_letter: str):
        drive_letter = drive_letter.rstrip('/\\')
        if not drive_letter.endswith(':'):
            drive_letter = drive_letter + ':'
        drive_path = drive_letter + '\\'

        logging.info(f"USB inserted: {drive_letter}")

        # Wait briefly for the drive to be accessible
        time.sleep(1.5)

        # Get volume label
        label = self._get_volume_label(drive_path)

        # Scan drive
        findings = self.scan_drive(drive_path)
        threat_count = sum(1 for f in findings if f['severity'] in ('critical', 'high', 'medium'))
        status = 'threat' if threat_count > 0 else 'clean'

        event = {
            'id': f"usb_{int(time.time())}",
            'drive': drive_letter,
            'label': label or 'USB Drive',
            'connected_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'files_scanned': sum(1 for f in findings),
            'threat_count': threat_count,
            'status': status,
            'findings': findings,
        }

        with self._lock:
            self.events.insert(0, event)
            # Keep last 50 USB events
            self.events = self.events[:50]
            self._save_events()

        if self._hids:
            self._hids.on_usb_inserted(drive_letter, label or 'USB Drive', findings, threat_count)

    # ------------------------------------------------------------------ #
    #  Drive Scanner                                                        #
    # ------------------------------------------------------------------ #

    def scan_drive(self, drive_path: str) -> list:
        """Walk drive, run YARA + heuristics. Returns list of finding dicts."""
        findings = []
        try:
            for root, dirs, files in os.walk(drive_path):
                # Limit depth to 4 levels to avoid scanning huge external HDDs deeply
                depth = root.replace(drive_path, '').count(os.sep)
                if depth > 4:
                    dirs.clear()
                    continue

                for filename in files:
                    full_path = os.path.join(root, filename)
                    finding = self._scan_file(full_path, drive_path)
                    if finding:
                        findings.append(finding)

                        # Cap findings list at 200
                        if len(findings) >= 200:
                            return findings
        except PermissionError:
            logging.warning(f"Permission denied scanning {drive_path}")
        except Exception as e:
            logging.error(f"Error scanning USB drive {drive_path}: {e}")

        return findings

    def _scan_file(self, full_path: str, drive_root: str) -> dict | None:
        """Scan a single file for threats. Returns finding dict or None."""
        filename = os.path.basename(full_path).lower()
        ext = os.path.splitext(filename)[1].lower()
        relative = full_path.replace(drive_root, '')
        # Normalize both sides so 'D:\' compares equal to 'D:\' (not 'D:')
        file_dir   = os.path.normpath(os.path.dirname(full_path))
        drive_norm = os.path.normpath(drive_root)

        # 1. Autorun check
        if filename in SUSPICIOUS_ROOT_FILES and file_dir == drive_norm:
            return {
                'file': relative,
                'full_path': full_path,
                'rule': 'Suspicious Autorun File',
                'severity': 'critical',
                'detail': f'Autorun file detected in USB root: {filename}',
            }

        # 2. Executable in root check
        if ext in SUSPICIOUS_EXTENSIONS and file_dir == drive_norm:
            return {
                'file': relative,
                'full_path': full_path,
                'rule': 'Executable in USB Root',
                'severity': 'high',
                'detail': f'Executable file in USB root directory: {filename}',
            }

        # 3. Hidden executable (hidden attribute set)
        try:
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(full_path)
            FILE_ATTRIBUTE_HIDDEN = 0x2
            FILE_ATTRIBUTE_SYSTEM = 0x4
            if attrs != -1 and (attrs & FILE_ATTRIBUTE_HIDDEN) and ext in SUSPICIOUS_EXTENSIONS:
                return {
                    'file': relative,
                    'full_path': full_path,
                    'rule': 'Hidden Executable',
                    'severity': 'critical',
                    'detail': f'Hidden executable detected: {filename}',
                }
        except Exception:
            pass

        # 4. YARA scan (only scan files ≤ 20 MB to keep it fast)
        try:
            file_size = os.path.getsize(full_path)
            if file_size > 0 and file_size <= 20 * 1024 * 1024:
                if self._hids and hasattr(self._hids, 'rules') and self._hids.rules:
                    matches = self._hids.rules.match(full_path)
                    if matches:
                        rule_names = ', '.join(str(m) for m in matches)
                        return {
                            'file': relative,
                            'full_path': full_path,
                            'rule': f'YARA: {rule_names}',
                            'severity': 'critical',
                            'detail': f'YARA match on USB file: {rule_names}',
                        }
        except Exception:
            pass

        return None

    # ------------------------------------------------------------------ #
    #  Rescan                                                               #
    # ------------------------------------------------------------------ #

    def rescan(self, drive_letter: str) -> dict:
        """Re-scan a connected drive on demand."""
        drive_letter = drive_letter.upper()
        if not drive_letter.endswith(':'):
            drive_letter += ':'
        drive_path = drive_letter + '\\'

        if not os.path.exists(drive_path):
            return {'success': False, 'message': f'Drive {drive_letter} is not accessible'}

        label = self._get_volume_label(drive_path)
        findings = self.scan_drive(drive_path)
        threat_count = sum(1 for f in findings if f['severity'] in ('critical', 'high', 'medium'))
        status = 'threat' if threat_count > 0 else 'clean'

        new_event = {
            'id': f"usb_{int(time.time())}",
            'drive': drive_letter,
            'label': label or 'USB Drive',
            'connected_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'files_scanned': len(findings),
            'threat_count': threat_count,
            'status': status,
            'findings': findings,
        }

        with self._lock:
            # Replace any existing event for same drive (most recent)
            self.events = [e for e in self.events if e['drive'] != drive_letter]
            self.events.insert(0, new_event)
            self._save_events()

        if self._hids:
            self._hids.on_usb_inserted(drive_letter, label or 'USB Drive', findings, threat_count)

        return {'success': True, 'event': new_event}

    # ------------------------------------------------------------------ #
    #  Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _get_volume_label(self, drive_path: str) -> str:
        try:
            import ctypes
            label_buf = ctypes.create_unicode_buffer(261)
            ctypes.windll.kernel32.GetVolumeInformationW(
                drive_path, label_buf, 261, None, None, None, None, 0
            )
            return label_buf.value.strip() or None
        except Exception:
            return None

    def get_all(self) -> list:
        with self._lock:
            return list(self.events)

    def clear(self):
        with self._lock:
            self.events = []
            self._save_events()
