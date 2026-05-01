"""
HIDS Core Module
Contains the main HIDS class with detection logic, configuration, and monitoring coordination
"""

import os
import sys
import time
import threading
import re
import ctypes
import logging
import configparser
import pythoncom
import wmi
import win32api
import win32con
import win32security
import yara
from collections import defaultdict
from watchdog.observers import Observer

from yara_rules import compile_rules
from monitors import ProcessMonitor, RegistryMonitor, HIDSFileSystemEventHandler
from email_alerts import EmailAlerter
from honeypot import HoneypotManager
from usb_guard import UsbGuardManager



def enable_privilege(privilege_name):
    """Enable Windows privilege"""
    try:
        flags = win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
        privilege_id = win32security.LookupPrivilegeValue(None, privilege_name)
        win32security.AdjustTokenPrivileges(token, False, [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)])
        logging.info(f"Privilege {privilege_name} enabled successfully")
        return True
    except Exception as e:
        logging.error(f"Failed to enable privilege {privilege_name}: {str(e)}")
        return False


class HIDS:
    """Main Host Intrusion Detection System class"""
    
    def __init__(self):
        # Check admin privileges first
        if not self.is_admin():
            logging.error("HIDS requires administrator privileges to function properly")
            print("ERROR: This application must be run as Administrator")
            sys.exit(1)
        
        self.config = configparser.ConfigParser()
        if not os.path.exists('config.ini'):
            logging.warning("config.ini not found, creating default configuration")
            self.create_default_config()
        self.config.read('config.ini')
        self.validate_config()
        
        self.monitoring_active = False
        self.shutdown_event = threading.Event()
        enable_privilege(win32con.SE_DEBUG_NAME)
        try:
            self.rules = compile_rules()
            logging.info("YARA rules compiled successfully")
        except Exception as e:
            logging.error(f"YARA compilation error: {str(e)}")
            sys.exit(1)
        self.suspicious_activities = []
        self.activities_lock = threading.Lock()  # Thread safety for suspicious_activities
        self.wmi_conn = None
        self.process_monitor = ProcessMonitor()
        self.process_monitor_started = False
        self.api_monitor_started = False
        self.last_alert_time = {}
        self.whitelist = self.load_whitelist()
        self.observer = None
        self.email_alerter = EmailAlerter(self.config)
        self.honeypot_manager = HoneypotManager()
        self.usb_guard = UsbGuardManager()

        # Anomaly detection state
        self.behavior_baseline = {
            'process_tree': defaultdict(int)
        }
        self.learning_mode = True
        self.learning_duration = int(self.config.get('ANOMALY', 'learning_duration', fallback=3600))
        self.anomaly_detection = self.config.getboolean('MONITORING', 'anomaly_detection', fallback=True)
        self.registry_monitor = RegistryMonitor(self)

        try:
            pythoncom.CoInitialize()
            self.wmi_conn = wmi.WMI()
            logging.info("WMI initialized successfully")
        except Exception as e:
            logging.warning(f"WMI initialization failed, using Windows API fallback: {str(e)}")

    @staticmethod
    def is_admin():
        """Check if the script is running with admin privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def create_default_config(self):
        """Create a default config.ini file"""
        default_config = """[MONITORING]
filesystem = true
processes = true
periodic_scans = true
process_check_interval = 5
scan_interval = 3600
anomaly_detection = true

[PATHS]
watch_paths = C:\\Windows\\System32;C:\\Windows\\SysWOW64
quarantine_dir = C:\\HIDS_Quarantine

[FILTERS]
whitelisted_paths = C:\\Windows\\Temp;AppData\\Local\\Temp
whitelisted_processes = svchost.exe,explorer.exe,Taskmgr.exe,dwm.exe,csrss.exe,lsass.exe,services.exe,winlogon.exe
scan_extensions = .exe,.dll,.ps1,.vbs,.js,.bat

[RESPONSE]
quarantine = true
kill_process = false

[ANOMALY]
learning_duration = 3600
late_night_hours = 23,0,1,2,3,4,5
suspicious_registry_keys = HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run,HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

[GUI]
start_minimized = false
refresh_interval = 1000
theme = dark
"""
        with open('config.ini', 'w') as f:
            f.write(default_config)
        logging.info("Created default config.ini file")
    
    def validate_config(self):
        """Validate configuration and log warnings for issues"""
        # Check required sections
        required_sections = ['MONITORING', 'PATHS', 'FILTERS', 'RESPONSE']
        for section in required_sections:
            if not self.config.has_section(section):
                logging.warning(f"Missing configuration section: {section}")
        
        # Validate watch paths exist
        if self.config.has_option('PATHS', 'watch_paths'):
            paths = self.config.get('PATHS', 'watch_paths').split(';')
            for path in paths:
                if not os.path.exists(path.strip()):
                    logging.warning(f"Watch path does not exist: {path}")
        
        # Validate quarantine directory
        quarantine_dir = self.config.get('PATHS', 'quarantine_dir', fallback='C:\\HIDS_Quarantine')
        try:
            os.makedirs(quarantine_dir, exist_ok=True)
            # Test write permissions
            test_file = os.path.join(quarantine_dir, '.test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except Exception as e:
            logging.error(f"Quarantine directory not writable: {quarantine_dir} - {str(e)}")
    
    def build_baseline(self):
        logging.info("Building behavior baseline for anomaly detection...")
        start_time = time.time()
        while time.time() - start_time < self.learning_duration and not self.shutdown_event.is_set():
            processes = self.process_monitor.get_process_list()
            for pid in processes:
                name = self.process_monitor.get_process_name(pid)
                parent_pid = self.process_monitor.get_parent_pid(pid)
                parent_name = self.process_monitor.get_process_name(parent_pid)
                key = f"{parent_name}->{name}"
                self.behavior_baseline['process_tree'][key] += 1
            time.sleep(5)
        self.learning_mode = False
        logging.info(f"Baseline established with {len(self.behavior_baseline['process_tree'])} process relationships")

    def load_whitelist(self):
        whitelist = {
            'paths': [
                r'C:\\Windows\\System32\\DriverStore\\',
                r'C:\\Windows\\Temp\\',
                r'AppData\\Local\\Temp\\',
                r'\\$Recycle.Bin\\',
                r'\\AMD\\EeuDumps\\',
                r'\\Microsoft\\Edge\\User Data\\',
                r'\\Spotify\\Users\\',
                r'\\Microsoft\\Protect\\',
                r'C:\\Windows\\System32\\config\\',
                r'C:\\Windows\\System32\\winevt\\Logs\\',
                r'C:\\Windows\\System32\\wbem\\',
                r'C:\\Windows\\System32\\en-US\\',
                r'C:\\Windows\\System32\\drivers\\en-US\\'
            ],
            'processes': [
                'svchost.exe',
                'explorer.exe',
                'notepad.exe',
                'chrome.exe',
                'msedge.exe',
                'winlogon.exe',
                'Taskmgr.exe',
                'dwm.exe',
                'csrss.exe',
                'lsass.exe'
            ],
            'extensions': ['.exe', '.dll', '.ps1', '.vbs', '.js', '.bat', '.cmd'],
            'files': []
        }
        if self.config.has_option('FILTERS', 'whitelisted_paths'):
            whitelist['paths'].extend(
                [x.strip() for x in self.config.get('FILTERS', 'whitelisted_paths').split(';')]
            )
        if self.config.has_option('FILTERS', 'whitelisted_processes'):
            whitelist['processes'].extend(
                [x.strip() for x in self.config.get('FILTERS', 'whitelisted_processes').split(',')]
            )
        if self.config.has_option('FILTERS', 'scan_extensions'):
            whitelist['extensions'] = [
                x.strip() for x in self.config.get('FILTERS', 'scan_extensions').split(',')
            ]
        # Load individually whitelisted files from [WHITELIST] section
        if self.config.has_option('WHITELIST', 'files'):
            whitelist['files'] = [
                os.path.normpath(f.strip()).lower()
                for f in self.config.get('WHITELIST', 'files').split(',')
                if f.strip()
            ]
        return whitelist

    def is_whitelisted(self, path_or_name):
        if not path_or_name:
            return False
        path_or_name = path_or_name.lower()
        # Check individually whitelisted files (exact path match)
        normalized = os.path.normpath(path_or_name)
        if normalized in self.whitelist.get('files', []):
            return True
        if any(re.search(rf'\\{p.lower()}$', path_or_name) or
               path_or_name.endswith(p.lower()) for p in self.whitelist['processes']):
            return True
        if any(p.lower() in path_or_name for p in self.whitelist['paths']):
            return True
        return False

    def should_scan_file(self, file_path):
        if not file_path:
            logging.debug(f"should_scan_file: empty file_path")
            return False
        file_path_lower = file_path.lower()
        if self.is_whitelisted(file_path_lower):
            logging.debug(f"should_scan_file: {file_path} is whitelisted")
            return False
        if not any(file_path_lower.endswith(ext.lower()) for ext in self.whitelist['extensions']):
            logging.debug(f"should_scan_file: {file_path} extension not in scan list. Extensions: {self.whitelist['extensions']}")
            return False
        # Check last alert time using lowercase path
        if file_path_lower in self.last_alert_time:
            if time.time() - self.last_alert_time[file_path_lower] < 60:
                logging.debug(f"should_scan_file: {file_path} scanned recently, skipping")
                return False
        logging.debug(f"should_scan_file: {file_path} passed all checks, will scan")
        return True

    def start_monitoring(self):
        if self.monitoring_active:
            return False
        self.monitoring_active = True
        logging.info("Starting HIDS monitoring")
        if self.config.getboolean('MONITORING', 'filesystem', fallback=True):
            self.start_file_monitor()
        if self.config.getboolean('MONITORING', 'processes', fallback=True):
            if self.wmi_conn:
                # Test WMI connectivity before attempting to use it
                try:
                    # Quick test to verify Win32_Process is accessible
                    test_query = self.wmi_conn.Win32_Process()
                    list(test_query)[:1]  # Try to access at least one process
                    self.start_wmi_process_monitor()
                except Exception as e:
                    logging.warning(f"WMI test failed: {str(e)}, falling back to Windows API monitor")
                    self.start_api_process_monitor()
            else:
                self.start_api_process_monitor()
        if self.config.getboolean('MONITORING', 'periodic_scans', fallback=True):
            self.start_periodic_scans()
        # Start honeypot access monitor (atime polling detects file reads)
        self.honeypot_manager.start_access_monitor(self.on_honeypot_triggered)
        # Also watch any already-existing honeypot directories
        for hp in self.honeypot_manager.get_all():
            self.schedule_honeypot_directory(hp.get('directory', ''))
        # Start USB Device Guard
        self.usb_guard.start(hids=self)
        return True
    
    def stop_monitoring(self):
        if not self.monitoring_active:
            return False
        self.monitoring_active = False
        logging.info("Stopping HIDS monitoring")
        self.honeypot_manager.stop_access_monitor()
        self.usb_guard.stop()
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=5)
                if self.observer.is_alive():
                    logging.warning("File system observer did not stop cleanly")
            except Exception as e:
                logging.error(f"Error stopping observer: {str(e)}")
        return True

    def on_usb_inserted(self, drive: str, label: str, findings: list, threat_count: int):
        """Called by UsbGuardManager when a USB is inserted and scanned."""
        if threat_count > 0:
            msg = (
                f"🔌 USB THREAT DETECTED: Drive {drive} ('{label}') — "
                f"{threat_count} threat(s) found during scan!"
            )
            logging.warning(msg)
            # Only log to activities when there are actual threats
            with self.activities_lock:
                self.suspicious_activities.append({
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'type': 'threat',
                    'severity': 'critical',
                    'message': msg,
                    'usb': True,
                    'drive': drive,
                    'label': label,
                    'threat_count': threat_count,
                })
            try:
                detail_lines = '\n'.join(
                    f"  - [{f['severity'].upper()}] {f['file']}: {f['rule']}"
                    for f in findings[:15]
                )
                self.email_alerter.send_alert(
                    subject=f'🔌 HIDS USB Threat Detected on {drive}',
                    body=(
                        f'A USB drive was inserted and threats were found!\n\n'
                        f'Drive: {drive} ("{label}")\n'
                        f'Threats: {threat_count}\n\n'
                        f'Findings:\n{detail_lines}'
                    )
                )
            except Exception as e:
                logging.error(f"Failed to send USB alert email: {e}")
        else:
            # Clean USB — log info only, do NOT add to suspicious_activities
            logging.info(f"🔌 USB Drive connected: {drive} ('{label}') — No threats detected.")
    
    def shutdown(self):
        """Clean shutdown of all monitoring threads and resources"""
        logging.info("Initiating HIDS shutdown...")
        self.shutdown_event.set()
        self.stop_monitoring()
        
        # Give threads time to finish
        time.sleep(2)
        
        # Close WMI connection if exists
        if self.wmi_conn:
            try:
                pythoncom.CoUninitialize()
            except Exception as e:
                logging.debug(f"Error during COM cleanup: {str(e)}")
        
        logging.info("HIDS shutdown complete")

    def clear_logs(self):
        with self.activities_lock:
            self.suspicious_activities = []
        logging.info("Cleared suspicious activities log")
        return True

    def schedule_honeypot_directory(self, directory: str):
        """Dynamically add a honeypot directory to the running watchdog observer."""
        if not directory or not os.path.isdir(directory):
            return
        if self.observer and self.observer.is_alive():
            try:
                event_handler = HIDSFileSystemEventHandler(self)
                self.observer.schedule(event_handler, directory, recursive=False)
                logging.info(f"Honeypot directory added to watch: {directory}")
            except Exception as e:
                logging.warning(f"Could not watch honeypot dir {directory}: {e}")

    def start_file_monitor(self):
        paths = self.config.get('PATHS', 'watch_paths', fallback="C:\\Windows\\System32;C:\\Windows\\SysWOW64").split(';')
        event_handler = HIDSFileSystemEventHandler(self)
        self.observer = Observer()
        for path in paths:
            if os.path.exists(path):
                try:
                    self.observer.schedule(event_handler, path, recursive=True)
                    logging.info(f"Monitoring path: {path}")
                except Exception as e:
                    logging.error(f"Failed to monitor path {path}: {str(e)}")
        try:
            self.observer.start()
            logging.info("File system monitoring started")
        except Exception as e:
            logging.error(f"Failed to start file monitor: {str(e)}")

    def on_file_modified(self, event):
        try:
            if not event.is_directory:
                logging.info(f"File modified event detected: {event.src_path}")
                # Check honeypot FIRST — always alert regardless of whitelist
                if self.honeypot_manager.is_honeypot(event.src_path):
                    self.on_honeypot_triggered(event.src_path, 'modified')
                    return
                if self.should_scan_file(event.src_path):
                    logging.info(f"Scanning modified file: {event.src_path}")
                    self.analyze_file(event.src_path, "modified")
                else:
                    logging.debug(f"Skipping file (not in scan list): {event.src_path}")
        except Exception as e:
            logging.error(f"Error in on_file_modified: {str(e)}")

    def on_file_created(self, event):
        try:
            if not event.is_directory:
                logging.info(f"File created event detected: {event.src_path}")
                # Check honeypot FIRST
                if self.honeypot_manager.is_honeypot(event.src_path):
                    self.on_honeypot_triggered(event.src_path, 'created')
                    return
                if self.should_scan_file(event.src_path):
                    logging.info(f"Scanning created file: {event.src_path}")
                    # Small delay to ensure file is fully written
                    time.sleep(0.1)
                    self.analyze_file(event.src_path, "created")
                else:
                    logging.debug(f"Skipping file (not in scan list): {event.src_path}")
        except Exception as e:
            logging.error(f"Error in on_file_created: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())

    def on_honeypot_triggered(self, filepath: str, event_type: str):
        """Handle a honeypot access event — fires CRITICAL alert and email."""
        # Cooldown: suppress duplicate events for the same file within 30 seconds
        cooldown_key = f'honeypot_{filepath.lower()}'
        now = time.time()
        last_trigger = self.last_alert_time.get(cooldown_key, 0)
        if now - last_trigger < 30:
            logging.debug(f"Honeypot cooldown active for {filepath}, skipping duplicate event")
            return
        self.last_alert_time[cooldown_key] = now

        self.honeypot_manager.record_access(filepath, event_type)
        filename = os.path.basename(filepath)
        alert_msg = (
            f"🍯 HONEYPOT TRIGGERED: Decoy file '{filename}' was {event_type}! "
            f"Possible intrusion detected at {filepath}"
        )
        logging.warning(alert_msg)
        with self.activities_lock:
            self.suspicious_activities.append({
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'type': 'threat',
                'severity': 'critical',
                'message': alert_msg,
                'file_path': filepath,
                'honeypot': True,
            })
        # Send email alert
        try:
            self.email_alerter.send_alert(
                subject=f'🍯 HIDS Honeypot Triggered: {filename}',
                body=(
                    f'A honeypot decoy file was accessed on your system!\n\n'
                    f'File: {filepath}\n'
                    f'Event: {event_type}\n'
                    f'Time: {time.strftime("%Y-%m-%d %H:%M:%S")}\n\n'
                    f'This may indicate an active intrusion attempt.'
                )
            )
        except Exception as e:
            logging.error(f"Failed to send honeypot email alert: {e}")

    def start_wmi_process_monitor(self):
        def wmi_monitor():
            pythoncom.CoInitialize()  # COM initialization for this thread
            try:
                # Validate WMI connection
                if not self.wmi_conn:
                    logging.warning("WMI connection not available, falling back to API monitor")
                    if not self.api_monitor_started:
                        self.start_api_process_monitor()
                    return
                
                interval = int(self.config.get('MONITORING', 'process_check_interval', fallback=5))
                
                # Try to create the watcher
                try:
                    watcher = self.wmi_conn.Win32_Process.watch_for(
                        notification_type="Creation",
                        delay_secs=interval
                    )
                except Exception as watcher_error:
                    logging.error(f"Failed to create WMI watcher: {str(watcher_error)}")
                    logging.info("Falling back to Windows API process monitor")
                    if not self.api_monitor_started:
                        self.start_api_process_monitor()
                    return
                
                logging.info("WMI process monitor started")
                self.process_monitor_started = True
                self.api_monitor_started = False  # WMI is active, API is not
                
                while self.monitoring_active and not self.shutdown_event.is_set():
                    try:
                        new_process = watcher()
                        if self.shutdown_event.is_set():
                            break
                        if new_process and not self.is_whitelisted(new_process.Name):
                            self.analyze_process(new_process.Name, new_process.ProcessId, new_process.ExecutablePath)
                    except pythoncom.com_error as e:
                        logging.error(f"WMI monitor error: {str(e)}")
                        time.sleep(interval)
                    except Exception as e:
                        logging.error(f"WMI watcher error: {str(e)}")
                        # If watcher fails during operation, fall back to API method
                        logging.info("Falling back to Windows API process monitor")
                        if not self.api_monitor_started:
                            self.start_api_process_monitor()
                        break
                logging.info("WMI process monitor stopped")
            except Exception as e:
                logging.error(f"Unexpected WMI error: {str(e)}")
                if not self.api_monitor_started:
                    logging.info("Falling back to Windows API process monitor")
                    self.start_api_process_monitor()
            finally:
                pythoncom.CoUninitialize()
        threading.Thread(target=wmi_monitor, daemon=True, name="WMIProcessMonitor").start()

    def start_api_process_monitor(self):
        def api_monitor():
            interval = int(self.config.get('MONITORING', 'process_check_interval', fallback=5))
            logging.info("Windows API process monitor started")
            self.process_monitor.last_processes = self.process_monitor.get_process_list()
            while self.monitoring_active and not self.shutdown_event.is_set():
                try:
                    new_pids = self.process_monitor.detect_new_processes()
                    for pid in new_pids:
                        if self.shutdown_event.is_set():
                            break
                        name = self.process_monitor.get_process_name(pid)
                        if name and not self.is_whitelisted(name):
                            self.analyze_process(name, pid, None)
                    time.sleep(interval)
                except Exception as e:
                    logging.error(f"API monitor error: {str(e)}")
                    time.sleep(interval)
            logging.info("Windows API process monitor stopped")
        self.api_monitor_started = True
        self.process_monitor_started = True
        threading.Thread(target=api_monitor, daemon=True, name="APIProcessMonitor").start()

    def analyze_process(self, name, pid, path):
        try:
            proc_info = f"{name}|||{path if path else 'unknown'}".encode()
            matches = self.rules.match(data=proc_info)
            # Anomaly detection
            if self.anomaly_detection and not self.learning_mode:
                self.detect_process_anomalies(name, pid, path)
            if matches:
                match_names = [str(m) for m in matches]
                alert_msg = f"SUSPICIOUS PROCESS: {name} (PID: {pid}) - Matches: {', '.join(match_names)}"
                logging.warning(alert_msg)
                with self.activities_lock:
                    self.suspicious_activities.append({
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'message': alert_msg
                    })
                # Send email alert
                self.email_alerter.send_process_alert(name, pid, match_names)
                if self.config.getboolean('RESPONSE', 'kill_process', fallback=False):
                    self.terminate_process(pid)
        except Exception as e:
            logging.error(f"Error analyzing process {name}: {str(e)}")

    def detect_process_anomalies(self, name, pid, path):
        parent_pid = self.process_monitor.get_parent_pid(pid)
        parent_name = self.process_monitor.get_process_name(parent_pid)
        process_key = f"{parent_name}->{name}"
        # Process tree anomaly
        if not self.behavior_baseline['process_tree'].get(process_key, 0):
            self.trigger_alert(f"ANOMALOUS PROCESS TREE: {process_key}")
        # Temporal anomaly
        current_hour = time.localtime().tm_hour
        late_hours = [int(x) for x in self.config.get('ANOMALY', 'late_night_hours', fallback="23,0,1,2,3,4,5").split(',')]
        if current_hour in late_hours:
            self.trigger_alert(f"LATE-NIGHT PROCESS: {name} @ {current_hour}:00")

    def trigger_alert(self, message):
        logging.warning(message)
        with self.activities_lock:
            self.suspicious_activities.append({
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'message': message
            })

    def analyze_file(self, file_path, action):
        try:
            logging.info(f"Analyzing file: {file_path} (action: {action})")
            if not os.path.exists(file_path):
                logging.warning(f"File does not exist: {file_path}")
                return
            matches = self.rules.match(filepath=file_path)
            logging.info(f"YARA match result for {file_path}: {matches} (type: {type(matches)}, len: {len(matches) if matches else 0})")
            if matches:
                self.last_alert_time[file_path.lower()] = time.time()
                match_names = [str(m.rule) if hasattr(m, 'rule') else str(m) for m in matches]
                alert_msg = f"SUSPICIOUS FILE {action}: {file_path} - Matches: {', '.join(match_names)}"
                logging.warning(alert_msg)
                # Send email alert
                self.email_alerter.send_threat_alert(file_path, action, match_names)
                with self.activities_lock:
                    # If a stale 'deleted' or 'marked_safe' entry exists for this file,
                    # update it in-place to reset it to active (preserves history)
                    existing = next(
                        (a for a in self.suspicious_activities
                         if a.get('file') == file_path and a.get('action') in ('deleted', 'marked_safe')),
                        None
                    )
                    if existing:
                        existing['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
                        existing['message'] = alert_msg
                        existing.pop('action', None)
                        existing.pop('action_time', None)
                    else:
                        self.suspicious_activities.append({
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                            'message': alert_msg,
                            'file': file_path
                        })
                if self.config.getboolean('RESPONSE', 'quarantine', fallback=False):
                    self.quarantine_file(file_path)
            else:
                logging.info(f"No YARA matches for file: {file_path}")
        except yara.Error as e:
            logging.error(f"YARA error analyzing {file_path}: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())

    def quarantine_file(self, file_path):
        quarantine_dir = self.config.get('PATHS', 'quarantine_dir', fallback="C:\\HIDS_Quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        try:
            dest = os.path.join(quarantine_dir, os.path.basename(file_path))
            if os.path.exists(dest):
                dest = dest + "_" + str(int(time.time()))
            os.rename(file_path, dest)
            logging.warning(f"QUARANTINED file {file_path} to {dest}")
        except Exception as e:
            logging.error(f"Failed to quarantine {file_path}: {str(e)}")

    def terminate_process(self, pid):
        """Terminate a process using Windows API"""
        try:
            PROCESS_TERMINATE = 0x0001
            hProcess = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if hProcess:
                try:
                    if ctypes.windll.kernel32.TerminateProcess(hProcess, 1):
                        logging.warning(f"TERMINATED process with PID: {pid}")
                    else:
                        logging.error(f"Failed to terminate process {pid}: TerminateProcess returned False")
                finally:
                    ctypes.windll.kernel32.CloseHandle(hProcess)
            else:
                logging.error(f"Failed to terminate process {pid}: Could not open process")
        except Exception as e:
            logging.error(f"Failed to terminate process {pid}: {str(e)}")

    def start_periodic_scans(self):
        def scan_job():
            interval = int(self.config.get('MONITORING', 'scan_interval', fallback=3600))
            while self.monitoring_active and not self.shutdown_event.is_set():
                logging.info("Starting periodic scan")
                self.scan_critical_files()
                # Use wait instead of sleep to allow graceful shutdown
                self.shutdown_event.wait(interval)
            logging.info("Periodic scan stopped")
        scan_thread = threading.Thread(target=scan_job, daemon=True, name="PeriodicScan")
        scan_thread.start()

    def scan_critical_files(self):
        critical_files = [
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "C:\\Windows\\System32\\wscript.exe",
            "C:\\Windows\\System32\\cscript.exe",
            "C:\\Windows\\System32\\schtasks.exe",
            "C:\\Windows\\System32\\regsvr32.exe"
        ]
        for file in critical_files:
            if os.path.exists(file) and not self.is_whitelisted(file):
                self.analyze_file(file, "periodic scan")

    def delete_file(self, file_path):
        """
        Permanently delete a file and remove its activity log entry
        
        Args:
            file_path: Path to file to delete
            
        Returns:
            dict with success status and message
        """
        try:
            deleted = False
            msg = ""
            
            if os.path.exists(file_path):
                os.remove(file_path)
                msg = f"File deleted: {file_path}"
                logging.warning(msg)
                deleted = True
            else:
                # Check if file is in quarantine
                quarantine_dir = self.config.get('PATHS', 'quarantine_dir', fallback="C:\\HIDS_Quarantine")
                basename = os.path.basename(file_path)
                
                # Search for files matching the basename in quarantine
                if os.path.exists(quarantine_dir):
                    for qfile in os.listdir(quarantine_dir):
                        if qfile.startswith(basename):
                            qpath = os.path.join(quarantine_dir, qfile)
                            os.remove(qpath)
                            msg = f"File deleted from quarantine: {basename} (was quarantined as {qfile})"
                            logging.warning(msg)
                            deleted = True
                            break
            
            if deleted:
                # Mark the activity log entry as deleted instead of removing it
                with self.activities_lock:
                    for activity in self.suspicious_activities:
                        if activity.get('file') == file_path:
                            activity['action'] = 'deleted'
                            activity['action_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
                # Clear cooldown so the file can be re-detected immediately if re-created
                self.last_alert_time.pop(file_path.lower(), None)
                return {'success': True, 'message': msg}
            else:
                return {'success': False, 'message': f'File not found: {file_path}'}
        except Exception as e:
            msg = f"Failed to delete {file_path}: {str(e)}"
            logging.error(msg)
            return {'success': False, 'message': msg}
    
    def mark_as_safe(self, file_path):
        """
        Mark a file as safe by adding to whitelist and restoring if quarantined
        
        Args:
            file_path: Path to file to mark as safe
            
        Returns:
            dict with success status and message
        """
        try:
            # Add to whitelist in config
            if not self.config.has_section('WHITELIST'):
                self.config.add_section('WHITELIST')
            whitelist_files = self.config.get('WHITELIST', 'files', fallback='').split(',')
            whitelist_files = [f.strip() for f in whitelist_files if f.strip()]
            
            # Add normalized path
            normalized_path = os.path.normpath(file_path).lower()
            if normalized_path not in [os.path.normpath(f).lower() for f in whitelist_files]:
                whitelist_files.append(file_path)
                self.config.set('WHITELIST', 'files', ','.join(whitelist_files))
                
                # Save to config file
                with open('config.ini', 'w') as f:
                    self.config.write(f)
                
                # Reload whitelist
                self.whitelist = self.load_whitelist()
            
            # Check if file is in quarantine and restore it
            quarantine_dir = self.config.get('PATHS', 'quarantine_dir', fallback="C:\\HIDS_Quarantine")
            basename = os.path.basename(file_path)
            
            restored = False
            if os.path.exists(quarantine_dir):
                for qfile in os.listdir(quarantine_dir):
                    if qfile.startswith(basename):
                        quarantined_path = os.path.join(quarantine_dir, qfile)
                        # Restore to original location if it doesn't exist
                        if not os.path.exists(file_path):
                            os.rename(quarantined_path, file_path)
                            restored = True
                            break
            
            msg = f"File marked as safe: {file_path}"
            if restored:
                msg += " (restored from quarantine)"
            
            logging.info(msg)
            # Mark the existing activity log entry as safe instead of creating a new one
            # Clear honeypot cooldown so the file can be re-detected if accessed again later
            cooldown_key = f'honeypot_{file_path.lower()}'
            self.last_alert_time.pop(cooldown_key, None)

            with self.activities_lock:
                found = False
                # First pass: find the most recent UNACTIONED entry (active threat)
                for activity in reversed(self.suspicious_activities):
                    match = (activity.get('file') == file_path or
                             activity.get('file_path') == file_path)
                    if match and not activity.get('action'):
                        activity['action'] = 'marked_safe'
                        activity['action_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
                        found = True
                        break
                # Second pass fallback: mark the most recent entry regardless
                if not found:
                    for activity in reversed(self.suspicious_activities):
                        match = (activity.get('file') == file_path or
                                 activity.get('file_path') == file_path)
                        if match:
                            activity['action'] = 'marked_safe'
                            activity['action_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
                            found = True
                            break
                
                # If no matching activity found, create a new one
                if not found:
                    self.suspicious_activities.append({
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'message': msg,
                        'file': file_path,
                        'action': 'marked_safe'
                    })
            
            return {'success': True, 'message': msg}
        except Exception as e:
            error_msg = f"Failed to mark as safe {file_path}: {str(e)}"
            logging.error(error_msg)
            return {'success': False, 'message': error_msg}

    def apply_activity_action(self, timestamp: str, message: str, action: str):
        """
        Apply an action (like 'deleted' or 'marked_safe') to a specific log entry.
        Designed for entries without file paths (e.g., USB Threats).
        """
        try:
            with self.activities_lock:
                for activity in reversed(self.suspicious_activities):
                    if activity.get('timestamp') == timestamp and activity.get('message') == message:
                        activity['action'] = action
                        activity['action_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
                        status = "deleted" if action == "deleted" else "marked as safe"
                        return {'success': True, 'message': f'Log entry {status}.'}
                
            return {'success': False, 'message': 'Log entry not found.'}
        except Exception as e:
            logging.error(f"Failed to apply action {action} to log: {str(e)}")
            return {'success': False, 'message': str(e)}
    
    def get_quarantined_files(self):
        """
        Get list of all quarantined files with metadata
        
        Returns:
            list of dicts containing file info
        """
        quarantine_dir = self.config.get('PATHS', 'quarantine_dir', fallback="C:\\HIDS_Quarantine")
        files = []
        
        try:
            if os.path.exists(quarantine_dir):
                for filename in os.listdir(quarantine_dir):
                    filepath = os.path.join(quarantine_dir, filename)
                    if os.path.isfile(filepath):
                        stat = os.stat(filepath)
                        files.append({
                            'filename': filename,
                            'path': filepath,
                            'size': stat.st_size,
                            'quarantined_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
                        })
            return files
        except Exception as e:
            logging.error(f"Failed to get quarantined files: {str(e)}")
            return []
    
    def restore_from_quarantine(self, quarantined_path, original_path=None):
        """
        Restore a file from quarantine to its original or specified location
        
        Args:
            quarantined_path: Path to quarantined file
            original_path: Optional path to restore to (if None, tries to infer from filename)
            
        Returns:
            dict with success status and message
        """
        try:
            if not os.path.exists(quarantined_path):
                return {'success': False, 'message': 'Quarantined file not found'}
            
            # If no original path provided, restore to a safe default location
            if not original_path:
                # Extract base filename (remove timestamp suffix if present)
                basename = os.path.basename(quarantined_path)
                if '_' in basename:
                    parts = basename.rsplit('_', 1)
                    if parts[1].isdigit():
                        basename = parts[0]
                
                # Restore to user's Downloads folder as a safe default
                import os.path
                original_path = os.path.join(os.path.expanduser('~'), 'Downloads', basename)
            
            # Make sure destination directory exists
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            
            # Restore file
            os.rename(quarantined_path, original_path)
            
            msg = f"File restored from quarantine: {original_path}"
            logging.info(msg)
            with self.activities_lock:
                self.suspicious_activities.append({
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'message': msg,
                    'action': 'restored'
                })
            
            return {'success': True, 'message': msg, 'restored_path': original_path}
        except Exception as e:
            error_msg = f"Failed to restore {quarantined_path}: {str(e)}"
            logging.error(error_msg)
            return {'success': False, 'message': error_msg}
    
    def get_status(self):
        paths = self.config.get('PATHS', 'watch_paths', fallback="C:\\Windows\\System32;C:\\Windows\\SysWOW64").split(';')
        with self.activities_lock:
            recent_activities = self.suspicious_activities[-20:]
        return {
            'monitoring': self.monitoring_active,
            'paths': '\n'.join(paths),
            'activities': recent_activities
        }
