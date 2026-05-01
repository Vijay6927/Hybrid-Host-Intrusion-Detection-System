"""
Monitoring Classes for HIDS
Contains ProcessMonitor, RegistryMonitor, and FileSystemEventHandler
"""

import os
import time
import ctypes
import logging
import pythoncom
import wmi
from ctypes import wintypes
from watchdog.events import FileSystemEventHandler


class ProcessMonitor:
    """Monitor Windows processes using Windows API"""
    
    def __init__(self):
        self.PROCESS_QUERY_INFORMATION = 0x0400
        self.PROCESS_VM_READ = 0x0010
        self.MAX_PROCESSES = 1024
        self.last_processes = set()

    def get_process_list(self):
        """Get current running processes using Windows API"""
        process_ids = (wintypes.DWORD * self.MAX_PROCESSES)()
        cb_needed = wintypes.DWORD()
        if not ctypes.windll.psapi.EnumProcesses(
            ctypes.byref(process_ids),
            ctypes.sizeof(process_ids),
            ctypes.byref(cb_needed)
        ):
            logging.error("Failed to enumerate processes")
            return set()
        count = cb_needed.value // ctypes.sizeof(wintypes.DWORD)
        return set(process_ids[:count])

    def get_process_name(self, pid):
        """Get process name by PID using Windows API"""
        hProcess = ctypes.windll.kernel32.OpenProcess(
            self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ,
            False, pid)
        if hProcess:
            try:
                buf = ctypes.create_string_buffer(1024)
                size = ctypes.c_ulong(ctypes.sizeof(buf))
                if ctypes.windll.psapi.GetModuleBaseNameA(
                    hProcess, None, ctypes.byref(buf), ctypes.byref(size)):
                    return buf.value.decode('utf-8')
            finally:
                ctypes.windll.kernel32.CloseHandle(hProcess)
        return None

    def detect_new_processes(self):
        """Detect newly created processes"""
        current_processes = self.get_process_list()
        new_processes = current_processes - self.last_processes
        self.last_processes = current_processes
        return new_processes

    def get_parent_pid(self, pid):
        """Get parent process ID using Windows API"""
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260)
            ]
        TH32CS_SNAPPROCESS = 0x00000002
        hSnapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        parent_pid = None
        if ctypes.windll.kernel32.Process32First(hSnapshot, ctypes.byref(entry)):
            while True:
                if entry.th32ProcessID == pid:
                    parent_pid = entry.th32ParentProcessID
                    break
                if not ctypes.windll.kernel32.Process32Next(hSnapshot, ctypes.byref(entry)):
                    break
        ctypes.windll.kernel32.CloseHandle(hSnapshot)
        return parent_pid


class RegistryMonitor:
    """Monitor Windows registry changes (currently disabled)"""
    
    def __init__(self, hids):
        self.hids = hids
        self.suspicious_keys = []
        if hids.config.has_option('ANOMALY', 'suspicious_registry_keys'):
            self.suspicious_keys = [
                x.strip() for x in hids.config.get('ANOMALY', 'suspicious_registry_keys').split(',')
            ]

    def monitor_registry(self):
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            watcher = c.Win32_RegistryKey.watch_for(
                notification_type="Modification",
                delay_secs=5
            )
            while self.hids.monitoring_active and not self.hids.shutdown_event.is_set():
                try:
                    change = watcher()
                    if change.Name in self.suspicious_keys:
                        self.analyze_reg_change(change)
                except Exception as e:
                    logging.error(f"Registry monitor error: {str(e)}")
            logging.info("Registry monitor stopped")
        finally:
            pythoncom.CoUninitialize()

    def analyze_reg_change(self, change):
        alert_msg = f"SUSPICIOUS REGISTRY MODIFICATION: {change.Name}"
        logging.warning(alert_msg)
        with self.hids.activities_lock:
            self.hids.suspicious_activities.append({
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'message': alert_msg
            })


class HIDSFileSystemEventHandler(FileSystemEventHandler):
    """Handle file system events for HIDS"""
    
    def __init__(self, hids):
        self.hids = hids

    def on_modified(self, event):
        if not event.is_directory:
            self.hids.on_file_modified(event)

    def on_created(self, event):
        if not event.is_directory:
            self.hids.on_file_created(event)
