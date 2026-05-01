Hybrid Host Intrusion Detection System (HIDS)
Overview

The Hybrid Host Intrusion Detection System (HIDS) is a security monitoring solution designed to detect suspicious activities on a host machine in real time. It combines multiple monitoring techniques such as USB device tracking, file integrity checking, and email-based alert notifications to improve system protection against unauthorized access and malicious behavior.

This project demonstrates practical implementation of host-level security monitoring using Python.

Features
Real-time USB device detection
Unauthorized device access alerts
File activity monitoring
Email notification system for detected threats
Logging of suspicious activities
Lightweight and efficient monitoring
Modular architecture for easy extension
System Architecture

The system consists of the following modules:

1. USB Guard Module
Detects newly connected USB devices
Identifies unauthorized storage access
Logs device details
Triggers alerts when suspicious activity occurs
2. File Monitoring Module
Tracks changes in selected directories
Detects unauthorized modifications
Maintains activity logs
3. Email Alert Module
Sends instant alerts when threats are detected
Uses SMTP protocol for notifications
Notifies administrator in real time
4. Logging System
Records all detected events
Maintains activity history for analysis
Technologies Used
Python
OS module
smtplib
threading
logging
watchdog (optional if used for file monitoring)
