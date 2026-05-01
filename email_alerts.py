"""
Email Alert Module for HIDS
Sends email notifications when threats are detected
"""

import smtplib
import logging
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


class EmailAlerter:
    """Handles sending email alerts for HIDS threat detections"""

    def __init__(self, config):
        self.config = config
        self._lock = threading.Lock()

    def is_enabled(self):
        """Check if email alerts are enabled"""
        return self.config.getboolean('EMAIL', 'enabled', fallback=False)

    def get_settings(self):
        """Return current email settings (password masked)"""
        return {
            'enabled': self.is_enabled(),
            'recipient_email': self.config.get('EMAIL', 'recipient_email', fallback=''),
            'smtp_host': self.config.get('EMAIL', 'smtp_host', fallback='smtp.gmail.com'),
            'smtp_port': int(self.config.get('EMAIL', 'smtp_port', fallback='587')),
            'sender_email': self.config.get('EMAIL', 'sender_email', fallback=''),
            'sender_password': '***' if self.config.get('EMAIL', 'sender_password', fallback='') else '',
        }

    def send_alert(self, subject, body, is_test=False):
        """
        Send an email alert in a background thread.
        Returns (success, message) tuple for test emails, None for background sends.
        """
        if not self.is_enabled() and not is_test:
            return

        recipient = self.config.get('EMAIL', 'recipient_email', fallback='')
        sender = self.config.get('EMAIL', 'sender_email', fallback='')
        password = self.config.get('EMAIL', 'sender_password', fallback='')
        smtp_host = self.config.get('EMAIL', 'smtp_host', fallback='smtp.gmail.com')
        smtp_port = int(self.config.get('EMAIL', 'smtp_port', fallback='587'))

        if not all([recipient, sender, password]):
            msg = "Email alert skipped: missing recipient, sender, or password in config"
            logging.warning(msg)
            if is_test:
                return False, "Missing email configuration. Please fill in all fields."
            return

        if is_test:
            return self._send_email(smtp_host, smtp_port, sender, password, recipient, subject, body)
        else:
            # Send in background thread so it never blocks detection
            thread = threading.Thread(
                target=self._send_email,
                args=(smtp_host, smtp_port, sender, password, recipient, subject, body),
                daemon=True
            )
            thread.start()

    def _send_email(self, smtp_host, smtp_port, sender, password, recipient, subject, body):
        """Internal: actually send the email via SMTP"""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"HIDS Security Alert <{sender}>"
            msg['To'] = recipient

            # Plain text version
            text_part = MIMEText(body, 'plain')

            # HTML version
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: #1e1b4b; border-radius: 12px; padding: 24px; border: 1px solid #ef4444;">
                    <div style="display: flex; align-items: center; margin-bottom: 20px;">
                        <span style="font-size: 28px; margin-right: 12px;">🛡️</span>
                        <h2 style="margin: 0; color: #ef4444;">HIDS Security Alert</h2>
                    </div>
                    <div style="background: rgba(239,68,68,0.1); border-left: 4px solid #ef4444; padding: 16px; border-radius: 4px; margin-bottom: 20px;">
                        <pre style="margin: 0; font-family: monospace; font-size: 14px; color: #fbbf24; white-space: pre-wrap;">{body}</pre>
                    </div>
                    <p style="color: #94a3b8; font-size: 12px; margin: 0;">
                        Detected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                        This is an automated alert from your Host Intrusion Detection System.
                    </p>
                </div>
            </body>
            </html>
            """
            html_part = MIMEText(html_body, 'html')

            msg.attach(text_part)
            msg.attach(html_part)

            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.login(sender, password)
                server.sendmail(sender, recipient, msg.as_string())

            logging.info(f"Email alert sent to {recipient}: {subject}")
            return True, f"Test email sent successfully to {recipient}!"

        except smtplib.SMTPAuthenticationError:
            msg = "Email authentication failed. Check your sender email and app password."
            logging.error(f"Email alert failed: {msg}")
            return False, msg
        except smtplib.SMTPConnectError:
            msg = f"Could not connect to SMTP server {smtp_host}:{smtp_port}. Check host/port."
            logging.error(f"Email alert failed: {msg}")
            return False, msg
        except Exception as e:
            msg = f"Failed to send email: {str(e)}"
            logging.error(msg)
            return False, msg

    def send_threat_alert(self, file_path, threat_type, matches):
        """Convenience method for file threat alerts"""
        subject = f"🚨 HIDS Alert: Suspicious File Detected"
        body = (
            f"THREAT DETECTED\n"
            f"{'='*40}\n"
            f"File:     {file_path}\n"
            f"Type:     {threat_type}\n"
            f"Matches:  {', '.join(matches)}\n"
            f"Time:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"{'='*40}\n\n"
            f"Action Required: Review this file immediately.\n"
            f"Log in to your HIDS dashboard for details."
        )
        self.send_alert(subject, body)

    def send_process_alert(self, process_name, pid, matches):
        """Convenience method for process threat alerts"""
        subject = f"🚨 HIDS Alert: Suspicious Process Detected"
        body = (
            f"SUSPICIOUS PROCESS\n"
            f"{'='*40}\n"
            f"Process:  {process_name}\n"
            f"PID:      {pid}\n"
            f"Matches:  {', '.join(matches)}\n"
            f"Time:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"{'='*40}\n\n"
            f"Action Required: Review this process immediately.\n"
            f"Log in to your HIDS dashboard for details."
        )
        self.send_alert(subject, body)
