"""
Flask API Module for HIDS
Contains all REST API endpoints for the web interface
"""

import os
import logging
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS


def create_api(hids_instance):
    """
    Create Flask app with API routes
    
    Args:
        hids_instance: Initialized HIDS core instance
        
    Returns:
        Flask app object
    """
    # Check if React build exists, otherwise use templates
    react_build_path = os.path.join(os.path.dirname(__file__), 'frontend', 'dist')
    use_react = os.path.exists(react_build_path)
    
    if use_react:
        app = Flask(__name__, 
                   static_folder='frontend/dist/assets',
                   static_url_path='/assets')
    else:
        app = Flask(__name__, template_folder='templates', static_folder='static')
    
    # Enable CORS for development
    CORS(app)
    
    @app.route('/')
    def index():
        if use_react:
            return send_from_directory(react_build_path, 'index.html')
        return render_template('index.html')
    
    @app.route('/api/status')
    def status():
        return jsonify(hids_instance.get_status())
    
    @app.route('/api/start', methods=['POST'])
    def start():
        success = hids_instance.start_monitoring()
        return jsonify({'success': success, 'message': 'Monitoring started' if success else 'Monitoring already active'})
    
    @app.route('/api/stop', methods=['POST'])
    def stop():
        success = hids_instance.stop_monitoring()
        return jsonify({'success': success, 'message': 'Monitoring stopped' if success else 'Monitoring already stopped'})
    
    @app.route('/api/clear', methods=['POST'])
    def clear():
        success = hids_instance.clear_logs()
        return jsonify({'success': success, 'message': 'Logs cleared' if success else 'Failed to clear logs'})
    
    @app.route('/api/scan', methods=['POST'])
    def scan_file():
        """Manual file scanning endpoint"""
        data = request.get_json()
        if not data or 'filepath' not in data:
            return jsonify({'success': False, 'message': 'Missing filepath parameter'})
        
        filepath = data['filepath']
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'message': 'File does not exist'})
        
        try:
            hids_instance.analyze_file(filepath, "manual scan")
            return jsonify({'success': True, 'message': f'Scan completed for {filepath}'})
        except Exception as e:
            logging.error(f"Manual scan error: {str(e)}")
            return jsonify({'success': False, 'message': str(e)})
    
    @app.route('/api/config', methods=['GET', 'POST'])
    def config():
        """Get or update configuration"""
        if request.method == 'GET':
            # Return current configuration
            config_dict = {}
            for section in hids_instance.config.sections():
                config_dict[section] = dict(hids_instance.config.items(section))
            return jsonify({'success': True, 'config': config_dict})
        
        elif request.method == 'POST':
            # Update configuration
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'message': 'No data provided'})
            
            try:
                for section, options in data.items():
                    if not hids_instance.config.has_section(section):
                        hids_instance.config.add_section(section)
                    for option, value in options.items():
                        hids_instance.config.set(section, option, str(value))
                
                # Save to file
                with open('config.ini', 'w') as configfile:
                    hids_instance.config.write(configfile)
                
                # Reload whitelist if filters were updated
                if 'FILTERS' in data:
                    hids_instance.whitelist = hids_instance.load_whitelist()
                
                logging.info("Configuration updated via API")
                return jsonify({'success': True, 'message': 'Configuration updated successfully'})
            except Exception as e:
                logging.error(f"Config update error: {str(e)}")
                return jsonify({'success': False, 'message': str(e)})
    
    @app.route('/api/threat/delete', methods=['POST'])
    def delete_threat():
        """Delete a file permanently"""
        data = request.get_json()
        if not data or 'file_path' not in data:
            return jsonify({'success': False, 'message': 'Missing file_path parameter'})
        
        file_path = data['file_path']
        result = hids_instance.delete_file(file_path)
        return jsonify(result)
    
    @app.route('/api/threat/mark-safe', methods=['POST'])
    def mark_safe():
        """Mark a file as safe and add to whitelist"""
        data = request.get_json()
        if not data or 'file_path' not in data:
            return jsonify({'success': False, 'message': 'Missing file_path parameter'})
        
        file_path = data['file_path']
        result = hids_instance.mark_as_safe(file_path)
        return jsonify(result)
    
    @app.route('/api/activity/action', methods=['POST'])
    def activity_action():
        """Apply an action (delete/mark safe) to a particular log entry using its timestamp and message"""
        data = request.get_json()
        if not data or 'timestamp' not in data or 'message' not in data or 'action' not in data:
            return jsonify({'success': False, 'message': 'Missing required parameters'})
            
        timestamp = data['timestamp']
        msg = data['message']
        action = data['action'] # 'deleted' or 'marked_safe'
        
        result = hids_instance.apply_activity_action(timestamp, msg, action)
        return jsonify(result)
    
    @app.route('/api/quarantine', methods=['GET'])
    def get_quarantine():
        """Get list of quarantined files"""
        files = hids_instance.get_quarantined_files()
        return jsonify({'success': True, 'files': files})
    
    @app.route('/api/quarantine/restore', methods=['POST'])
    def restore_quarantine():
        """Restore a file from quarantine"""
        data = request.get_json()
        if not data or 'file_path' not in data:
            return jsonify({'success': False, 'message': 'Missing file_path parameter'})
        
        file_path = data['file_path']
        original_path = data.get('original_path', None)
        result = hids_instance.restore_from_quarantine(file_path, original_path)
        return jsonify(result)
    
    @app.route('/api/email-config', methods=['GET'])
    def get_email_config():
        """Get current email alert configuration"""
        return jsonify({'success': True, 'config': hids_instance.email_alerter.get_settings()})
    
    @app.route('/api/email-config', methods=['POST'])
    def save_email_config():
        """Save email alert configuration"""
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'})
        
        try:
            if not hids_instance.config.has_section('EMAIL'):
                hids_instance.config.add_section('EMAIL')
            
            hids_instance.config.set('EMAIL', 'enabled', str(data.get('enabled', False)).lower())
            hids_instance.config.set('EMAIL', 'recipient_email', data.get('recipient_email', ''))
            hids_instance.config.set('EMAIL', 'sender_email', data.get('sender_email', ''))
            hids_instance.config.set('EMAIL', 'smtp_host', data.get('smtp_host', 'smtp.gmail.com'))
            hids_instance.config.set('EMAIL', 'smtp_port', str(data.get('smtp_port', 587)))
            
            # Only update password if a real one was provided (not the masked placeholder)
            if data.get('sender_password') and data.get('sender_password') != '***':
                hids_instance.config.set('EMAIL', 'sender_password', data.get('sender_password'))
            
            with open('config.ini', 'w') as f:
                hids_instance.config.write(f)
            
            logging.info("Email configuration updated via API")
            return jsonify({'success': True, 'message': 'Email settings saved successfully'})
        except Exception as e:
            logging.error(f"Email config save error: {str(e)}")
            return jsonify({'success': False, 'message': str(e)})
    
    @app.route('/api/email-test', methods=['POST'])
    def test_email():
        """Send a test email to verify configuration"""
        data = request.get_json() or {}
        
        # Temporarily apply submitted settings for the test (without saving)
        from email_alerts import EmailAlerter
        import configparser
        
        test_config = configparser.ConfigParser()
        # Copy existing config
        for section in hids_instance.config.sections():
            test_config.add_section(section)
            for key, val in hids_instance.config.items(section):
                test_config.set(section, key, val)
        
        # Override with submitted values for the test
        if not test_config.has_section('EMAIL'):
            test_config.add_section('EMAIL')
        test_config.set('EMAIL', 'enabled', 'true')
        test_config.set('EMAIL', 'recipient_email', data.get('recipient_email', ''))
        test_config.set('EMAIL', 'sender_email', data.get('sender_email', ''))
        test_config.set('EMAIL', 'smtp_host', data.get('smtp_host', 'smtp.gmail.com'))
        test_config.set('EMAIL', 'smtp_port', str(data.get('smtp_port', 587)))
        
        # Use real password: submitted one, or existing saved one
        password = data.get('sender_password', '')
        if not password or password == '***':
            password = hids_instance.config.get('EMAIL', 'sender_password', fallback='')
        test_config.set('EMAIL', 'sender_password', password)
        
        test_alerter = EmailAlerter(test_config)
        success, message = test_alerter.send_alert(
            subject="🛡️ HIDS Test Alert",
            body="This is a test email from your HIDS (Host Intrusion Detection System).\n\nIf you received this, email alerts are configured correctly!",
            is_test=True
        )
        return jsonify({'success': success, 'message': message})
    
    @app.route('/api/report/csv')
    def export_csv():
        """Export activity log as CSV"""
        from report_generator import generate_csv
        from flask import Response
        filter_type = request.args.get('filter', 'all')
        activities = hids_instance.get_status().get('activities', [])
        csv_bytes = generate_csv(activities, filter_type)
        timestamp = __import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'hids_report_{filter_type}_{timestamp}.csv'
        return Response(
            csv_bytes,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )

    @app.route('/api/report/pdf')
    def export_pdf():
        """Export activity log as PDF"""
        from report_generator import generate_pdf
        from flask import Response
        filter_type = request.args.get('filter', 'all')
        status_data = hids_instance.get_status()
        activities = status_data.get('activities', [])
        threats = [a for a in activities if a.get('type') == 'threat']
        quarantined = [a for a in activities if a.get('action') == 'quarantined']
        safe_marked = [a for a in activities if a.get('action') == 'marked_safe']
        stats = {
            'total': len(activities),
            'threats': len(threats),
            'quarantined': len(quarantined),
            'safe_marked': len(safe_marked),
        }
        try:
            pdf_bytes = generate_pdf(activities, stats, filter_type)
            timestamp = __import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'hids_report_{filter_type}_{timestamp}.pdf'
            return Response(
                pdf_bytes,
                mimetype='application/pdf',
                headers={'Content-Disposition': f'attachment; filename="{filename}"'}
            )
        except Exception as e:
            logging.error(f"PDF generation error: {str(e)}")
            return jsonify({'success': False, 'message': f'PDF generation failed: {str(e)}'}), 500

    # ------------------------------------------------------------------ #
    #  Honeypot endpoints                                                   #
    # ------------------------------------------------------------------ #

    @app.route('/api/honeypots', methods=['GET'])
    def get_honeypots():
        """List all planted honeypot files."""
        return jsonify({
            'success': True,
            'honeypots': hids_instance.honeypot_manager.get_all()
        })

    @app.route('/api/honeypots/templates', methods=['GET'])
    def get_honeypot_templates():
        """List available decoy file templates."""
        return jsonify({
            'success': True,
            'templates': hids_instance.honeypot_manager.get_templates()
        })

    @app.route('/api/honeypots/plant', methods=['POST'])
    def plant_honeypot():
        """Plant a honeypot decoy file."""
        data = request.get_json()
        if not data or 'directory' not in data or 'template_id' not in data:
            return jsonify({'success': False, 'message': 'Missing directory or template_id'}), 400
        result = hids_instance.honeypot_manager.plant(data['directory'], data['template_id'])
        if result['success']:
            # Dynamically add the directory to the file system observer
            hids_instance.schedule_honeypot_directory(data['directory'])
        status = 200 if result['success'] else 400
        return jsonify(result), status

    @app.route('/api/honeypots/<honeypot_id>', methods=['DELETE'])
    def delete_honeypot(honeypot_id):
        """Delete a honeypot file and its record."""
        result = hids_instance.honeypot_manager.delete(honeypot_id)
        status = 200 if result['success'] else 404
        return jsonify(result), status

    # ------------------------------------------------------------------ #
    #  USB Device Guard endpoints                                           #
    # ------------------------------------------------------------------ #

    @app.route('/api/usb/events', methods=['GET'])
    def get_usb_events():
        """List all USB insertion events with scan results."""
        return jsonify({
            'success': True,
            'events': hids_instance.usb_guard.get_all()
        })

    @app.route('/api/usb/rescan', methods=['POST'])
    def rescan_usb():
        """Re-scan a connected USB drive on demand."""
        data = request.get_json()
        if not data or 'drive' not in data:
            return jsonify({'success': False, 'message': 'Missing drive letter'}), 400
        result = hids_instance.usb_guard.rescan(data['drive'])
        return jsonify(result), (200 if result['success'] else 400)

    @app.route('/api/usb/clear', methods=['POST'])
    def clear_usb_events():
        """Clear USB event history."""
        hids_instance.usb_guard.clear()
        return jsonify({'success': True, 'message': 'USB event history cleared'})

    return app

