const API_BASE_URL = '';  // Empty for same origin (Vite proxy handles this)

export const api = {
    async getStatus() {
        const response = await fetch(`${API_BASE_URL}/api/status`);
        if (!response.ok) throw new Error('Failed to fetch status');
        return response.json();
    },

    async startMonitoring() {
        const response = await fetch(`${API_BASE_URL}/api/start`, {
            method: 'POST',
        });
        if (!response.ok) throw new Error('Failed to start monitoring');
        return response.json();
    },

    async stopMonitoring() {
        const response = await fetch(`${API_BASE_URL}/api/stop`, {
            method: 'POST',
        });
        if (!response.ok) throw new Error('Failed to stop monitoring');
        return response.json();
    },

    async clearLogs() {
        const response = await fetch(`${API_BASE_URL}/api/clear`, {
            method: 'POST',
        });
        if (!response.ok) throw new Error('Failed to clear logs');
        return response.json();
    },

    async deleteFile(filePath) {
        const response = await fetch(`${API_BASE_URL}/api/threat/delete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_path: filePath })
        });
        if (!response.ok) throw new Error('Failed to delete file');
        return response.json();
    },

    async markAsSafe(filePath) {
        const response = await fetch(`${API_BASE_URL}/api/threat/mark-safe`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_path: filePath })
        });
        if (!response.ok) throw new Error('Failed to mark as safe');
        return response.json();
    },

    async deleteActivity(timestamp, message) {
        const response = await fetch(`${API_BASE_URL}/api/activity/action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ timestamp, message, action: 'deleted' })
        });
        if (!response.ok) throw new Error('Failed to delete activity');
        return response.json();
    },

    async markActivitySafe(timestamp, message) {
        const response = await fetch(`${API_BASE_URL}/api/activity/action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ timestamp, message, action: 'marked_safe' })
        });
        if (!response.ok) throw new Error('Failed to mark activity safe');
        return response.json();
    },

    async getQuarantinedFiles() {
        const response = await fetch(`${API_BASE_URL}/api/quarantine`);
        if (!response.ok) throw new Error('Failed to fetch quarantined files');
        return response.json();
    },

    async restoreFile(filePath, originalPath = null) {
        const response = await fetch(`${API_BASE_URL}/api/quarantine/restore`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_path: filePath, original_path: originalPath })
        });
        if (!response.ok) throw new Error('Failed to restore file');
        return response.json();
    },

    async getEmailConfig() {
        const response = await fetch(`${API_BASE_URL}/api/email-config`);
        if (!response.ok) throw new Error('Failed to fetch email config');
        return response.json();
    },

    async saveEmailConfig(config) {
        const response = await fetch(`${API_BASE_URL}/api/email-config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        if (!response.ok) throw new Error('Failed to save email config');
        return response.json();
    },

    async sendTestEmail(config) {
        const response = await fetch(`${API_BASE_URL}/api/email-test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        if (!response.ok) throw new Error('Failed to send test email');
        return response.json();
    },

    async getUsbEvents() {
        const response = await fetch(`${API_BASE_URL}/api/usb/events`);
        if (!response.ok) throw new Error('Failed to fetch USB events');
        return response.json();
    },

    async rescanDrive(drive) {
        const response = await fetch(`${API_BASE_URL}/api/usb/rescan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ drive })
        });
        if (!response.ok) throw new Error('Failed to rescan drive');
        return response.json();
    },

    async clearUsbHistory() {
        const response = await fetch(`${API_BASE_URL}/api/usb/clear`, { method: 'POST' });
        if (!response.ok) throw new Error('Failed to clear USB history');
        return response.json();
    },
};

