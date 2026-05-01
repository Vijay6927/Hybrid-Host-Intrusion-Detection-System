import { useState } from 'react'
import { Card, CardContent, Typography, Box, Chip, Dialog, DialogTitle, DialogContent, DialogContentText, DialogActions, Button, Alert } from '@mui/material'
import WarningIcon from '@mui/icons-material/Warning'
import AccessTimeIcon from '@mui/icons-material/AccessTime'
import DeleteIcon from '@mui/icons-material/Delete'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'
import { api } from '../services/api'

export default function ActivityLog({ activities, onActionComplete }) {
    const [confirmDialog, setConfirmDialog] = useState({ open: false, action: null, filePath: null, message: '' })
    const [loading, setLoading] = useState(false)
    const [notification, setNotification] = useState({ open: false, message: '', severity: 'success' })

    // Extract file path from activity message
    const extractFilePath = (message) => {
        // Try to find file path in common formats
        const pathMatch = message.match(/(?:file|path|File|Path):\s*([A-Za-z]:[\\\/][^\s]+)/i) ||
            message.match(/\b([A-Za-z]:[\\\/][^\s]+)\b/)
        return pathMatch ? pathMatch[1] : null
    }

    const handleAction = (action, activity) => {
        const filePath = extractFilePath(activity.message)

        // USB threats and general log messages might not have a file path.
        if (!filePath && !activity.usb) {
            showNotification('Could not extract file path from message', 'error')
            return
        }

        setConfirmDialog({
            open: true,
            action,
            filePath,
            activity, // Store full activity for log-based actions
            message: action === 'delete'
                ? (activity.usb ? 'Are you sure you want to delete this USB threat log?' : `Are you sure you want to permanently delete this file?\n\n${filePath}`)
                : (activity.usb ? 'Mark this USB threat as safe? It will clear the alert.' : `Mark this file as safe and add to whitelist?\n\n${filePath}`)
        })
    }

    const confirmAction = async () => {
        const { action, filePath, activity } = confirmDialog
        setLoading(true)
        setConfirmDialog({ ...confirmDialog, open: false })

        try {
            let result
            if (activity.usb) {
                // USB Log Actions
                if (action === 'delete') {
                    result = await api.deleteActivity(activity.timestamp, activity.message)
                } else if (action === 'markSafe') {
                    result = await api.markActivitySafe(activity.timestamp, activity.message)
                }
            } else {
                // File-based Actions
                if (action === 'delete') {
                    result = await api.deleteFile(filePath)
                } else if (action === 'markSafe') {
                    result = await api.markAsSafe(filePath)
                }
            }

            if (result.success) {
                showNotification(result.message, 'success')
                if (onActionComplete) onActionComplete()
            } else {
                showNotification(result.message || 'Action failed', 'error')
            }
        } catch (error) {
            showNotification(`Error: ${error.message}`, 'error')
        } finally {
            setLoading(false)
        }
    }

    const showNotification = (message, severity) => {
        setNotification({ open: true, message, severity })
        setTimeout(() => setNotification({ open: false, message: '', severity: 'success' }), 5000)
    }

    return (
        <>
            <Card sx={{
                background: 'rgba(30, 27, 75, 0.85)',
                backdropFilter: 'blur(10px)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                mt: 3
            }}>
                <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
                        <Typography variant="h6" sx={{ fontWeight: 600, color: 'error.main' }}>
                            Suspicious Activity Log
                        </Typography>
                        <Chip
                            label={`${activities.filter(a => !a.action).length} Alerts`}
                            color="error"
                            size="small"
                            sx={{ fontWeight: 600 }}
                        />
                    </Box>

                    {notification.open && (
                        <Alert severity={notification.severity} sx={{ mb: 2 }} onClose={() => setNotification({ ...notification, open: false })}>
                            {notification.message}
                        </Alert>
                    )}

                    <Box sx={{
                        maxHeight: 400,
                        overflowY: 'auto',
                        pr: 1
                    }}>
                        {activities.length > 0 ? (
                            [...activities].reverse().map((activity, index) => (
                                <Box
                                    key={index}
                                    sx={{
                                        p: 2,
                                        mb: 1.5,
                                        background: 'rgba(239, 68, 68, 0.1)',
                                        border: '1px solid rgba(239, 68, 68, 0.3)',
                                        borderLeft: '4px solid #ef4444',
                                        borderRadius: 2,
                                        transition: 'all 0.3s ease',
                                        '&:hover': {
                                            background: 'rgba(239, 68, 68, 0.15)',
                                            transform: 'translateX(4px)',
                                            boxShadow: '0 4px 12px rgba(239, 68, 68, 0.2)'
                                        }
                                    }}
                                >
                                    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                                        <WarningIcon sx={{ color: 'error.main', mt: 0.5 }} />

                                        <Box sx={{ flex: 1 }}>
                                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                                                <AccessTimeIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
                                                <Typography
                                                    variant="caption"
                                                    sx={{
                                                        color: 'text.secondary',
                                                        fontFamily: 'monospace'
                                                    }}
                                                >
                                                    {activity.timestamp}
                                                </Typography>
                                                {activity.action && (
                                                    <Chip
                                                        label={activity.action}
                                                        size="small"
                                                        sx={{ ml: 1, textTransform: 'capitalize' }}
                                                        color={
                                                            activity.action === 'deleted' ? 'error' :
                                                                activity.action === 'marked_safe' ? 'success' :
                                                                    'default'
                                                        }
                                                    />
                                                )}
                                            </Box>

                                            <Typography
                                                sx={{
                                                    fontFamily: 'monospace',
                                                    fontSize: '0.95rem',
                                                    color: '#fbbf24',
                                                    wordBreak: 'break-word',
                                                    mb: 1
                                                }}
                                            >
                                                {activity.message}
                                            </Typography>

                                            {/* Action Buttons - only show if no action has been taken yet */}
                                            {!activity.action && (extractFilePath(activity.message) || activity.usb) && (
                                                <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                                                    {/* Hide Delete for honeypot entries — managed via Honeypot panel */}
                                                    {!activity.honeypot && (
                                                        <Button
                                                            size="small"
                                                            variant="outlined"
                                                            color="error"
                                                            startIcon={<DeleteIcon />}
                                                            onClick={() => handleAction('delete', activity)}
                                                            disabled={loading}
                                                            sx={{
                                                                textTransform: 'none',
                                                                fontSize: '0.75rem',
                                                                py: 0.5,
                                                                px: 1.5
                                                            }}
                                                        >
                                                            {activity.usb ? 'Delete Log' : 'Delete'}
                                                        </Button>
                                                    )}
                                                    <Button
                                                        size="small"
                                                        variant="outlined"
                                                        color="success"
                                                        startIcon={<CheckCircleIcon />}
                                                        onClick={() => handleAction('markSafe', activity)}
                                                        disabled={loading}
                                                        sx={{
                                                            textTransform: 'none',
                                                            fontSize: '0.75rem',
                                                            py: 0.5,
                                                            px: 1.5
                                                        }}
                                                    >
                                                        Mark as Safe
                                                    </Button>
                                                </Box>
                                            )}
                                        </Box>
                                    </Box>
                                </Box>
                            ))
                        ) : (
                            <Box sx={{
                                height: 200,
                                display: 'flex',
                                flexDirection: 'column',
                                alignItems: 'center',
                                justifyContent: 'center',
                                color: 'text.secondary'
                            }}>
                                <WarningIcon sx={{ fontSize: 48, mb: 2, opacity: 0.3 }} />
                                <Typography>No suspicious activity detected</Typography>
                                <Typography variant="caption" sx={{ mt: 1 }}>
                                    System is secure
                                </Typography>
                            </Box>
                        )}
                    </Box>
                </CardContent>
            </Card>

            {/* Confirmation Dialog */}
            <Dialog
                open={confirmDialog.open}
                onClose={() => setConfirmDialog({ ...confirmDialog, open: false })}
            >
                <DialogTitle>
                    {confirmDialog.action === 'delete' ? 'Confirm Delete' : 'Confirm Mark as Safe'}
                </DialogTitle>
                <DialogContent>
                    <DialogContentText sx={{ whiteSpace: 'pre-line' }}>
                        {confirmDialog.message}
                    </DialogContentText>
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setConfirmDialog({ ...confirmDialog, open: false })}>
                        Cancel
                    </Button>
                    <Button
                        onClick={confirmAction}
                        color={confirmDialog.action === 'delete' ? 'error' : 'success'}
                        variant="contained"
                        autoFocus
                    >
                        {confirmDialog.action === 'delete' ? 'Delete' : 'Mark as Safe'}
                    </Button>
                </DialogActions>
            </Dialog>
        </>
    )
}
