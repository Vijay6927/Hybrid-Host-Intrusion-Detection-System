import { useState, useEffect } from 'react'
import {
    Card, CardContent, Typography, Box, TextField, Button, Switch,
    FormControlLabel, Alert, Collapse, Divider, CircularProgress,
    Tooltip, IconButton, InputAdornment
} from '@mui/material'
import EmailIcon from '@mui/icons-material/Email'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import ExpandLessIcon from '@mui/icons-material/ExpandLess'
import SendIcon from '@mui/icons-material/Send'
import SaveIcon from '@mui/icons-material/Save'
import Visibility from '@mui/icons-material/Visibility'
import VisibilityOff from '@mui/icons-material/VisibilityOff'
import { api } from '../services/api'

// Global sender defaults — used unless user provides their own
const GLOBAL_SENDER = 'divyanshudemy2005@gmail.com'
const GLOBAL_SMTP_HOST = 'smtp.gmail.com'
const GLOBAL_SMTP_PORT = 587

export default function EmailAlerts() {
    const [config, setConfig] = useState({
        enabled: false,
        recipient_email: '',
        // Advanced / custom sender fields (hidden by default)
        sender_email: '',
        sender_password: '',
        smtp_host: GLOBAL_SMTP_HOST,
        smtp_port: GLOBAL_SMTP_PORT,
    })
    const [useCustomSender, setUseCustomSender] = useState(false)
    const [showAdvanced, setShowAdvanced] = useState(false)
    const [showPassword, setShowPassword] = useState(false)
    const [saving, setSaving] = useState(false)
    const [testing, setTesting] = useState(false)
    const [notification, setNotification] = useState({ open: false, message: '', severity: 'success' })

    useEffect(() => {
        api.getEmailConfig()
            .then(res => {
                if (res.success) {
                    const c = res.config
                    setConfig(c)
                    // If saved sender differs from global, user has a custom sender
                    if (c.sender_email && c.sender_email !== GLOBAL_SENDER) {
                        setUseCustomSender(true)
                        setShowAdvanced(true)
                    }
                }
            })
            .catch(err => console.error('Failed to load email config:', err))
    }, [])

    const showNotification = (message, severity = 'success') => {
        setNotification({ open: true, message, severity })
        setTimeout(() => setNotification({ open: false, message: '', severity: 'success' }), 6000)
    }

    // Build the payload — use global sender unless user has custom sender enabled
    const buildPayload = () => {
        if (useCustomSender && config.sender_email) {
            return config
        }
        return {
            ...config,
            sender_email: GLOBAL_SENDER,
            sender_password: '',   // backend will keep existing saved password
            smtp_host: GLOBAL_SMTP_HOST,
            smtp_port: GLOBAL_SMTP_PORT,
        }
    }

    const handleSave = async () => {
        if (!config.recipient_email) {
            showNotification('Please enter a recipient email address.', 'warning')
            return
        }
        setSaving(true)
        try {
            const result = await api.saveEmailConfig(buildPayload())
            showNotification(result.message, result.success ? 'success' : 'error')
        } catch (e) {
            showNotification(`Save failed: ${e.message}`, 'error')
        } finally {
            setSaving(false)
        }
    }

    const handleTest = async () => {
        if (!config.recipient_email) {
            showNotification('Please enter a recipient email address first.', 'warning')
            return
        }
        setTesting(true)
        try {
            const result = await api.sendTestEmail(buildPayload())
            showNotification(result.message, result.success ? 'success' : 'error')
        } catch (e) {
            showNotification(`Test failed: ${e.message}`, 'error')
        } finally {
            setTesting(false)
        }
    }

    const fieldSx = {
        '& .MuiOutlinedInput-root': {
            color: '#e2e8f0',
            '& fieldset': { borderColor: 'rgba(124, 58, 237, 0.3)' },
            '&:hover fieldset': { borderColor: 'rgba(124, 58, 237, 0.6)' },
            '&.Mui-focused fieldset': { borderColor: '#7c3aed' },
        },
        '& .MuiInputLabel-root': { color: '#94a3b8' },
        '& .MuiInputLabel-root.Mui-focused': { color: '#a78bfa' },
    }

    return (
        <Card sx={{
            background: 'rgba(30, 27, 75, 0.85)',
            backdropFilter: 'blur(10px)',
            border: '1px solid rgba(124, 58, 237, 0.3)',
            mt: 3,
        }}>
            <CardContent>
                {/* Header */}
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2.5 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                        <Box sx={{
                            p: 1,
                            borderRadius: 2,
                            background: 'linear-gradient(135deg, rgba(124,58,237,0.2) 0%, rgba(139,92,246,0.2) 100%)',
                            display: 'flex',
                            alignItems: 'center',
                        }}>
                            <EmailIcon sx={{ color: '#a78bfa', fontSize: 22 }} />
                        </Box>
                        <Box>
                            <Typography variant="h6" sx={{ fontWeight: 600, color: '#e2e8f0', lineHeight: 1.2 }}>
                                Email Alert Notifications
                            </Typography>
                            <Typography variant="caption" sx={{ color: '#94a3b8' }}>
                                Get notified when threats are detected
                            </Typography>
                        </Box>
                    </Box>

                    <FormControlLabel
                        control={
                            <Switch
                                checked={config.enabled}
                                onChange={e => setConfig({ ...config, enabled: e.target.checked })}
                                sx={{
                                    '& .MuiSwitch-switchBase.Mui-checked': { color: '#a78bfa' },
                                    '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { backgroundColor: '#7c3aed' },
                                }}
                            />
                        }
                        label={
                            <Typography sx={{ color: config.enabled ? '#a78bfa' : '#6b7280', fontWeight: 500, fontSize: '0.85rem' }}>
                                {config.enabled ? 'Enabled' : 'Disabled'}
                            </Typography>
                        }
                    />
                </Box>

                {notification.open && (
                    <Alert
                        severity={notification.severity}
                        sx={{ mb: 2 }}
                        onClose={() => setNotification({ ...notification, open: false })}
                    >
                        {notification.message}
                    </Alert>
                )}

                {/* Recipient email — the ONLY required field */}
                <TextField
                    id="email-recipient"
                    label="Your Email Address (Receive Alerts Here)"
                    placeholder="you@example.com"
                    value={config.recipient_email}
                    onChange={e => setConfig({ ...config, recipient_email: e.target.value })}
                    fullWidth
                    size="small"
                    sx={{ ...fieldSx, mb: 2 }}
                    InputProps={{
                        startAdornment: (
                            <InputAdornment position="start">
                                <EmailIcon sx={{ fontSize: 18, color: '#94a3b8' }} />
                            </InputAdornment>
                        )
                    }}
                    helperText={
                        <Typography variant="caption" sx={{ color: '#64748b' }}>
                            Threat alerts will be sent to this address from our HIDS notification service
                        </Typography>
                    }
                />

                {/* Optional: Use custom sender */}
                <Box
                    onClick={() => setShowAdvanced(!showAdvanced)}
                    sx={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 1,
                        cursor: 'pointer',
                        color: '#6b7280',
                        '&:hover': { color: '#a78bfa' },
                        userSelect: 'none',
                        mb: 1,
                    }}
                >
                    {showAdvanced ? <ExpandLessIcon fontSize="small" /> : <ExpandMoreIcon fontSize="small" />}
                    <Typography variant="caption" sx={{ fontWeight: 500 }}>
                        Use a custom sender email (optional)
                    </Typography>
                </Box>

                <Collapse in={showAdvanced}>
                    <Box sx={{
                        p: 2,
                        borderRadius: 2,
                        background: 'rgba(124, 58, 237, 0.05)',
                        border: '1px solid rgba(124, 58, 237, 0.15)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 2,
                        mb: 2,
                    }}>
                        <FormControlLabel
                            control={
                                <Switch
                                    size="small"
                                    checked={useCustomSender}
                                    onChange={e => setUseCustomSender(e.target.checked)}
                                    sx={{
                                        '& .MuiSwitch-switchBase.Mui-checked': { color: '#a78bfa' },
                                        '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { backgroundColor: '#7c3aed' },
                                    }}
                                />
                            }
                            label={
                                <Typography variant="body2" sx={{ color: '#94a3b8' }}>
                                    Send from my own email account
                                </Typography>
                            }
                        />

                        <Collapse in={useCustomSender}>
                            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                                <Alert severity="info" sx={{
                                    background: 'rgba(59, 130, 246, 0.1)',
                                    border: '1px solid rgba(59, 130, 246, 0.3)',
                                    color: '#93c5fd',
                                    '& .MuiAlert-icon': { color: '#60a5fa' }
                                }}>
                                    For Gmail, use an <strong>App Password</strong> (Google Account → Security → 2-Step Verification → App Passwords).
                                </Alert>

                                <TextField
                                    id="email-sender"
                                    label="Sender Email"
                                    placeholder="yourgmail@gmail.com"
                                    value={config.sender_email}
                                    onChange={e => setConfig({ ...config, sender_email: e.target.value })}
                                    fullWidth
                                    size="small"
                                    sx={fieldSx}
                                />

                                <TextField
                                    id="email-password"
                                    label="App Password"
                                    type={showPassword ? 'text' : 'password'}
                                    placeholder="Gmail App Password"
                                    value={config.sender_password === '***' ? '' : config.sender_password}
                                    onChange={e => setConfig({ ...config, sender_password: e.target.value })}
                                    fullWidth
                                    size="small"
                                    sx={fieldSx}
                                    InputProps={{
                                        endAdornment: (
                                            <InputAdornment position="end">
                                                <IconButton
                                                    onClick={() => setShowPassword(!showPassword)}
                                                    edge="end"
                                                    size="small"
                                                    sx={{ color: '#94a3b8' }}
                                                >
                                                    {showPassword ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                                                </IconButton>
                                            </InputAdornment>
                                        )
                                    }}
                                />

                                <Box sx={{ display: 'flex', gap: 2 }}>
                                    <TextField
                                        id="email-smtp-host"
                                        label="SMTP Host"
                                        value={config.smtp_host}
                                        onChange={e => setConfig({ ...config, smtp_host: e.target.value })}
                                        size="small"
                                        sx={{ ...fieldSx, flex: 2 }}
                                    />
                                    <TextField
                                        id="email-smtp-port"
                                        label="Port"
                                        type="number"
                                        value={config.smtp_port}
                                        onChange={e => setConfig({ ...config, smtp_port: parseInt(e.target.value) || 587 })}
                                        size="small"
                                        sx={{ ...fieldSx, flex: 1 }}
                                    />
                                </Box>
                            </Box>
                        </Collapse>
                    </Box>
                </Collapse>

                <Divider sx={{ my: 2, borderColor: 'rgba(124, 58, 237, 0.2)' }} />

                {/* Action buttons */}
                <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                    <Button
                        id="email-save-btn"
                        variant="contained"
                        startIcon={saving ? <CircularProgress size={16} color="inherit" /> : <SaveIcon />}
                        onClick={handleSave}
                        disabled={saving || testing}
                        sx={{
                            background: 'linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%)',
                            boxShadow: '0 4px 15px rgba(124, 58, 237, 0.4)',
                            '&:hover': {
                                background: 'linear-gradient(135deg, #6d28d9 0%, #5b21b6 100%)',
                                boxShadow: '0 6px 20px rgba(124, 58, 237, 0.6)',
                            },
                            '&:disabled': { background: '#374151', color: '#6b7280' },
                            textTransform: 'none',
                            fontWeight: 600,
                            px: 3,
                        }}
                    >
                        {saving ? 'Saving...' : 'Save Settings'}
                    </Button>

                    <Tooltip title="Send a test alert to your email to verify it works">
                        <span>
                            <Button
                                id="email-test-btn"
                                variant="outlined"
                                startIcon={testing ? <CircularProgress size={16} color="inherit" /> : <SendIcon />}
                                onClick={handleTest}
                                disabled={saving || testing || !config.recipient_email}
                                sx={{
                                    borderColor: 'rgba(124, 58, 237, 0.5)',
                                    color: '#a78bfa',
                                    borderWidth: 2,
                                    '&:hover': {
                                        borderWidth: 2,
                                        borderColor: '#7c3aed',
                                        background: 'rgba(124, 58, 237, 0.1)',
                                    },
                                    '&:disabled': { borderColor: '#374151', color: '#6b7280' },
                                    textTransform: 'none',
                                    fontWeight: 600,
                                    px: 3,
                                }}
                            >
                                {testing ? 'Sending...' : 'Send Test Email'}
                            </Button>
                        </span>
                    </Tooltip>
                </Box>
            </CardContent>
        </Card>
    )
}
