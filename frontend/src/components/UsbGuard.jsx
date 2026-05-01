import { useState, useEffect, useCallback } from 'react'
import {
    Box, Typography, Button, Table, TableBody, TableCell, TableContainer,
    TableHead, TableRow, Paper, Chip, IconButton, Tooltip, Snackbar, Alert,
    Divider, CircularProgress, Collapse, Badge
} from '@mui/material'
import UsbIcon from '@mui/icons-material/Usb'
import RefreshIcon from '@mui/icons-material/Refresh'
import DeleteSweepIcon from '@mui/icons-material/DeleteSweep'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import ExpandLessIcon from '@mui/icons-material/ExpandLess'
import ShieldIcon from '@mui/icons-material/Shield'
import WarningAmberIcon from '@mui/icons-material/WarningAmber'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'

const POLL_INTERVAL = 5000

const severityColor = {
    critical: { bg: 'rgba(239,68,68,0.15)', text: '#f87171', border: 'rgba(239,68,68,0.4)' },
    high: { bg: 'rgba(249,115,22,0.15)', text: '#fb923c', border: 'rgba(249,115,22,0.4)' },
    medium: { bg: 'rgba(234,179,8,0.15)', text: '#facc15', border: 'rgba(234,179,8,0.4)' },
    low: { bg: 'rgba(100,116,139,0.15)', text: '#94a3b8', border: 'rgba(100,116,139,0.35)' },
}

export default function UsbGuard() {
    const [events, setEvents] = useState([])
    const [expandedId, setExpandedId] = useState(null)
    const [rescanning, setRescanning] = useState({})
    const [clearing, setClearing] = useState(false)
    const [snack, setSnack] = useState({ open: false, message: '', severity: 'success' })

    const showSnack = (message, severity = 'success') =>
        setSnack({ open: true, message, severity })

    const fetchEvents = useCallback(async () => {
        try {
            const res = await fetch('/api/usb/events')
            const data = await res.json()
            if (data.success) setEvents(data.events)
        } catch (_) { }
    }, [])

    useEffect(() => {
        fetchEvents()
        const id = setInterval(fetchEvents, POLL_INTERVAL)
        return () => clearInterval(id)
    }, [fetchEvents])

    const handleRescan = async (drive) => {
        setRescanning(r => ({ ...r, [drive]: true }))
        try {
            const res = await fetch('/api/usb/rescan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ drive }),
            })
            const data = await res.json()
            if (data.success) {
                showSnack(`✅ Rescan complete for ${drive}`)
                fetchEvents()
            } else {
                showSnack(`Failed: ${data.message}`, 'error')
            }
        } catch (e) {
            showSnack(`Error: ${e.message}`, 'error')
        } finally {
            setRescanning(r => ({ ...r, [drive]: false }))
        }
    }

    const handleClear = async () => {
        setClearing(true)
        try {
            const res = await fetch('/api/usb/clear', { method: 'POST' })
            const data = await res.json()
            if (data.success) {
                showSnack('USB history cleared')
                setEvents([])
                setExpandedId(null)
            }
        } catch (e) {
            showSnack(`Error: ${e.message}`, 'error')
        } finally {
            setClearing(false)
        }
    }

    const threatCount = events.reduce((s, e) => s + (e.threat_count || 0), 0)
    const deviceCount = events.length

    const cellSx = { color: '#94a3b8', borderColor: 'rgba(99,102,241,0.12)', py: 1 }
    const headSx = {
        color: '#64748b', borderColor: 'rgba(99,102,241,0.2)',
        fontWeight: 700, fontSize: '0.72rem', textTransform: 'uppercase', py: 1
    }

    return (
        <Box sx={{
            mt: 3, mb: 1,
            background: 'rgba(15,23,42,0.6)',
            border: `1px solid ${threatCount > 0 ? 'rgba(239,68,68,0.35)' : 'rgba(99,102,241,0.18)'}`,
            borderRadius: 2,
            p: 2.5,
            backdropFilter: 'blur(8px)',
            transition: 'border-color 0.4s ease',
        }}>
            {/* ── Header ── */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <Badge
                    badgeContent={threatCount > 0 ? threatCount : null}
                    color="error"
                    overlap="circular"
                >
                    <UsbIcon sx={{
                        color: threatCount > 0 ? '#ef4444' : '#818cf8',
                        fontSize: 22,
                        animation: threatCount > 0 ? 'usb-pulse 2s infinite' : 'none',
                        '@keyframes usb-pulse': {
                            '0%, 100%': { opacity: 1, filter: 'drop-shadow(0 0 4px #ef4444)' },
                            '50%': { opacity: 0.6, filter: 'none' },
                        },
                    }} />
                </Badge>

                <Typography variant="subtitle1" sx={{
                    color: threatCount > 0 ? '#f87171' : '#818cf8',
                    fontWeight: 700,
                    transition: 'color 0.4s',
                }}>
                    USB Device Guard
                </Typography>

                <Chip
                    label={`${deviceCount} device${deviceCount !== 1 ? 's' : ''}`}
                    size="small"
                    sx={{ background: 'rgba(99,102,241,0.12)', color: '#818cf8', border: '1px solid rgba(99,102,241,0.3)' }}
                />

                {threatCount > 0 && (
                    <Chip
                        icon={<WarningAmberIcon fontSize="small" />}
                        label={`${threatCount} Threat${threatCount > 1 ? 's' : ''} Found!`}
                        size="small"
                        sx={{
                            background: 'rgba(239,68,68,0.15)', color: '#f87171',
                            border: '1px solid rgba(239,68,68,0.4)', fontWeight: 700,
                            animation: 'pulse 2s infinite',
                            '@keyframes pulse': {
                                '0%, 100%': { opacity: 1 },
                                '50%': { opacity: 0.6 },
                            },
                        }}
                    />
                )}

                {threatCount === 0 && deviceCount > 0 && (
                    <Chip
                        icon={<ShieldIcon fontSize="small" />}
                        label="All Clean"
                        size="small"
                        sx={{ background: 'rgba(34,197,94,0.1)', color: '#4ade80', border: '1px solid rgba(34,197,94,0.3)' }}
                    />
                )}

                {/* Spacer + Clear button */}
                <Box sx={{ ml: 'auto' }}>
                    <Tooltip title="Clear USB event history">
                        <span>
                            <Button
                                size="small"
                                startIcon={clearing ? <CircularProgress size={12} color="inherit" /> : <DeleteSweepIcon />}
                                onClick={handleClear}
                                disabled={clearing || events.length === 0}
                                sx={{
                                    color: '#64748b', textTransform: 'none', fontSize: '0.75rem',
                                    '&:hover': { color: '#94a3b8', background: 'rgba(255,255,255,0.04)' },
                                    '&:disabled': { opacity: 0.3 },
                                }}
                            >
                                Clear History
                            </Button>
                        </span>
                    </Tooltip>
                </Box>
            </Box>

            <Divider sx={{ borderColor: 'rgba(99,102,241,0.15)', mb: 2 }} />

            {/* ── Empty state ── */}
            {events.length === 0 ? (
                <Box sx={{ textAlign: 'center', py: 4 }}>
                    <UsbIcon sx={{ fontSize: 40, color: 'rgba(99,102,241,0.2)', mb: 1 }} />
                    <Typography variant="body2" sx={{ color: '#475569' }}>
                        No USB devices detected yet. Plug in a drive to start monitoring.
                    </Typography>
                    <Typography variant="caption" sx={{ color: '#334155' }}>
                        HIDS monitoring must be running.
                    </Typography>
                </Box>
            ) : (
                /* ── Events table ── */
                <TableContainer component={Paper} sx={{ background: 'transparent', boxShadow: 'none' }}>
                    <Table size="small">
                        <TableHead>
                            <TableRow>
                                <TableCell sx={headSx}>Drive</TableCell>
                                <TableCell sx={headSx}>Label</TableCell>
                                <TableCell sx={headSx}>Connected At</TableCell>
                                <TableCell sx={headSx}>Files Scanned</TableCell>
                                <TableCell sx={headSx}>Status</TableCell>
                                <TableCell sx={headSx} align="right">Actions</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {events.map(ev => (
                                <>
                                    <TableRow
                                        key={ev.id}
                                        sx={{
                                            '&:hover': { background: 'rgba(99,102,241,0.05)' },
                                            background: ev.threat_count > 0 ? 'rgba(239,68,68,0.04)' : 'transparent',
                                        }}
                                    >
                                        {/* Drive */}
                                        <TableCell sx={{ ...cellSx, fontFamily: 'monospace', fontWeight: 700, color: '#e2e8f0', fontSize: '0.9rem' }}>
                                            {ev.drive}
                                        </TableCell>

                                        {/* Label */}
                                        <TableCell sx={{ ...cellSx, color: '#cbd5e1' }}>
                                            {ev.label}
                                        </TableCell>

                                        {/* Connected at */}
                                        <TableCell sx={{ ...cellSx, fontSize: '0.75rem' }}>
                                            {ev.connected_at}
                                        </TableCell>

                                        {/* Files scanned */}
                                        <TableCell sx={cellSx}>
                                            {ev.findings && ev.findings.length > 0 ? (
                                                <Tooltip title="Click to view findings">
                                                    <Chip
                                                        label={`${ev.findings.length} finding${ev.findings.length > 1 ? 's' : ''}`}
                                                        size="small"
                                                        onClick={() => setExpandedId(expandedId === ev.id ? null : ev.id)}
                                                        deleteIcon={expandedId === ev.id ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                                                        onDelete={() => setExpandedId(expandedId === ev.id ? null : ev.id)}
                                                        sx={{
                                                            background: 'rgba(239,68,68,0.1)', color: '#fca5a5',
                                                            border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer',
                                                        }}
                                                    />
                                                </Tooltip>
                                            ) : (
                                                <Typography variant="caption" sx={{ color: '#475569' }}>
                                                    {ev.files_scanned ?? 0} files — clean
                                                </Typography>
                                            )}
                                        </TableCell>

                                        {/* Status */}
                                        <TableCell sx={cellSx}>
                                            {ev.status === 'threat' ? (
                                                <Chip
                                                    icon={<WarningAmberIcon fontSize="small" />}
                                                    label={`${ev.threat_count} Threat${ev.threat_count > 1 ? 's' : ''}`}
                                                    size="small"
                                                    sx={{
                                                        background: 'rgba(239,68,68,0.15)', color: '#f87171',
                                                        border: '1px solid rgba(239,68,68,0.4)', fontWeight: 700,
                                                    }}
                                                />
                                            ) : (
                                                <Chip
                                                    icon={<CheckCircleIcon fontSize="small" />}
                                                    label="Clean"
                                                    size="small"
                                                    sx={{ background: 'rgba(34,197,94,0.1)', color: '#4ade80', border: '1px solid rgba(34,197,94,0.3)' }}
                                                />
                                            )}
                                        </TableCell>

                                        {/* Actions */}
                                        <TableCell sx={cellSx} align="right">
                                            <Tooltip title={`Re-scan ${ev.drive}`}>
                                                <span>
                                                    <IconButton
                                                        size="small"
                                                        onClick={() => handleRescan(ev.drive)}
                                                        disabled={!!rescanning[ev.drive]}
                                                        sx={{
                                                            color: '#818cf8',
                                                            '&:hover': { background: 'rgba(99,102,241,0.12)' },
                                                            '&:disabled': { opacity: 0.3 },
                                                        }}
                                                    >
                                                        {rescanning[ev.drive]
                                                            ? <CircularProgress size={14} color="inherit" />
                                                            : <RefreshIcon fontSize="small" />
                                                        }
                                                    </IconButton>
                                                </span>
                                            </Tooltip>
                                        </TableCell>
                                    </TableRow>

                                    {/* ── Expanded findings ── */}
                                    {expandedId === ev.id && ev.findings && ev.findings.length > 0 && (
                                        <TableRow key={`${ev.id}-findings`}>
                                            <TableCell colSpan={6} sx={{ p: 0, borderColor: 'rgba(99,102,241,0.12)' }}>
                                                <Collapse in>
                                                    <Box sx={{ px: 3, py: 2, background: 'rgba(239,68,68,0.04)' }}>
                                                        <Typography variant="caption" sx={{ color: '#f87171', fontWeight: 700, display: 'block', mb: 1.5 }}>
                                                            🔍 Threat Findings — {ev.drive}
                                                        </Typography>
                                                        <Table size="small">
                                                            <TableHead>
                                                                <TableRow>
                                                                    <TableCell sx={{ ...headSx, borderColor: 'rgba(239,68,68,0.15)' }}>File</TableCell>
                                                                    <TableCell sx={{ ...headSx, borderColor: 'rgba(239,68,68,0.15)' }}>Rule / Reason</TableCell>
                                                                    <TableCell sx={{ ...headSx, borderColor: 'rgba(239,68,68,0.15)' }}>Severity</TableCell>
                                                                </TableRow>
                                                            </TableHead>
                                                            <TableBody>
                                                                {ev.findings.map((f, i) => {
                                                                    const colors = severityColor[f.severity] || severityColor.low
                                                                    return (
                                                                        <TableRow key={i}>
                                                                            <TableCell sx={{ ...cellSx, fontFamily: 'monospace', fontSize: '0.78rem', borderColor: 'rgba(239,68,68,0.1)', color: '#e2e8f0' }}>
                                                                                <Tooltip title={f.full_path || f.file}>
                                                                                    <span>{f.file}</span>
                                                                                </Tooltip>
                                                                            </TableCell>
                                                                            <TableCell sx={{ ...cellSx, fontSize: '0.78rem', borderColor: 'rgba(239,68,68,0.1)' }}>
                                                                                {f.rule}
                                                                            </TableCell>
                                                                            <TableCell sx={{ ...cellSx, borderColor: 'rgba(239,68,68,0.1)' }}>
                                                                                <Chip
                                                                                    label={f.severity.toUpperCase()}
                                                                                    size="small"
                                                                                    sx={{
                                                                                        background: colors.bg,
                                                                                        color: colors.text,
                                                                                        border: `1px solid ${colors.border}`,
                                                                                        fontWeight: 700,
                                                                                        fontSize: '0.65rem',
                                                                                        height: 18,
                                                                                    }}
                                                                                />
                                                                            </TableCell>
                                                                        </TableRow>
                                                                    )
                                                                })}
                                                            </TableBody>
                                                        </Table>
                                                    </Box>
                                                </Collapse>
                                            </TableCell>
                                        </TableRow>
                                    )}
                                </>
                            ))}
                        </TableBody>
                    </Table>
                </TableContainer>
            )}

            <Snackbar
                open={snack.open}
                autoHideDuration={4000}
                onClose={() => setSnack({ ...snack, open: false })}
                anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
            >
                <Alert severity={snack.severity} onClose={() => setSnack({ ...snack, open: false })} sx={{ width: '100%' }}>
                    {snack.message}
                </Alert>
            </Snackbar>
        </Box>
    )
}
