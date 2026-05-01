import { useState, useEffect, useCallback } from 'react'
import {
    Box, Typography, TextField, Button, MenuItem, Select, FormControl,
    InputLabel, Table, TableBody, TableCell, TableContainer, TableHead,
    TableRow, Paper, Chip, IconButton, Tooltip, Snackbar, Alert,
    Divider, CircularProgress, Collapse
} from '@mui/material'
import BugReportIcon from '@mui/icons-material/BugReport'
import AddIcon from '@mui/icons-material/Add'
import DeleteIcon from '@mui/icons-material/Delete'
import WarningAmberIcon from '@mui/icons-material/WarningAmber'
import CheckCircleIcon from '@mui/icons-material/CheckCircle'
import FolderOpenIcon from '@mui/icons-material/FolderOpen'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import ExpandLessIcon from '@mui/icons-material/ExpandLess'

const POLL_INTERVAL = 5000

export default function Honeypot() {
    const [honeypots, setHoneypots] = useState([])
    const [templates, setTemplates] = useState([])
    const [directory, setDirectory] = useState('')
    const [templateId, setTemplateId] = useState('')
    const [planting, setPlanting] = useState(false)
    const [expandedId, setExpandedId] = useState(null)
    const [snack, setSnack] = useState({ open: false, message: '', severity: 'success' })

    const showSnack = (message, severity = 'success') =>
        setSnack({ open: true, message, severity })

    const fetchHoneypots = useCallback(async () => {
        try {
            const res = await fetch('/api/honeypots')
            const data = await res.json()
            if (data.success) setHoneypots(data.honeypots)
        } catch (_) { }
    }, [])

    const fetchTemplates = useCallback(async () => {
        try {
            const res = await fetch('/api/honeypots/templates')
            const data = await res.json()
            if (data.success) {
                setTemplates(data.templates)
                if (data.templates.length > 0) setTemplateId(data.templates[0].id)
            }
        } catch (_) { }
    }, [])

    useEffect(() => {
        fetchTemplates()
        fetchHoneypots()
        const id = setInterval(fetchHoneypots, POLL_INTERVAL)
        return () => clearInterval(id)
    }, [fetchHoneypots, fetchTemplates])

    const handlePlant = async () => {
        if (!directory.trim() || !templateId) {
            showSnack('Please enter a directory and select a template.', 'warning')
            return
        }
        setPlanting(true)
        try {
            const res = await fetch('/api/honeypots/plant', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: directory.trim(), template_id: templateId }),
            })
            const data = await res.json()
            if (data.success) {
                showSnack(`🍯 Honeypot planted: ${data.honeypot.filename}`)
                fetchHoneypots()
            } else {
                showSnack(`Failed: ${data.message}`, 'error')
            }
        } catch (e) {
            showSnack(`Error: ${e.message}`, 'error')
        } finally {
            setPlanting(false)
        }
    }

    const handleDelete = async (id, filename) => {
        try {
            const res = await fetch(`/api/honeypots/${id}`, { method: 'DELETE' })
            const data = await res.json()
            if (data.success) {
                showSnack(`Deleted honeypot: ${filename}`)
                fetchHoneypots()
            } else {
                showSnack(`Failed: ${data.message}`, 'error')
            }
        } catch (e) {
            showSnack(`Error: ${e.message}`, 'error')
        }
    }

    const cellSx = { color: '#94a3b8', borderColor: 'rgba(124,58,237,0.12)', py: 1 }
    const headSx = { color: '#64748b', borderColor: 'rgba(124,58,237,0.2)', fontWeight: 700, fontSize: '0.72rem', textTransform: 'uppercase', py: 1 }

    return (
        <Box sx={{
            mt: 3,
            mb: 1,
            background: 'rgba(15,23,42,0.6)',
            border: '1px solid rgba(124,58,237,0.18)',
            borderRadius: 2,
            p: 2.5,
            backdropFilter: 'blur(8px)',
        }}>
            {/* Header */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <BugReportIcon sx={{ color: '#f59e0b', fontSize: 20 }} />
                <Typography variant="subtitle1" sx={{ color: '#f59e0b', fontWeight: 700 }}>
                    Honeypot Files
                </Typography>
                <Chip
                    label={`${honeypots.length} planted`}
                    size="small"
                    sx={{ background: 'rgba(245,158,11,0.12)', color: '#f59e0b', borderColor: 'rgba(245,158,11,0.3)', border: '1px solid' }}
                />
                {honeypots.some(h => h.accessed) && (
                    <Chip
                        icon={<WarningAmberIcon fontSize="small" />}
                        label="Access Detected!"
                        size="small"
                        sx={{ background: 'rgba(239,68,68,0.15)', color: '#f87171', borderColor: 'rgba(239,68,68,0.4)', border: '1px solid' }}
                    />
                )}
            </Box>

            <Divider sx={{ borderColor: 'rgba(124,58,237,0.15)', mb: 2 }} />

            {/* Plant form */}
            <Box sx={{ display: 'flex', gap: 1.5, flexWrap: 'wrap', alignItems: 'flex-end', mb: 2.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flex: '1 1 280px' }}>
                    <FolderOpenIcon sx={{ color: '#64748b', fontSize: 18, mt: '18px' }} />
                    <TextField
                        id="honeypot-directory"
                        label="Target Directory"
                        placeholder="e.g. C:\Users\Public"
                        value={directory}
                        onChange={e => setDirectory(e.target.value)}
                        size="small"
                        fullWidth
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                color: '#e2e8f0',
                                '& fieldset': { borderColor: 'rgba(124,58,237,0.3)' },
                                '&:hover fieldset': { borderColor: 'rgba(124,58,237,0.5)' },
                                '&.Mui-focused fieldset': { borderColor: '#7c3aed' },
                            },
                            '& .MuiInputLabel-root': { color: '#64748b' },
                            '& .MuiInputLabel-root.Mui-focused': { color: '#a78bfa' },
                        }}
                    />
                </Box>

                <FormControl size="small" sx={{ flex: '0 1 200px' }}>
                    <InputLabel sx={{ color: '#64748b', '&.Mui-focused': { color: '#a78bfa' } }}>
                        Decoy Template
                    </InputLabel>
                    <Select
                        id="honeypot-template"
                        value={templateId}
                        label="Decoy Template"
                        onChange={e => setTemplateId(e.target.value)}
                        sx={{
                            color: '#e2e8f0',
                            '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(124,58,237,0.3)' },
                            '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(124,58,237,0.5)' },
                            '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: '#7c3aed' },
                            '& .MuiSvgIcon-root': { color: '#64748b' },
                        }}
                        MenuProps={{
                            PaperProps: {
                                sx: { background: '#0f172a', border: '1px solid rgba(124,58,237,0.3)', color: '#e2e8f0' }
                            }
                        }}
                    >
                        {templates.map(t => (
                            <MenuItem key={t.id} value={t.id} sx={{ '&:hover': { background: 'rgba(124,58,237,0.15)' } }}>
                                {t.label}
                            </MenuItem>
                        ))}
                    </Select>
                </FormControl>

                <Button
                    id="plant-honeypot-btn"
                    variant="contained"
                    startIcon={planting ? <CircularProgress size={14} color="inherit" /> : <AddIcon />}
                    onClick={handlePlant}
                    disabled={planting}
                    sx={{
                        background: 'linear-gradient(135deg, #d97706, #f59e0b)',
                        color: '#0f172a',
                        fontWeight: 700,
                        textTransform: 'none',
                        px: 2.5,
                        '&:hover': { background: 'linear-gradient(135deg, #b45309, #d97706)' },
                        '&:disabled': { opacity: 0.5 },
                    }}
                >
                    {planting ? 'Planting…' : 'Plant Honeypot'}
                </Button>
            </Box>

            {/* Honeypot table */}
            {honeypots.length === 0 ? (
                <Box sx={{ textAlign: 'center', py: 3 }}>
                    <Typography variant="body2" sx={{ color: '#475569' }}>
                        No honeypot files planted yet. Use the form above to add decoy files.
                    </Typography>
                </Box>
            ) : (
                <TableContainer component={Paper} sx={{ background: 'transparent', boxShadow: 'none' }}>
                    <Table size="small">
                        <TableHead>
                            <TableRow>
                                <TableCell sx={headSx}>File</TableCell>
                                <TableCell sx={headSx}>Directory</TableCell>
                                <TableCell sx={headSx}>Planted At</TableCell>
                                <TableCell sx={headSx}>Status</TableCell>
                                <TableCell sx={headSx}>Events</TableCell>
                                <TableCell sx={headSx} align="right">Actions</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {honeypots.map(hp => (
                                <>
                                    <TableRow key={hp.id} sx={{ '&:hover': { background: 'rgba(124,58,237,0.05)' } }}>
                                        <TableCell sx={{ ...cellSx, fontFamily: 'monospace', fontSize: '0.82rem', color: '#e2e8f0' }}>
                                            {hp.filename}
                                        </TableCell>
                                        <TableCell sx={{ ...cellSx, fontSize: '0.75rem', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                            <Tooltip title={hp.directory}>
                                                <span>{hp.directory}</span>
                                            </Tooltip>
                                        </TableCell>
                                        <TableCell sx={{ ...cellSx, fontSize: '0.75rem' }}>{hp.planted_at}</TableCell>
                                        <TableCell sx={cellSx}>
                                            {hp.accessed ? (
                                                <Chip
                                                    icon={<WarningAmberIcon fontSize="small" />}
                                                    label="Accessed!"
                                                    size="small"
                                                    sx={{
                                                        background: 'rgba(239,68,68,0.15)',
                                                        color: '#f87171',
                                                        border: '1px solid rgba(239,68,68,0.4)',
                                                        fontWeight: 700,
                                                        animation: 'pulse 2s infinite',
                                                        '@keyframes pulse': {
                                                            '0%, 100%': { opacity: 1 },
                                                            '50%': { opacity: 0.6 },
                                                        },
                                                    }}
                                                />
                                            ) : (
                                                <Chip
                                                    icon={<CheckCircleIcon fontSize="small" />}
                                                    label="Safe"
                                                    size="small"
                                                    sx={{ background: 'rgba(34,197,94,0.1)', color: '#4ade80', border: '1px solid rgba(34,197,94,0.3)' }}
                                                />
                                            )}
                                        </TableCell>
                                        <TableCell sx={cellSx}>
                                            {hp.access_events.length > 0 ? (
                                                <Tooltip title="View access history">
                                                    <Chip
                                                        label={`${hp.access_events.length} event${hp.access_events.length > 1 ? 's' : ''}`}
                                                        size="small"
                                                        onClick={() => setExpandedId(expandedId === hp.id ? null : hp.id)}
                                                        deleteIcon={expandedId === hp.id ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                                                        onDelete={() => setExpandedId(expandedId === hp.id ? null : hp.id)}
                                                        sx={{ background: 'rgba(239,68,68,0.1)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer' }}
                                                    />
                                                </Tooltip>
                                            ) : (
                                                <Typography variant="caption" sx={{ color: '#475569' }}>—</Typography>
                                            )}
                                        </TableCell>
                                        <TableCell sx={cellSx} align="right">
                                            <Tooltip title="Delete honeypot file">
                                                <IconButton
                                                    size="small"
                                                    onClick={() => handleDelete(hp.id, hp.filename)}
                                                    sx={{ color: '#ef4444', '&:hover': { background: 'rgba(239,68,68,0.1)' } }}
                                                >
                                                    <DeleteIcon fontSize="small" />
                                                </IconButton>
                                            </Tooltip>
                                        </TableCell>
                                    </TableRow>
                                    {/* Access event history row */}
                                    {expandedId === hp.id && hp.access_events.length > 0 && (
                                        <TableRow key={`${hp.id}-events`}>
                                            <TableCell colSpan={6} sx={{ p: 0, borderColor: 'rgba(124,58,237,0.12)' }}>
                                                <Collapse in>
                                                    <Box sx={{ px: 3, py: 1.5, background: 'rgba(239,68,68,0.05)' }}>
                                                        <Typography variant="caption" sx={{ color: '#f87171', fontWeight: 700, display: 'block', mb: 1 }}>
                                                            Access History
                                                        </Typography>
                                                        {hp.access_events.map((ev, i) => (
                                                            <Box key={i} sx={{ display: 'flex', gap: 2, mb: 0.5 }}>
                                                                <Typography variant="caption" sx={{ color: '#64748b', fontFamily: 'monospace' }}>
                                                                    {ev.timestamp}
                                                                </Typography>
                                                                <Chip label={ev.event_type} size="small"
                                                                    sx={{ height: 16, fontSize: '0.65rem', background: 'rgba(239,68,68,0.15)', color: '#fca5a5' }} />
                                                            </Box>
                                                        ))}
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
