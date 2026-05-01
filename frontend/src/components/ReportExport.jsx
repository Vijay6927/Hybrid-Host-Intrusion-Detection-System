import { useState } from 'react'
import {
    Box, Button, ButtonGroup, ToggleButton, ToggleButtonGroup,
    Typography, Snackbar, Alert, Tooltip, Divider, CircularProgress
} from '@mui/material'
import DownloadIcon from '@mui/icons-material/Download'
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf'
import TableChartIcon from '@mui/icons-material/TableChart'
import FilterListIcon from '@mui/icons-material/FilterList'

export default function ReportExport({ activities = [] }) {
    const [filter, setFilter] = useState('all')
    const [loadingPdf, setLoadingPdf] = useState(false)
    const [snack, setSnack] = useState({ open: false, message: '', severity: 'success' })

    const threatCount = activities.filter(a => a.type === 'threat').length
    const totalCount = activities.length

    const handleCsvExport = () => {
        const url = `/api/report/csv?filter=${filter}`
        const a = document.createElement('a')
        a.href = url
        a.download = ''
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        setSnack({ open: true, message: 'CSV export started — check your downloads!', severity: 'success' })
    }

    const handlePdfExport = async () => {
        setLoadingPdf(true)
        try {
            const response = await fetch(`/api/report/pdf?filter=${filter}`)
            if (!response.ok) {
                const err = await response.json()
                throw new Error(err.message || 'PDF generation failed')
            }
            const blob = await response.blob()
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
            a.href = url
            a.download = `hids_report_${filter}_${timestamp}.pdf`
            document.body.appendChild(a)
            a.click()
            document.body.removeChild(a)
            URL.revokeObjectURL(url)
            setSnack({ open: true, message: 'PDF report downloaded!', severity: 'success' })
        } catch (e) {
            setSnack({ open: true, message: `Export failed: ${e.message}`, severity: 'error' })
        } finally {
            setLoadingPdf(false)
        }
    }

    return (
        <Box sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 2,
            mt: 3,
            mb: 1,
            px: 1,
        }}>
            {/* Left: filter toggle */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <FilterListIcon sx={{ color: '#64748b', fontSize: 16 }} />
                <ToggleButtonGroup
                    value={filter}
                    exclusive
                    onChange={(_, val) => val && setFilter(val)}
                    size="small"
                    sx={{
                        '& .MuiToggleButton-root': {
                            color: '#64748b',
                            borderColor: 'rgba(124,58,237,0.25)',
                            fontSize: '0.72rem',
                            py: 0.4,
                            px: 1.2,
                            textTransform: 'none',
                            '&.Mui-selected': {
                                color: '#a78bfa',
                                background: 'rgba(124,58,237,0.15)',
                                borderColor: 'rgba(124,58,237,0.5)',
                            },
                        }
                    }}
                >
                    <ToggleButton value="all">All Events</ToggleButton>
                    <ToggleButton value="threats">Threats Only</ToggleButton>
                </ToggleButtonGroup>
                <Divider orientation="vertical" flexItem sx={{ borderColor: 'rgba(124,58,237,0.2)', mx: 0.5 }} />
                <Typography variant="caption" sx={{ color: '#64748b' }}>
                    {totalCount} events · {threatCount} threats
                </Typography>
            </Box>

            {/* Right: Export Report label + CSV/PDF buttons grouped together */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                    <DownloadIcon sx={{ color: '#a78bfa', fontSize: 18 }} />
                    <Typography variant="subtitle2" sx={{ color: '#94a3b8', fontWeight: 600 }}>
                        Export Report
                    </Typography>
                </Box>
                <Divider orientation="vertical" flexItem sx={{ borderColor: 'rgba(124,58,237,0.2)' }} />
                <ButtonGroup size="small" variant="outlined">
                    <Tooltip title="Download as CSV (opens in Excel)">
                        <Button
                            id="export-csv-btn"
                            startIcon={<TableChartIcon fontSize="small" />}
                            onClick={handleCsvExport}
                            disabled={totalCount === 0}
                            sx={{
                                borderColor: 'rgba(34,197,94,0.4)',
                                color: '#4ade80',
                                textTransform: 'none',
                                fontWeight: 600,
                                fontSize: '0.8rem',
                                '&:hover': {
                                    borderColor: '#22c55e',
                                    background: 'rgba(34,197,94,0.1)',
                                },
                                '&:disabled': { borderColor: '#374151', color: '#4b5563' },
                            }}
                        >
                            CSV
                        </Button>
                    </Tooltip>

                    <Tooltip title="Download as styled PDF report">
                        <Button
                            id="export-pdf-btn"
                            startIcon={loadingPdf
                                ? <CircularProgress size={14} color="inherit" />
                                : <PictureAsPdfIcon fontSize="small" />
                            }
                            onClick={handlePdfExport}
                            disabled={totalCount === 0 || loadingPdf}
                            sx={{
                                borderColor: 'rgba(239,68,68,0.4)',
                                color: '#f87171',
                                textTransform: 'none',
                                fontWeight: 600,
                                fontSize: '0.8rem',
                                '&:hover': {
                                    borderColor: '#ef4444',
                                    background: 'rgba(239,68,68,0.1)',
                                },
                                '&:disabled': { borderColor: '#374151', color: '#4b5563' },
                            }}
                        >
                            {loadingPdf ? 'Generating…' : 'PDF'}
                        </Button>
                    </Tooltip>
                </ButtonGroup>
            </Box>

            {/* Snackbar */}
            <Snackbar
                open={snack.open}
                autoHideDuration={4000}
                onClose={() => setSnack({ ...snack, open: false })}
                anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
            >
                <Alert
                    severity={snack.severity}
                    onClose={() => setSnack({ ...snack, open: false })}
                    sx={{ width: '100%' }}
                >
                    {snack.message}
                </Alert>
            </Snackbar>
        </Box>
    )
}
