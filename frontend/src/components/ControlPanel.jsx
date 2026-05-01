import { Box, Button } from '@mui/material'
import PlayArrowIcon from '@mui/icons-material/PlayArrow'
import StopIcon from '@mui/icons-material/Stop'
import DeleteSweepIcon from '@mui/icons-material/DeleteSweep'

export default function ControlPanel({ monitoring, onStart, onStop, onClear }) {
    return (
        <Box sx={{
            display: 'flex',
            justifyContent: 'center',
            gap: 2,
            my: 4,
            flexWrap: 'wrap'
        }}>
            <Button
                variant="contained"
                size="large"
                startIcon={<PlayArrowIcon />}
                onClick={onStart}
                disabled={monitoring}
                sx={{
                    px: 4,
                    py: 1.5,
                    background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                    boxShadow: monitoring ? 'none' : '0 4px 20px rgba(16, 185, 129, 0.4)',
                    '&:hover': {
                        background: 'linear-gradient(135deg, #059669 0%, #047857 100%)',
                        boxShadow: '0 6px 24px rgba(16, 185, 129, 0.6)',
                    },
                    '&:disabled': {
                        background: '#374151',
                        color: '#6b7280'
                    }
                }}
            >
                Start Monitoring
            </Button>

            <Button
                variant="contained"
                size="large"
                startIcon={<StopIcon />}
                onClick={onStop}
                disabled={!monitoring}
                sx={{
                    px: 4,
                    py: 1.5,
                    background: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
                    boxShadow: !monitoring ? 'none' : '0 4px 20px rgba(239, 68, 68, 0.4)',
                    '&:hover': {
                        background: 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)',
                        boxShadow: '0 6px 24px rgba(239, 68, 68, 0.6)',
                    },
                    '&:disabled': {
                        background: '#374151',
                        color: '#6b7280'
                    }
                }}
            >
                Stop Monitoring
            </Button>

            <Button
                variant="outlined"
                size="large"
                startIcon={<DeleteSweepIcon />}
                onClick={onClear}
                sx={{
                    px: 4,
                    py: 1.5,
                    borderColor: 'primary.main',
                    color: 'primary.main',
                    borderWidth: 2,
                    '&:hover': {
                        borderWidth: 2,
                        borderColor: 'primary.light',
                        background: 'rgba(124, 58, 237, 0.1)',
                    }
                }}
            >
                Clear Logs
            </Button>
        </Box>
    )
}
