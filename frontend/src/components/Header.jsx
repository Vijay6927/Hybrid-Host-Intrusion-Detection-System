import { Box, Typography, Chip } from '@mui/material'
import ShieldIcon from '@mui/icons-material/Shield'
import FiberManualRecordIcon from '@mui/icons-material/FiberManualRecord'

export default function Header({ monitoring }) {
    return (
        <Box sx={{
            textAlign: 'center',
            mb: 4,
            position: 'relative'
        }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 2 }}>
                <ShieldIcon sx={{
                    fontSize: 80,
                    color: 'primary.main',
                    filter: 'drop-shadow(0 0 20px rgba(124, 58, 237, 0.6))',
                    animation: monitoring ? 'pulse 2s ease-in-out infinite' : 'none'
                }} />

                <Box>
                    <Typography
                        variant="h2"
                        sx={{
                            fontWeight: 700,
                            background: 'linear-gradient(135deg, #7c3aed 0%, #3b82f6 100%)',
                            backgroundClip: 'text',
                            WebkitBackgroundClip: 'text',
                            WebkitTextFillColor: 'transparent',
                            textShadow: '0 0 40px rgba(124, 58, 237, 0.3)',
                            mb: 1
                        }}
                    >
                        HIDS Monitor
                    </Typography>

                    <Chip
                        icon={<FiberManualRecordIcon />}
                        label={monitoring ? 'Active Monitoring' : 'Monitoring Stopped'}
                        color={monitoring ? 'success' : 'default'}
                        sx={{
                            fontWeight: 600,
                            fontSize: '1rem',
                            px: 2,
                            animation: monitoring ? 'pulse 2s ease-in-out infinite' : 'none'
                        }}
                    />
                </Box>
            </Box>
        </Box>
    )
}
