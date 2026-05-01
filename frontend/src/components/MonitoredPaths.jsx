import { Card, CardContent, Typography, Box } from '@mui/material'
import FolderOpenIcon from '@mui/icons-material/FolderOpen'

export default function MonitoredPaths({ paths }) {
    const pathList = paths ? paths.split('\n').filter(p => p.trim()) : []

    return (
        <Card sx={{
            background: 'rgba(30, 27, 75, 0.85)',
            backdropFilter: 'blur(10px)',
            border: '1px solid rgba(59, 130, 246, 0.3)',
            height: 400
        }}>
            <CardContent>
                <Typography variant="h6" sx={{ mb: 3, fontWeight: 600, color: 'secondary.main' }}>
                    Monitored Paths
                </Typography>

                <Box sx={{
                    maxHeight: 320,
                    overflowY: 'auto',
                    pr: 1
                }}>
                    {pathList.length > 0 ? (
                        pathList.map((path, index) => (
                            <Box
                                key={index}
                                sx={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: 2,
                                    p: 2,
                                    mb: 1,
                                    background: 'rgba(59, 130, 246, 0.1)',
                                    border: '1px solid rgba(59, 130, 246, 0.2)',
                                    borderRadius: 2,
                                    transition: 'all 0.3s ease',
                                    '&:hover': {
                                        background: 'rgba(59, 130, 246, 0.2)',
                                        transform: 'translateX(4px)'
                                    }
                                }}
                            >
                                <FolderOpenIcon sx={{ color: 'secondary.main', fontSize: 24 }} />
                                <Typography
                                    sx={{
                                        fontFamily: 'monospace',
                                        fontSize: '0.9rem',
                                        wordBreak: 'break-all'
                                    }}
                                >
                                    {path}
                                </Typography>
                            </Box>
                        ))
                    ) : (
                        <Box sx={{
                            height: 280,
                            display: 'flex',
                            flexDirection: 'column',
                            alignItems: 'center',
                            justifyContent: 'center',
                            color: 'text.secondary'
                        }}>
                            <FolderOpenIcon sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
                            <Typography>No paths configured</Typography>
                        </Box>
                    )}
                </Box>
            </CardContent>
        </Card>
    )
}
