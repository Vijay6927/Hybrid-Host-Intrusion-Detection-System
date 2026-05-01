import { Box, Card, CardContent, Typography } from '@mui/material'
import SecurityIcon from '@mui/icons-material/Security'
import FolderIcon from '@mui/icons-material/Folder'
import AccessTimeIcon from '@mui/icons-material/AccessTime'

export default function StatsCards({ monitoring, threatCount, paths }) {
    const pathCount = paths ? paths.split('\n').filter(p => p.trim()).length : 0

    const stats = [
        {
            title: 'Detected Threats',
            value: threatCount,
            icon: SecurityIcon,
            color: '#ef4444',
            gradient: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)'
        },
        {
            title: 'Monitored Paths',
            value: pathCount,
            icon: FolderIcon,
            color: '#3b82f6',
            gradient: 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)'
        },
        {
            title: 'System Status',
            value: monitoring ? 'Online' : 'Offline',
            icon: AccessTimeIcon,
            color: monitoring ? '#10b981' : '#6b7280',
            gradient: monitoring
                ? 'linear-gradient(135deg, #10b981 0%, #059669 100%)'
                : 'linear-gradient(135deg, #6b7280 0%, #4b5563 100%)'
        }
    ]

    return (
        <Box sx={{
            display: 'grid',
            gridTemplateColumns: { xs: '1fr', sm: 'repeat(3, 1fr)' },
            gap: 3
        }}>
            {stats.map((stat, index) => (
                <Card
                    key={index}
                    sx={{
                        background: 'rgba(30, 27, 75, 0.85)',
                        backdropFilter: 'blur(10px)',
                        border: `1px solid ${stat.color}40`,
                        transition: 'transform 0.3s ease, box-shadow 0.3s ease',
                        '&:hover': {
                            transform: 'translateY(-4px)',
                            boxShadow: `0 8px 24px ${stat.color}40`
                        }
                    }}
                >
                    <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                            <Typography variant="subtitle2" color="text.secondary" sx={{ fontWeight: 600 }}>
                                {stat.title}
                            </Typography>
                            <stat.icon sx={{ color: stat.color, fontSize: 28 }} />
                        </Box>

                        <Typography
                            variant="h3"
                            sx={{
                                fontWeight: 700,
                                background: stat.gradient,
                                backgroundClip: 'text',
                                WebkitBackgroundClip: 'text',
                                WebkitTextFillColor: 'transparent'
                            }}
                        >
                            {stat.value}
                        </Typography>
                    </CardContent>
                </Card>
            ))}
        </Box>
    )
}
