import { Card, CardContent, Typography, Box } from '@mui/material'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts'

export default function ThreatChart({ data, activeCount = 0 }) {
    return (
        <Card sx={{
            background: 'rgba(30, 27, 75, 0.85)',
            backdropFilter: 'blur(10px)',
            border: '1px solid rgba(124, 58, 237, 0.3)',
            height: 400
        }}>
            <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
                    <Typography variant="h6" sx={{ fontWeight: 600, color: 'primary.main' }}>
                        Threat Activity Timeline
                    </Typography>
                    {activeCount > 0 && (
                        <Typography variant="body2" sx={{
                            color: '#ef4444',
                            fontWeight: 700,
                            background: 'rgba(239,68,68,0.1)',
                            border: '1px solid rgba(239,68,68,0.4)',
                            borderRadius: '6px',
                            px: 1.5,
                            py: 0.5
                        }}>
                            ⚠ {activeCount} Active Threat{activeCount !== 1 ? 's' : ''}
                        </Typography>
                    )}
                </Box>

                {data.length > 0 ? (
                    <ResponsiveContainer width="100%" height={300}>
                        <AreaChart data={data}>
                            <defs>
                                <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.8} />
                                    <stop offset="95%" stopColor="#7c3aed" stopOpacity={0.1} />
                                </linearGradient>
                                <linearGradient id="threatGradientActive" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8} />
                                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.1} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(124, 58, 237, 0.1)" />
                            <XAxis
                                dataKey="time"
                                stroke="#888"
                                style={{ fontSize: '11px' }}
                                interval="preserveStartEnd"
                                tickCount={6}
                            />
                            <YAxis
                                stroke="#888"
                                style={{ fontSize: '12px' }}
                                allowDecimals={false}
                                domain={[0, dataMax => Math.max(dataMax, activeCount, 1)]}
                            />
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                                    border: '1px solid rgba(124, 58, 237, 0.5)',
                                    borderRadius: '8px',
                                    color: '#fff'
                                }}
                                formatter={(value) => [value, 'Active Threats']}
                            />
                            {activeCount > 0 && (
                                <ReferenceLine
                                    y={activeCount}
                                    stroke="#ef4444"
                                    strokeDasharray="6 3"
                                    strokeWidth={2}
                                    label={{
                                        value: `${activeCount} active`,
                                        position: 'insideTopRight',
                                        fill: '#ef4444',
                                        fontSize: 12,
                                        fontWeight: 700
                                    }}
                                />
                            )}
                            <Area
                                type="monotone"
                                dataKey="threats"
                                stroke={activeCount > 0 ? "#ef4444" : "#7c3aed"}
                                strokeWidth={2}
                                fillOpacity={1}
                                fill={activeCount > 0 ? "url(#threatGradientActive)" : "url(#threatGradient)"}
                            />
                        </AreaChart>
                    </ResponsiveContainer>
                ) : (
                    <Box sx={{
                        height: 300,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'text.secondary'
                    }}>
                        <Typography>No threat data available yet</Typography>
                    </Box>
                )}
            </CardContent>
        </Card>
    )
}
