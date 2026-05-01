import { useState, useEffect, useRef } from 'react'
import { Container, Box } from '@mui/material'
import Header from './components/Header'
import StatsCards from './components/StatsCards'
import ThreatChart from './components/ThreatChart'
import ControlPanel from './components/ControlPanel'
import ActivityLog from './components/ActivityLog'
import MonitoredPaths from './components/MonitoredPaths'
import { api } from './services/api'
import EmailAlerts from './components/EmailAlerts'
import ReportExport from './components/ReportExport'
import Honeypot from './components/Honeypot'
import UsbGuard from './components/UsbGuard'

function App() {
    const [status, setStatus] = useState({
        monitoring: false,
        paths: '',
        activities: []
    })
    const [chartData, setChartData] = useState([])
    const [alertSound] = useState(new Audio('/alert.mp3'))
    const prevActiveCountRef = useRef(0)

    useEffect(() => {
        fetchStatus()
        const interval = setInterval(fetchStatus, 3000)
        return () => clearInterval(interval)
    }, [])

    const fetchStatus = async () => {
        try {
            const data = await api.getStatus()
            // Count only active threats (not deleted or marked safe)
            const activeThreats = (data.activities || []).filter(a => !a.action)
            setStatus(data)

            // Update chart data with active threat count only
            setChartData(prev => {
                const newPoint = {
                    time: new Date().toLocaleTimeString(),
                    threats: activeThreats.length
                }
                const updated = [...prev, newPoint].slice(-60)
                return updated
            })

            // Play alert on new active threat (use ref to avoid stale closure)
            if (activeThreats.length > prevActiveCountRef.current) {
                alertSound.play().catch(e => console.log('Audio play failed:', e))
            }
            prevActiveCountRef.current = activeThreats.length
        } catch (error) {
            console.error('Failed to fetch status:', error)
        }
    }

    const handleStart = async () => {
        try {
            await api.startMonitoring()
            fetchStatus()
        } catch (error) {
            console.error('Failed to start monitoring:', error)
        }
    }

    const handleStop = async () => {
        try {
            await api.stopMonitoring()
            fetchStatus()
        } catch (error) {
            console.error('Failed to stop monitoring:', error)
        }
    }

    const handleClear = async () => {
        try {
            await api.clearLogs()
            setChartData([])
            fetchStatus()
        } catch (error) {
            console.error('Failed to clear logs:', error)
        }
    }

    return (
        <Box sx={{
            minHeight: '100vh',
            background: 'linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%)',
            py: 4
        }}>
            <Container maxWidth="xl">
                <Header monitoring={status.monitoring} />

                <StatsCards
                    monitoring={status.monitoring}
                    threatCount={(status.activities || []).filter(a => !a.action).length}
                    paths={status.paths}
                />

                <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '2fr 1fr' }, gap: 3, mt: 3 }}>
                    <ThreatChart data={chartData} activeCount={(status.activities || []).filter(a => !a.action).length} />
                    <MonitoredPaths paths={status.paths} />
                </Box>

                <ControlPanel
                    monitoring={status.monitoring}
                    onStart={handleStart}
                    onStop={handleStop}
                    onClear={handleClear}
                />

                <EmailAlerts />


                <Honeypot />

                <UsbGuard />

                <ReportExport activities={status.activities || []} />

                <ActivityLog activities={status.activities} onActionComplete={fetchStatus} />
            </Container>
        </Box>
    )
}

export default App
