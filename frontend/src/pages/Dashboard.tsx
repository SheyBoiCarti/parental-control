import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  getSystemStats,
  getDevices,
  getTopDomains,
  getTopBlocked,
  SystemStats,
  Device,
} from '../api/client'
import { useWebSocket } from '../contexts/WebSocketContext'
import {
  MonitorSmartphone,
  Wifi,
  Eye,
  Shield,
  Activity,
  Globe,
  Ban,
  RefreshCw,
} from 'lucide-react'

export default function Dashboard() {
  const [stats, setStats] = useState<SystemStats | null>(null)
  const [recentDevices, setRecentDevices] = useState<Device[]>([])
  const [topDomains, setTopDomains] = useState<Array<{ domain: string; count: number }>>([])
  const [topBlocked, setTopBlocked] = useState<Array<{ domain: string; app: string | null; count: number }>>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { subscribe } = useWebSocket()

  const fetchData = async () => {
    try {
      setError(null)
      const [statsData, devicesData, domainsData, blockedData] = await Promise.all([
        getSystemStats(),
        getDevices(),
        getTopDomains(24, 10),
        getTopBlocked(24, 10),
      ])

      setStats(statsData)
      setRecentDevices(devicesData.devices.slice(0, 5))
      setTopDomains(domainsData.domains)
      setTopBlocked(blockedData.blocked)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load data')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchData()

    // Subscribe to WebSocket updates
    const unsubDevices = subscribe('devices_list', () => {
      fetchData()
    })

    return () => {
      unsubDevices()
    }
  }, [subscribe])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <p className="text-red-500 mb-4">{error}</p>
        <button onClick={fetchData} className="btn btn-primary">
          <RefreshCw size={16} className="mr-2" />
          Retry
        </button>
      </div>
    )
  }

  const statCards = [
    {
      label: 'Total Devices',
      value: stats?.total_devices || 0,
      icon: MonitorSmartphone,
      color: 'bg-blue-500',
    },
    {
      label: 'Online',
      value: stats?.online_devices || 0,
      icon: Wifi,
      color: 'bg-green-500',
    },
    {
      label: 'Monitored',
      value: stats?.monitored_devices || 0,
      icon: Eye,
      color: 'bg-purple-500',
    },
    {
      label: 'Blocked',
      value: stats?.blocked_devices || 0,
      icon: Shield,
      color: 'bg-red-500',
    },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <button onClick={fetchData} className="btn btn-secondary">
          <RefreshCw size={16} className="mr-2" />
          Refresh
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((stat) => {
          const Icon = stat.icon
          return (
            <div key={stat.label} className="card">
              <div className="flex items-center space-x-4">
                <div className={`p-3 rounded-lg ${stat.color}`}>
                  <Icon size={24} className="text-white" />
                </div>
                <div>
                  <p className="text-sm text-gray-500">{stat.label}</p>
                  <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Activity Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card">
          <div className="flex items-center space-x-2 mb-4">
            <Activity size={20} className="text-primary-600" />
            <h2 className="text-lg font-semibold">Capture Stats</h2>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-gray-600">DNS Queries Captured</span>
              <span className="font-medium">{stats?.dns_queries_captured || 0}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-600">TLS Connections Captured</span>
              <span className="font-medium">{stats?.tls_connections_captured || 0}</span>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <MonitorSmartphone size={20} className="text-primary-600" />
              <h2 className="text-lg font-semibold">Recent Devices</h2>
            </div>
            <Link to="/devices" className="text-sm text-primary-600 hover:underline">
              View all
            </Link>
          </div>
          {recentDevices.length > 0 ? (
            <div className="space-y-2">
              {recentDevices.map((device) => (
                <Link
                  key={device.mac_address}
                  to={`/devices/${encodeURIComponent(device.mac_address)}`}
                  className="flex items-center justify-between p-2 rounded-lg hover:bg-gray-50"
                >
                  <div className="flex items-center space-x-3">
                    <div
                      className={`w-2 h-2 rounded-full ${
                        device.is_online ? 'bg-green-500' : 'bg-gray-300'
                      }`}
                    />
                    <span className="font-medium">{device.friendly_name}</span>
                  </div>
                  <span className="text-sm text-gray-500">{device.ip_address || 'No IP'}</span>
                </Link>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-center py-4">No devices found</p>
          )}
        </div>
      </div>

      {/* Top Domains */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card">
          <div className="flex items-center space-x-2 mb-4">
            <Globe size={20} className="text-primary-600" />
            <h2 className="text-lg font-semibold">Top Domains (24h)</h2>
          </div>
          {topDomains.length > 0 ? (
            <div className="space-y-2">
              {topDomains.map((item, i) => (
                <div key={i} className="flex items-center justify-between">
                  <span className="text-sm font-mono truncate max-w-[200px]">{item.domain}</span>
                  <span className="text-sm text-gray-500">{item.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-center py-4">No data available</p>
          )}
        </div>

        <div className="card">
          <div className="flex items-center space-x-2 mb-4">
            <Ban size={20} className="text-red-600" />
            <h2 className="text-lg font-semibold">Top Blocked (24h)</h2>
          </div>
          {topBlocked.length > 0 ? (
            <div className="space-y-2">
              {topBlocked.map((item, i) => (
                <div key={i} className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="text-sm font-mono truncate max-w-[150px]">{item.domain}</span>
                    {item.app && (
                      <span className="text-xs px-2 py-0.5 bg-red-100 text-red-700 rounded">
                        {item.app}
                      </span>
                    )}
                  </div>
                  <span className="text-sm text-gray-500">{item.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-center py-4">No blocked requests</p>
          )}
        </div>
      </div>
    </div>
  )
}
