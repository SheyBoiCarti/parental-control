import { useState, useEffect, useCallback } from 'react'
import {
  getDevices,
  blockDevice,
  unblockDevice,
  startMonitoring,
  stopMonitoring,
  scanNetwork,
  Device,
} from '../api/client'
import { useWebSocket } from '../contexts/WebSocketContext'
import DeviceList from '../components/DeviceList'
import { RefreshCw, Search, Filter } from 'lucide-react'

type FilterType = 'all' | 'online' | 'offline' | 'monitored' | 'blocked'

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([])
  const [filteredDevices, setFilteredDevices] = useState<Device[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isScanning, setIsScanning] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [filter, setFilter] = useState<FilterType>('all')
  const [error, setError] = useState<string | null>(null)
  const { subscribe } = useWebSocket()

  const fetchDevices = useCallback(async () => {
    try {
      setError(null)
      const data = await getDevices()
      setDevices(data.devices)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load devices')
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchDevices()

    // Subscribe to real-time updates
    const unsubList = subscribe('devices_list', (data: unknown) => {
      setDevices(data as Device[])
    })

    const unsubUpdate = subscribe('device_update', (data: unknown) => {
      const updatedDevice = data as Device
      setDevices((prev) => prev.some((d) => d.mac_address === updatedDevice.mac_address)
        ? prev.map((d) => (d.mac_address === updatedDevice.mac_address ? updatedDevice : d))
        : [...prev, updatedDevice])
    })

    return () => {
      unsubList()
      unsubUpdate()
    }
  }, [fetchDevices, subscribe])

  // Apply filters and search
  useEffect(() => {
    let result = [...devices]

    // Apply filter
    switch (filter) {
      case 'online':
        result = result.filter((d) => d.is_online)
        break
      case 'offline':
        result = result.filter((d) => !d.is_online)
        break
      case 'monitored':
        result = result.filter((d) => d.is_monitored)
        break
      case 'blocked':
        result = result.filter((d) => d.is_blocked)
        break
    }

    // Apply search
    if (searchTerm) {
      const term = searchTerm.toLowerCase()
      result = result.filter(
        (d) =>
          d.friendly_name.toLowerCase().includes(term) ||
          d.mac_address.toLowerCase().includes(term) ||
          (d.ip_address && d.ip_address.includes(term)) ||
          (d.hostname && d.hostname.toLowerCase().includes(term)) ||
          (d.vendor && d.vendor.toLowerCase().includes(term))
      )
    }

    setFilteredDevices(result)
  }, [devices, filter, searchTerm])

  const handleScan = async () => {
    setIsScanning(true)
    try {
      const data = await scanNetwork()
      setDevices(data.devices)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Scan failed')
    } finally {
      setIsScanning(false)
    }
  }

  const handleBlock = async (mac: string) => {
    try {
      await blockDevice(mac)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to block device')
    } finally {
      await fetchDevices()
    }
  }

  const handleUnblock = async (mac: string) => {
    try {
      await unblockDevice(mac)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to unblock device')
    } finally {
      await fetchDevices()
    }
  }

  const handleMonitor = async (mac: string) => {
    try {
      await startMonitoring(mac)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to start monitoring')
    } finally {
      await fetchDevices()
    }
  }

  const handleStopMonitor = async (mac: string) => {
    try {
      await stopMonitoring(mac)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to stop monitoring')
    } finally {
      await fetchDevices()
    }
  }

  const filterOptions: Array<{ value: FilterType; label: string }> = [
    { value: 'all', label: 'All Devices' },
    { value: 'online', label: 'Online' },
    { value: 'offline', label: 'Offline' },
    { value: 'monitored', label: 'Monitored' },
    { value: 'blocked', label: 'Blocked' },
  ]

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Devices</h1>
        <button
          onClick={handleScan}
          disabled={isScanning}
          className="btn btn-primary flex items-center"
        >
          <RefreshCw size={16} className={`mr-2 ${isScanning ? 'animate-spin' : ''}`} />
          {isScanning ? 'Scanning...' : 'Scan Network'}
        </button>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          {error}
          <button onClick={() => setError(null)} className="ml-4 underline">
            Dismiss
          </button>
        </div>
      )}

      {/* Search and Filter */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search
            size={20}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"
          />
          <input
            type="text"
            placeholder="Search by name, IP, MAC, or vendor..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="input w-full pl-10"
          />
        </div>

        <div className="relative">
          <Filter
            size={20}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"
          />
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value as FilterType)}
            className="input pl-10 pr-8 appearance-none"
          >
            {filterOptions.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Device Count */}
      <p className="text-sm text-gray-500">
        Showing {filteredDevices.length} of {devices.length} devices
      </p>

      {/* Device List */}
      <DeviceList
        devices={filteredDevices}
        onBlock={handleBlock}
        onUnblock={handleUnblock}
        onMonitor={handleMonitor}
        onStopMonitor={handleStopMonitor}
      />
    </div>
  )
}
