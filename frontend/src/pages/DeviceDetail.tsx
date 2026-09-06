import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  getDevice,
  updateDevice,
  getDeviceRules,
  getDeviceBandwidthStats,
  getDeviceAccessStats,
  createBandwidthRule,
  createAppBlockRule,
  createDomainBlockRule,
  deleteRule,
  blockDevice,
  unblockDevice,
  startMonitoring,
  stopMonitoring,
  Device,
  Rule,
  BandwidthStats,
  AccessLog,
} from '../api/client'
import RuleEditor from '../components/RuleEditor'
import BandwidthChart from '../components/BandwidthChart'
import CoverageNotice from '../components/CoverageNotice'
import { AccessLogTable } from '../components/AccessLogTable'
import {
  ArrowLeft,
  Edit2,
  Save,
  X,
  Shield,
  ShieldOff,
  Eye,
  EyeOff,
  Wifi,
  WifiOff,
} from 'lucide-react'

export default function DeviceDetail() {
  const { mac } = useParams<{ mac: string }>()
  const navigate = useNavigate()
  const decodedMac = mac ? decodeURIComponent(mac) : ''

  const [device, setDevice] = useState<Device | null>(null)
  const [rules, setRules] = useState<Rule[]>([])
  const [bandwidthStats, setBandwidthStats] = useState<BandwidthStats | null>(null)
  const [accessLogs, setAccessLogs] = useState<AccessLog[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [isEditing, setIsEditing] = useState(false)
  const [editName, setEditName] = useState('')

  const fetchData = useCallback(async () => {
    if (!decodedMac) return

    try {
      setError(null)
      const [deviceData, rulesData, statsData, accessData] = await Promise.all([
        getDevice(decodedMac),
        getDeviceRules(decodedMac),
        getDeviceBandwidthStats(decodedMac, 24).catch(() => null),
        getDeviceAccessStats(decodedMac, 24, 50).catch(() => ({ logs: [] })),
      ])

      setDevice(deviceData)
      setRules(rulesData.rules)
      setBandwidthStats(statsData)
      setAccessLogs(accessData.logs)
      setEditName(deviceData.friendly_name)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load device')
    } finally {
      setIsLoading(false)
    }
  }, [decodedMac])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const handleSaveName = async () => {
    if (!device || !editName.trim()) return

    try {
      await updateDevice(device.mac_address, { friendly_name: editName.trim() })
      setDevice({ ...device, friendly_name: editName.trim() })
      setIsEditing(false)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update name')
    }
  }

  const handleToggleBlock = async () => {
    if (!device) return

    try {
      if (device.is_blocked) {
        await unblockDevice(device.mac_address)
      } else {
        await blockDevice(device.mac_address)
      }
      await fetchData()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to toggle block')
    }
  }

  const handleToggleMonitor = async () => {
    if (!device) return

    try {
      if (device.is_monitored) {
        await stopMonitoring(device.mac_address)
      } else {
        await startMonitoring(device.mac_address)
      }
      await fetchData()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to toggle monitoring')
    }
  }

  const handleCreateBandwidthRule = async (download: number, upload: number) => {
    if (!device) return

    await createBandwidthRule(device.mac_address, download, upload)
    await fetchData()
  }

  const handleCreateAppBlockRule = async (app: string) => {
    if (!device) return

    await createAppBlockRule(device.mac_address, app)
    await fetchData()
  }

  const handleCreateDomainBlockRule = async (domain: string) => {
    if (!device) return

    await createDomainBlockRule(device.mac_address, domain)
    await fetchData()
  }

  const handleDeleteRule = async (ruleId: number) => {
    if (!device) return

    await deleteRule(device.mac_address, ruleId)
    await fetchData()
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (!device) {
    return (
      <div className="text-center py-12">
        <p className="text-red-500 mb-4">{error || 'Device not found'}</p>
        <button onClick={() => navigate('/devices')} className="btn btn-primary">
          Back to Devices
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center space-x-4">
        <button
          onClick={() => navigate('/devices')}
          className="p-2 hover:bg-gray-100 rounded-lg"
        >
          <ArrowLeft size={24} />
        </button>

        <div className="flex-1">
          {isEditing ? (
            <div className="flex items-center space-x-2">
              <input
                type="text"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                className="input text-xl font-bold"
                autoFocus
              />
              <button onClick={handleSaveName} className="p-2 text-green-600 hover:bg-green-50 rounded">
                <Save size={20} />
              </button>
              <button
                onClick={() => {
                  setIsEditing(false)
                  setEditName(device.friendly_name)
                }}
                className="p-2 text-gray-600 hover:bg-gray-100 rounded"
              >
                <X size={20} />
              </button>
            </div>
          ) : (
            <div className="flex items-center space-x-2">
              <h1 className="text-2xl font-bold text-gray-900">{device.friendly_name}</h1>
              <button
                onClick={() => setIsEditing(true)}
                className="p-1 text-gray-400 hover:text-gray-600"
              >
                <Edit2 size={16} />
              </button>
            </div>
          )}
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleToggleMonitor}
            disabled={!device.is_online && !device.is_monitored}
            className={`btn ${device.is_monitored ? 'btn-secondary' : 'btn-primary'}`}
          >
            {device.is_monitored ? (
              <>
                <EyeOff size={16} className="mr-2" /> Stop Monitoring
              </>
            ) : (
              <>
                <Eye size={16} className="mr-2" /> Start Monitoring
              </>
            )}
          </button>

          <button
            onClick={handleToggleBlock}
            className={`btn ${device.is_blocked ? 'btn-success' : 'btn-danger'}`}
          >
            {device.is_blocked ? (
              <>
                <ShieldOff size={16} className="mr-2" /> Unblock
              </>
            ) : (
              <>
                <Shield size={16} className="mr-2" /> Block
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          {error}
          <button onClick={() => setError(null)} className="ml-4 underline">
            Dismiss
          </button>
        </div>
      )}

      {(device.is_monitored || device.is_blocked || rules.some((rule) => rule.is_active)) && (
        <CoverageNotice />
      )}

      {/* Device Info */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Device Information</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <p className="text-sm text-gray-500">Status</p>
            <p className="font-medium flex items-center">
              {device.is_online ? (
                <>
                  <Wifi size={16} className="text-green-500 mr-1" /> Online
                </>
              ) : (
                <>
                  <WifiOff size={16} className="text-gray-400 mr-1" /> Offline
                </>
              )}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-500">IP Address</p>
            <p className="font-medium font-mono">{device.ip_address || 'N/A'}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">MAC Address</p>
            <p className="font-medium font-mono text-sm">{device.mac_address}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Vendor</p>
            <p className="font-medium">{device.vendor || 'Unknown'}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Hostname</p>
            <p className="font-medium">{device.hostname || 'N/A'}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">First Seen</p>
            <p className="font-medium text-sm">
              {device.first_seen ? new Date(device.first_seen).toLocaleString() : 'N/A'}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Last Seen</p>
            <p className="font-medium text-sm">
              {device.last_seen ? new Date(device.last_seen).toLocaleString() : 'N/A'}
            </p>
          </div>
        </div>
      </div>

      {/* Rules */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Rules & Restrictions</h2>
        <RuleEditor
          rules={rules}
          onCreateBandwidthRule={handleCreateBandwidthRule}
          onCreateAppBlockRule={handleCreateAppBlockRule}
          onCreateDomainBlockRule={handleCreateDomainBlockRule}
          onDeleteRule={handleDeleteRule}
        />
      </div>

      {/* Bandwidth Chart */}
      {bandwidthStats && bandwidthStats.hourly_stats.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Bandwidth Usage (24h)</h2>
          <BandwidthChart data={bandwidthStats.hourly_stats} />
        </div>
      )}

      {/* Access Logs */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Recent Activity</h2>
        <AccessLogTable logs={accessLogs} />
      </div>
    </div>
  )
}
