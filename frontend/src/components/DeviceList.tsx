import { Link } from 'react-router-dom'
import { Device } from '../api/client'
import {
  Smartphone,
  Laptop,
  Tv,
  Wifi,
  WifiOff,
  Shield,
  ShieldOff,
  Eye,
  EyeOff,
} from 'lucide-react'

interface DeviceListProps {
  devices: Device[]
  onBlock: (mac: string) => void
  onUnblock: (mac: string) => void
  onMonitor: (mac: string) => void
  onStopMonitor: (mac: string) => void
}

function getDeviceIcon(device: Device) {
  const vendor = (device.vendor || '').toLowerCase()
  const hostname = (device.hostname || '').toLowerCase()

  if (vendor.includes('apple') || hostname.includes('iphone') || hostname.includes('ipad')) {
    return Smartphone
  }
  if (vendor.includes('samsung') || hostname.includes('android') || hostname.includes('galaxy')) {
    return Smartphone
  }
  if (hostname.includes('tv') || vendor.includes('roku') || vendor.includes('amazon')) {
    return Tv
  }

  return Laptop
}

export default function DeviceList({
  devices,
  onBlock,
  onUnblock,
  onMonitor,
  onStopMonitor,
}: DeviceListProps) {
  if (devices.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        <Wifi size={48} className="mx-auto mb-4 opacity-50" />
        <p>No devices found</p>
        <p className="text-sm mt-2">Devices will appear here after a network scan</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {devices.map((device) => {
        const Icon = getDeviceIcon(device)

        return (
          <div
            key={device.mac_address}
            className="card flex items-center justify-between hover:shadow-lg transition-shadow"
          >
            <div className="flex items-center space-x-4">
              <div
                className={`p-3 rounded-full ${
                  device.is_online ? 'bg-green-100 text-green-600' : 'bg-gray-100 text-gray-400'
                }`}
              >
                <Icon size={24} />
              </div>

              <div>
                <Link
                  to={`/devices/${encodeURIComponent(device.mac_address)}`}
                  className="font-medium text-gray-900 hover:text-primary-600"
                >
                  {device.friendly_name}
                </Link>

                <div className="flex items-center space-x-3 text-sm text-gray-500 mt-1">
                  <span>{device.ip_address || 'No IP'}</span>
                  <span className="text-gray-300">|</span>
                  <span className="font-mono text-xs">{device.mac_address}</span>
                  {device.vendor && (
                    <>
                      <span className="text-gray-300">|</span>
                      <span>{device.vendor}</span>
                    </>
                  )}
                </div>

                <div className="flex items-center space-x-2 mt-2">
                  <span
                    className={`badge ${device.is_online ? 'badge-online' : 'badge-offline'}`}
                  >
                    {device.is_online ? (
                      <>
                        <Wifi size={12} className="mr-1" /> Online
                      </>
                    ) : (
                      <>
                        <WifiOff size={12} className="mr-1" /> Offline
                      </>
                    )}
                  </span>

                  {device.is_blocked && (
                    <span className="badge badge-blocked">
                      <Shield size={12} className="mr-1" /> Blocked
                    </span>
                  )}

                  {device.is_monitored && (
                    <span className="badge badge-monitored">
                      <Eye size={12} className="mr-1" /> Monitored
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              {device.is_monitored ? (
                <button
                  onClick={() => onStopMonitor(device.mac_address)}
                  className="btn btn-secondary flex items-center space-x-1"
                  title="Stop monitoring"
                >
                  <EyeOff size={16} />
                  <span className="hidden sm:inline">Stop</span>
                </button>
              ) : (
                <button
                  onClick={() => onMonitor(device.mac_address)}
                  className="btn btn-secondary flex items-center space-x-1"
                  title="Start monitoring"
                  disabled={!device.is_online}
                >
                  <Eye size={16} />
                  <span className="hidden sm:inline">Monitor</span>
                </button>
              )}

              {device.is_blocked ? (
                <button
                  onClick={() => onUnblock(device.mac_address)}
                  className="btn btn-success flex items-center space-x-1"
                  title="Unblock device"
                >
                  <ShieldOff size={16} />
                  <span className="hidden sm:inline">Unblock</span>
                </button>
              ) : (
                <button
                  onClick={() => onBlock(device.mac_address)}
                  className="btn btn-danger flex items-center space-x-1"
                  title="Block device"
                >
                  <Shield size={16} />
                  <span className="hidden sm:inline">Block</span>
                </button>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
