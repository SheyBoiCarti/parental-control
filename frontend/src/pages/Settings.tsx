import { useState, useEffect } from 'react'
import { getNetworkInfo, changePassword } from '../api/client'
import { useAuth } from '../contexts/AuthContext'
import {
  Network,
  Shield,
  Eye,
  Activity,
  Lock,
  CheckCircle,
  AlertCircle,
} from 'lucide-react'

interface NetworkInfo {
  interface: string
  local_mac: string
  gateway_ip: string
  gateway_mac: string
  subnet: string
  arp_spoof_active: boolean
  active_spoof_targets: number
  packet_analyzer_running: boolean
}

export default function Settings() {
  const { username } = useAuth()
  const [networkInfo, setNetworkInfo] = useState<NetworkInfo | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [newPassword, setNewPassword] = useState('')
  const [currentPassword, setCurrentPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [passwordSuccess, setPasswordSuccess] = useState(false)
  const [isChangingPassword, setIsChangingPassword] = useState(false)

  useEffect(() => {
    fetchNetworkInfo()
  }, [])

  const fetchNetworkInfo = async () => {
    try {
      setError(null)
      const info = await getNetworkInfo()
      setNetworkInfo(info)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load network info')
    } finally {
      setIsLoading(false)
    }
  }

  const handleChangePassword = async () => {
    setPasswordError(null)
    setPasswordSuccess(false)

    if (newPassword.length < 8) {
      setPasswordError('Password must be at least 8 characters')
      return
    }

    if (newPassword !== confirmPassword) {
      setPasswordError('Passwords do not match')
      return
    }

    setIsChangingPassword(true)

    try {
      await changePassword(currentPassword, newPassword)
      setPasswordSuccess(true)
      setNewPassword('')
      setCurrentPassword('')
      setConfirmPassword('')
    } catch (e) {
      setPasswordError(e instanceof Error ? e.message : 'Failed to change password')
    } finally {
      setIsChangingPassword(false)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <h1 className="text-2xl font-bold text-gray-900">Settings</h1>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          {error}
        </div>
      )}

      {/* Network Configuration */}
      <div className="card">
        <div className="flex items-center space-x-2 mb-4">
          <Network size={20} className="text-primary-600" />
          <h2 className="text-lg font-semibold">Network Configuration</h2>
        </div>

        {networkInfo ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-500">Interface</p>
                <p className="font-mono font-medium">{networkInfo.interface}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Subnet</p>
                <p className="font-mono font-medium">{networkInfo.subnet || 'N/A'}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Local MAC</p>
                <p className="font-mono font-medium text-sm">{networkInfo.local_mac || 'N/A'}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Gateway IP</p>
                <p className="font-mono font-medium">{networkInfo.gateway_ip || 'N/A'}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Gateway MAC</p>
                <p className="font-mono font-medium text-sm">{networkInfo.gateway_mac || 'N/A'}</p>
              </div>
            </div>

            <hr />

            <div className="grid grid-cols-3 gap-4">
              <div className="flex items-center space-x-2">
                <div
                  className={`p-2 rounded-full ${
                    networkInfo.arp_spoof_active ? 'bg-green-100' : 'bg-gray-100'
                  }`}
                >
                  <Shield
                    size={20}
                    className={networkInfo.arp_spoof_active ? 'text-green-600' : 'text-gray-400'}
                  />
                </div>
                <div>
                  <p className="text-sm text-gray-500">ARP Spoofer</p>
                  <p className="font-medium">
                    {networkInfo.arp_spoof_active ? 'Active' : 'Inactive'}
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                <div
                  className={`p-2 rounded-full ${
                    networkInfo.active_spoof_targets > 0 ? 'bg-blue-100' : 'bg-gray-100'
                  }`}
                >
                  <Eye
                    size={20}
                    className={
                      networkInfo.active_spoof_targets > 0 ? 'text-blue-600' : 'text-gray-400'
                    }
                  />
                </div>
                <div>
                  <p className="text-sm text-gray-500">Monitored Devices</p>
                  <p className="font-medium">{networkInfo.active_spoof_targets}</p>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                <div
                  className={`p-2 rounded-full ${
                    networkInfo.packet_analyzer_running ? 'bg-green-100' : 'bg-gray-100'
                  }`}
                >
                  <Activity
                    size={20}
                    className={
                      networkInfo.packet_analyzer_running ? 'text-green-600' : 'text-gray-400'
                    }
                  />
                </div>
                <div>
                  <p className="text-sm text-gray-500">Packet Analyzer</p>
                  <p className="font-medium">
                    {networkInfo.packet_analyzer_running ? 'Running' : 'Stopped'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <p className="text-gray-500">Network info unavailable</p>
        )}
      </div>

      {/* Change Password */}
      <div className="card">
        <div className="flex items-center space-x-2 mb-4">
          <Lock size={20} className="text-primary-600" />
          <h2 className="text-lg font-semibold">Change Password</h2>
        </div>

        <div className="space-y-4 max-w-md">
          <div>
            <p className="text-sm text-gray-500 mb-2">
              Logged in as: <span className="font-medium">{username}</span>
            </p>
          </div>

          {passwordSuccess && (
            <div className="flex items-center space-x-2 p-3 bg-green-50 border border-green-200 rounded-lg text-green-700">
              <CheckCircle size={20} />
              <span>Password changed successfully</span>
            </div>
          )}

          {passwordError && (
            <div className="flex items-center space-x-2 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700">
              <AlertCircle size={20} />
              <span>{passwordError}</span>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Current Password
            </label>
            <input
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="input w-full"
              placeholder="Enter current password"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              New Password
            </label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="input w-full"
              placeholder="Enter new password"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Confirm Password
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="input w-full"
              placeholder="Confirm new password"
            />
          </div>

          <button
            onClick={handleChangePassword}
            disabled={isChangingPassword || !currentPassword || !newPassword || !confirmPassword}
            className="btn btn-primary"
          >
            {isChangingPassword ? 'Changing...' : 'Change Password'}
          </button>
        </div>
      </div>

      {/* About */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">About</h2>
        <div className="space-y-2 text-sm text-gray-600">
          <p>
            <strong>Parental Control Network Manager</strong> v1.0.0
          </p>
          <p>A Linux-based network management tool for parental control.</p>
          <p className="text-gray-400">
            Uses ARP spoofing for traffic interception, iptables for blocking, and tc for
            bandwidth limiting.
          </p>
        </div>
      </div>
    </div>
  )
}
