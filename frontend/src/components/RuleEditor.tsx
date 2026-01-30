import { useState, useEffect } from 'react'
import { Rule, AvailableApp, getAvailableApps } from '../api/client'
import { Trash2, Ban, Globe, Gauge } from 'lucide-react'

interface RuleEditorProps {
  rules: Rule[]
  onCreateBandwidthRule: (download: number, upload: number) => void
  onCreateAppBlockRule: (app: string) => void
  onCreateDomainBlockRule: (domain: string) => void
  onDeleteRule: (ruleId: number) => void
}

export default function RuleEditor({
  rules,
  onCreateBandwidthRule,
  onCreateAppBlockRule,
  onCreateDomainBlockRule,
  onDeleteRule,
}: RuleEditorProps) {
  const [availableApps, setAvailableApps] = useState<AvailableApp[]>([])
  const [selectedApp, setSelectedApp] = useState('')
  const [customDomain, setCustomDomain] = useState('')
  const [downloadLimit, setDownloadLimit] = useState(1000)
  const [uploadLimit, setUploadLimit] = useState(500)
  const [activeTab, setActiveTab] = useState<'apps' | 'domains' | 'bandwidth'>('apps')

  useEffect(() => {
    getAvailableApps()
      .then((data) => setAvailableApps(data.apps))
      .catch(console.error)
  }, [])

  const blockedApps = rules
    .filter((r) => r.rule_type === 'block_app')
    .map((r) => (r.rule_value as { app: string }).app)

  const blockedDomains = rules
    .filter((r) => r.rule_type === 'block_domain')
    .map((r) => (r.rule_value as { domain: string }).domain)

  const bandwidthRule = rules.find((r) => r.rule_type === 'bandwidth')

  const handleBlockApp = () => {
    if (selectedApp) {
      onCreateAppBlockRule(selectedApp)
      setSelectedApp('')
    }
  }

  const handleBlockDomain = () => {
    if (customDomain.trim()) {
      onCreateDomainBlockRule(customDomain.trim())
      setCustomDomain('')
    }
  }

  const handleSetBandwidth = () => {
    onCreateBandwidthRule(downloadLimit, uploadLimit)
  }

  return (
    <div className="space-y-6">
      {/* Tab Navigation */}
      <div className="flex space-x-1 bg-gray-100 rounded-lg p-1">
        <button
          onClick={() => setActiveTab('apps')}
          className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'apps'
              ? 'bg-white shadow text-gray-900'
              : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          <Ban size={16} className="inline mr-2" />
          Block Apps
        </button>
        <button
          onClick={() => setActiveTab('domains')}
          className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'domains'
              ? 'bg-white shadow text-gray-900'
              : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          <Globe size={16} className="inline mr-2" />
          Block Domains
        </button>
        <button
          onClick={() => setActiveTab('bandwidth')}
          className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'bandwidth'
              ? 'bg-white shadow text-gray-900'
              : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          <Gauge size={16} className="inline mr-2" />
          Bandwidth
        </button>
      </div>

      {/* App Blocking */}
      {activeTab === 'apps' && (
        <div className="space-y-4">
          <div className="flex space-x-2">
            <select
              value={selectedApp}
              onChange={(e) => setSelectedApp(e.target.value)}
              className="input flex-1"
            >
              <option value="">Select an app to block...</option>
              {availableApps
                .filter((app) => !blockedApps.includes(app.name))
                .map((app) => (
                  <option key={app.name} value={app.name}>
                    {app.name.charAt(0).toUpperCase() + app.name.slice(1)}
                  </option>
                ))}
            </select>
            <button
              onClick={handleBlockApp}
              disabled={!selectedApp}
              className="btn btn-danger"
            >
              Block
            </button>
          </div>

          {blockedApps.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-gray-700 mb-2">Blocked Apps</h4>
              <div className="flex flex-wrap gap-2">
                {rules
                  .filter((r) => r.rule_type === 'block_app')
                  .map((rule) => {
                    const appName = (rule.rule_value as { app: string }).app
                    return (
                      <span
                        key={rule.id}
                        className="inline-flex items-center px-3 py-1 rounded-full bg-red-100 text-red-800 text-sm"
                      >
                        {appName.charAt(0).toUpperCase() + appName.slice(1)}
                        <button
                          onClick={() => onDeleteRule(rule.id)}
                          className="ml-2 hover:text-red-900"
                        >
                          <Trash2 size={14} />
                        </button>
                      </span>
                    )
                  })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Domain Blocking */}
      {activeTab === 'domains' && (
        <div className="space-y-4">
          <div className="flex space-x-2">
            <input
              type="text"
              value={customDomain}
              onChange={(e) => setCustomDomain(e.target.value)}
              placeholder="Enter domain (e.g., example.com)"
              className="input flex-1"
            />
            <button
              onClick={handleBlockDomain}
              disabled={!customDomain.trim()}
              className="btn btn-danger"
            >
              Block
            </button>
          </div>

          {blockedDomains.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-gray-700 mb-2">Blocked Domains</h4>
              <div className="flex flex-wrap gap-2">
                {rules
                  .filter((r) => r.rule_type === 'block_domain')
                  .map((rule) => {
                    const domain = (rule.rule_value as { domain: string }).domain
                    return (
                      <span
                        key={rule.id}
                        className="inline-flex items-center px-3 py-1 rounded-full bg-orange-100 text-orange-800 text-sm font-mono"
                      >
                        {domain}
                        <button
                          onClick={() => onDeleteRule(rule.id)}
                          className="ml-2 hover:text-orange-900"
                        >
                          <Trash2 size={14} />
                        </button>
                      </span>
                    )
                  })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Bandwidth Limiting */}
      {activeTab === 'bandwidth' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Download Limit (Kbps)
              </label>
              <input
                type="number"
                value={downloadLimit}
                onChange={(e) => setDownloadLimit(parseInt(e.target.value) || 0)}
                min={1}
                className="input w-full"
              />
              <p className="text-xs text-gray-500 mt-1">
                {(downloadLimit / 1000).toFixed(1)} Mbps
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Upload Limit (Kbps)
              </label>
              <input
                type="number"
                value={uploadLimit}
                onChange={(e) => setUploadLimit(parseInt(e.target.value) || 0)}
                min={1}
                className="input w-full"
              />
              <p className="text-xs text-gray-500 mt-1">
                {(uploadLimit / 1000).toFixed(1)} Mbps
              </p>
            </div>
          </div>

          <button onClick={handleSetBandwidth} className="btn btn-primary w-full">
            {bandwidthRule ? 'Update Bandwidth Limit' : 'Set Bandwidth Limit'}
          </button>

          {bandwidthRule && (
            <div className="p-4 bg-blue-50 rounded-lg">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-blue-900">Current Limit</p>
                  <p className="text-sm text-blue-700">
                    ↓ {((bandwidthRule.rule_value as { download_kbps: number }).download_kbps / 1000).toFixed(1)} Mbps
                    {' / '}
                    ↑ {((bandwidthRule.rule_value as { upload_kbps: number }).upload_kbps / 1000).toFixed(1)} Mbps
                  </p>
                </div>
                <button
                  onClick={() => onDeleteRule(bandwidthRule.id)}
                  className="text-blue-600 hover:text-blue-800"
                >
                  <Trash2 size={18} />
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
