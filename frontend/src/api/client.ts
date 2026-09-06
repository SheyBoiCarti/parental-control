/**
 * API client for communicating with the Parental Control backend
 */

const API_BASE = '/api'

// Types
export type EnforcementState = 'pending' | 'applied' | 'error' | 'inactive'

export interface EnforcementStatus {
  state: EnforcementState
  last_error: string | null
  updated_at: string
}

export interface DeviceEnforcement extends EnforcementStatus {
  components: Record<'interception' | 'blocking' | 'content' | 'bandwidth', EnforcementStatus>
}

export interface Device {
  id: number
  mac_address: string
  ip_address: string | null
  hostname: string | null
  vendor: string | null
  friendly_name: string
  is_monitored: boolean
  is_blocked: boolean
  first_seen: string | null
  last_seen: string | null
  is_online: boolean
  enforcement: DeviceEnforcement
}

export interface Rule {
  id: number
  device_id: number
  rule_type: 'bandwidth' | 'block_app' | 'block_domain'
  rule_value: Record<string, unknown>
  is_active: boolean
  created_at: string | null
  validation_error: string | null
  enforcement: EnforcementStatus
}

export interface SystemStats {
  total_devices: number
  online_devices: number
  monitored_devices: number
  blocked_devices: number
  dns_queries_captured: number
  tls_connections_captured: number
}

export interface BandwidthStats {
  mac_address: string
  total_bytes_sent: number
  total_bytes_received: number
  hourly_stats: Array<{
    hour: string
    bytes_sent: number
    bytes_received: number
  }>
}

export interface AccessLog {
  timestamp: string
  domain: string
  action: 'allowed' | 'blocked'
  app_name: string | null
  rule_id: number | null
  protocol: string | null
  reason: string | null
}

export interface AvailableApp {
  name: string
  domains: string[]
}

export interface SessionInfo { username: string; csrf_token: string; expires_at: string }
let csrfToken: string | null = null
const expiredListeners = new Set<() => void>()
export function setSessionCsrf(token: string | null) { csrfToken = token }
export function invalidateSession() {
  csrfToken = null
  expiredListeners.forEach(listener => listener())
}
export function onSessionExpired(listener: () => void) {
  expiredListeners.add(listener)
  return () => { expiredListeners.delete(listener) }
}
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
    public enforcement?: Partial<DeviceEnforcement>,
  ) { super(message) }
}

// API request helper
async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {},
  notifyUnauthorized = true
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  }

  if (csrfToken && !['GET', 'HEAD', 'OPTIONS'].includes(options.method || 'GET')) {
    headers['X-CSRF-Token'] = csrfToken
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
    credentials: 'same-origin',
  })

  if (response.status === 401) {
    if (notifyUnauthorized) invalidateSession()
    throw new ApiError(401, 'Invalid credentials or expired session')
  }

  if (!response.ok) {
    const error: unknown = await response.json().catch(() => ({ detail: 'Unknown error' }))
    const detail = error && typeof error === 'object' && 'detail' in error
      ? (error as { detail: unknown }).detail
      : 'Unknown error'
    if (detail && typeof detail === 'object') {
      const structured = detail as {
        code?: unknown
        enforcement?: { last_error?: unknown }
      }
      const code = typeof structured.code === 'string' ? structured.code : undefined
      const message = typeof structured.enforcement?.last_error === 'string'
        ? structured.enforcement.last_error
        : code || `Request failed (${response.status})`
      throw new ApiError(
        response.status,
        message,
        code,
        structured.enforcement as Partial<DeviceEnforcement> | undefined,
      )
    }
    throw new ApiError(
      response.status,
      typeof detail === 'string' ? detail : `Request failed (${response.status})`,
    )
  }

  return response.status === 204 ? undefined as T : response.json()
}

export function getSession(signal?: AbortSignal): Promise<SessionInfo> {
  return apiRequest('/auth/session', { signal }, false)
}
export function loginSession(username: string, password: string): Promise<SessionInfo> {
  return apiRequest('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }, false)
}
export function logoutSession(): Promise<void> {
  return apiRequest('/auth/logout', { method: 'POST' })
}

// Device APIs
export async function getDevices(): Promise<{ devices: Device[]; total: number }> {
  return apiRequest('/devices')
}

export async function getDevice(mac: string): Promise<Device> {
  return apiRequest(`/devices/${encodeURIComponent(mac)}`)
}

export async function updateDevice(
  mac: string,
  data: { friendly_name?: string; is_monitored?: boolean; is_blocked?: boolean }
): Promise<Device> {
  return apiRequest(`/devices/${encodeURIComponent(mac)}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  })
}

export async function blockDevice(mac: string): Promise<void> {
  return apiRequest(`/devices/${encodeURIComponent(mac)}/block`, {
    method: 'POST',
  })
}

export async function unblockDevice(mac: string): Promise<void> {
  return apiRequest(`/devices/${encodeURIComponent(mac)}/block`, {
    method: 'DELETE',
  })
}

export async function startMonitoring(mac: string): Promise<void> {
  return apiRequest(`/devices/${encodeURIComponent(mac)}/monitor`, {
    method: 'POST',
  })
}

export async function stopMonitoring(mac: string): Promise<void> {
  return apiRequest(`/devices/${encodeURIComponent(mac)}/monitor`, {
    method: 'DELETE',
  })
}

export async function scanNetwork(): Promise<{ devices: Device[]; total: number }> {
  return apiRequest('/devices/scan', { method: 'POST' })
}

// Rules APIs
export async function getDeviceRules(mac: string): Promise<{ rules: Rule[]; total: number }> {
  return apiRequest(`/devices/${encodeURIComponent(mac)}/rules`)
}

export async function createBandwidthRule(
  mac: string,
  download_kbps: number,
  upload_kbps: number
): Promise<Rule> {
  return apiRequest(`/devices/${encodeURIComponent(mac)}/rules/bandwidth`, {
    method: 'POST',
    body: JSON.stringify({ download_kbps, upload_kbps }),
  })
}

export async function createAppBlockRule(mac: string, app: string): Promise<Rule> {
  return apiRequest(`/devices/${encodeURIComponent(mac)}/rules/block-app`, {
    method: 'POST',
    body: JSON.stringify({ app }),
  })
}

export async function createDomainBlockRule(mac: string, domain: string): Promise<Rule> {
  return apiRequest(`/devices/${encodeURIComponent(mac)}/rules/block-domain`, {
    method: 'POST',
    body: JSON.stringify({ domain }),
  })
}

export async function deleteRule(mac: string, ruleId: number): Promise<void> {
  return apiRequest(`/devices/${encodeURIComponent(mac)}/rules/${ruleId}`, {
    method: 'DELETE',
  })
}

export async function getAvailableApps(): Promise<{ apps: AvailableApp[] }> {
  return apiRequest('/devices/_/rules/apps/available')
}

// Stats APIs
export async function getSystemStats(): Promise<SystemStats> {
  return apiRequest('/stats/system')
}

export async function getDeviceBandwidthStats(
  mac: string,
  hours: number = 24
): Promise<BandwidthStats> {
  return apiRequest(`/stats/devices/${encodeURIComponent(mac)}/bandwidth?hours=${hours}`)
}

export async function getDeviceAccessStats(
  mac: string,
  hours: number = 24,
  limit: number = 100
): Promise<{ mac_address: string; total_requests: number; blocked_requests: number; logs: AccessLog[] }> {
  return apiRequest(`/stats/devices/${encodeURIComponent(mac)}/access?hours=${hours}&limit=${limit}`)
}

export async function getTopDomains(
  hours: number = 24,
  limit: number = 20
): Promise<{ domains: Array<{ domain: string; count: number }> }> {
  return apiRequest(`/stats/top-domains?hours=${hours}&limit=${limit}`)
}

export async function getTopBlocked(
  hours: number = 24,
  limit: number = 20
): Promise<{ blocked: Array<{ domain: string; app: string | null; count: number }> }> {
  return apiRequest(`/stats/top-blocked?hours=${hours}&limit=${limit}`)
}

// Settings APIs
export async function getNetworkInfo(): Promise<{
  interface: string
  local_mac: string
  gateway_ip: string
  gateway_mac: string
  subnet: string
  arp_spoof_active: boolean
  active_spoof_targets: number
  packet_analyzer_running: boolean
}> {
  return apiRequest('/settings/network/info')
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  await apiRequest('/settings/password', {
    method: 'POST',
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  })
  invalidateSession()
}

// Health check
export async function healthCheck(): Promise<{ status: string }> {
  const response = await fetch('/health')
  return response.json()
}
