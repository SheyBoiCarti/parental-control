import { Clock } from 'lucide-react'

import type { AccessLog } from '../api/client'

function label(value: string | null): string {
  if (!value) return '-'
  if (value === 'tls_sni') return 'TLS SNI'
  if (value === 'dns_udp') return 'DNS UDP'
  if (value === 'dns_tcp') return 'DNS TCP'
  if (value === 'quic') return 'QUIC'
  return value.replace(/_/g, ' ')
}

export function AccessLogTable({ logs }: { logs: AccessLog[] }) {
  if (logs.length === 0) {
    return <p className="text-gray-500 text-center py-4">No recent activity</p>
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b">
            <th className="text-left py-2 px-3">Time</th>
            <th className="text-left py-2 px-3">Domain</th>
            <th className="text-left py-2 px-3">Action</th>
            <th className="text-left py-2 px-3">Protocol</th>
            <th className="text-left py-2 px-3">Reason</th>
            <th className="text-left py-2 px-3">Rule</th>
            <th className="text-left py-2 px-3">App</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, index) => (
            <tr key={`${log.timestamp}-${index}`} className="border-b hover:bg-gray-50">
              <td className="py-2 px-3 text-gray-500">
                <Clock size={12} className="inline mr-1" />
                {new Date(log.timestamp).toLocaleTimeString()}
              </td>
              <td className="py-2 px-3 font-mono text-xs">{log.domain}</td>
              <td className="py-2 px-3">
                <span className={`badge ${
                  log.action === 'blocked' ? 'badge-blocked' : 'badge-online'
                }`}>
                  {log.action}
                </span>
              </td>
              <td className="py-2 px-3">{label(log.protocol)}</td>
              <td className="py-2 px-3">{label(log.reason)}</td>
              <td className="py-2 px-3">{log.rule_id == null ? '-' : `#${log.rule_id}`}</td>
              <td className="py-2 px-3">{log.app_name || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
