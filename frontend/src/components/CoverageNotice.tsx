import { AlertTriangle } from 'lucide-react'


export default function CoverageNotice() {
  return (
    <aside className="p-4 rounded-lg border border-amber-300 bg-amber-50 text-amber-950">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 shrink-0" size={20} aria-hidden="true" />
        <div className="space-y-1 text-sm">
          <p className="font-semibold">Network protection coverage</p>
          <p>
            Controls apply to IPv4 devices on the same local network. Content rules inspect
            ordinary DNS over UDP or TCP port 53 and TLS SNI over TCP port 443. UDP port 443
            is blocked for restricted devices so clients can fall back from QUIC to TCP.
          </p>
          <p>
            IPv6, encrypted DNS, encrypted ClientHello, VPNs, alternate gateways, MAC
            spoofing, and nonstandard ports can bypass these controls.
          </p>
        </div>
      </div>
    </aside>
  )
}
