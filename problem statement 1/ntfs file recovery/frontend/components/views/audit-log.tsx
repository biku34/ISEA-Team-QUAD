'use client'

import { useState, useEffect } from 'react'
import { Clock, Loader, AlertCircle, CheckCircle, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { getAuditLog } from '@/lib/api-client'

interface AuditEntry {
  id: number
  timestamp: string
  user: string
  action: string
  evidence_id: number
  details: string
  ip_address: string
}

export default function AuditLogView() {
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [limit, setLimit] = useState(100)

  useEffect(() => {
    fetchAuditLog()
  }, [limit])

  const fetchAuditLog = async () => {
    setLoading(true)
    setError(null)
    const result = await getAuditLog(limit)
    if (result.error) {
      setError(result.error)
    } else {
      const data = result.data as any
      if (data && Array.isArray(data.logs)) {
        setAuditLog(data.logs)
      } else if (Array.isArray(data)) {
        setAuditLog(data)
      } else {
        setAuditLog([])
      }
    }
    setLoading(false)
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString()
  }

  const getActionColor = (action: string) => {
    if (action.includes('Error') || action.includes('Failed')) return 'text-red-500'
    if (action.includes('Upload') || action.includes('Delete')) return 'text-yellow-500'
    if (action.includes('Success') || action.includes('Verified')) return 'text-[#4fd1c5]'
    return 'text-[#9ca3af]'
  }

  if (loading) {
    return (
      <div className="p-8">
        <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
          <div className="flex justify-center mb-4">
            <Loader size={24} className="animate-spin text-[#4fd1c5]" />
          </div>
          <p className="text-[#9ca3af]">Loading audit log...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[#e5e7eb]">Audit Log</h1>
          <p className="text-[#9ca3af] text-sm mt-1">Chain of custody and activity tracking</p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={() => fetchAuditLog()}
            className="gap-2 bg-[#4fd1c5] text-[#0b0f14] hover:bg-[#45b8ad]"
          >
            <Loader size={16} />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <div className="border border-red-900 rounded bg-red-900/10 p-4 flex gap-3">
          <AlertCircle size={20} className="text-red-500 flex-shrink-0" />
          <div>
            <p className="text-red-400 font-medium">Error</p>
            <p className="text-red-300 text-sm">{error}</p>
          </div>
        </div>
      )}

      <div className="border border-[#1f2933] rounded bg-[#121821] p-4">
        <label className="block text-sm font-medium text-[#e5e7eb] mb-2">
          Show last
        </label>
        <div className="flex gap-2">
          {[50, 100, 500, 1000].map((count) => (
            <Button
              key={count}
              onClick={() => setLimit(count)}
              className={`px-3 py-1 text-sm ${limit === count
                  ? 'bg-[#4fd1c5] text-[#0b0f14]'
                  : 'bg-[#1f2933] text-[#e5e7eb] hover:bg-[#2a3a47]'
                }`}
            >
              {count}
            </Button>
          ))}
        </div>
      </div>

      {auditLog.length > 0 ? (
        <div className="border border-[#1f2933] rounded bg-[#121821] overflow-hidden">
          <div className="max-h-screen overflow-y-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1f2933] bg-[#0b0f14] sticky top-0">
                  <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                    Timestamp
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                    User
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                    Action
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                    Evidence ID
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                    Details
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                    IP Address
                  </th>
                </tr>
              </thead>
              <tbody>
                {auditLog.map((entry) => (
                  <tr
                    key={entry.id}
                    className="border-b border-[#1f2933] hover:bg-[#1f2933] transition-colors"
                  >
                    <td className="px-4 py-2 text-[#9ca3af] text-xs whitespace-nowrap">
                      {formatDate(entry.timestamp)}
                    </td>
                    <td className="px-4 py-2 text-[#e5e7eb]">{entry.user}</td>
                    <td className={`px-4 py-2 font-medium ${getActionColor(entry.action)}`}>
                      {entry.action}
                    </td>
                    <td className="px-4 py-2 text-[#9ca3af] font-mono text-xs">
                      {entry.evidence_id}
                    </td>
                    <td className="px-4 py-2 text-[#9ca3af] text-xs max-w-xs truncate">
                      {entry.details}
                    </td>
                    <td className="px-4 py-2 text-[#9ca3af] font-mono text-xs">
                      {entry.ip_address}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
          <p className="text-[#9ca3af]">No audit entries found.</p>
        </div>
      )}
    </div>
  )
}
