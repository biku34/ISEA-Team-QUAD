'use client'

import { useState, useEffect } from 'react'
import { Loader, AlertCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { listEvidence, listPartitions, scanPartitions } from '@/lib/api-client'

interface Partition {
  id: number
  partition_number: number
  filesystem_type: string
  start_offset: number
  size_bytes: number
}

interface Evidence {
  id: number
  filename: string
}

export default function PartitionsView() {
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([])
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<number | null>(null)
  const [partitions, setPartitions] = useState<Partition[]>([])
  const [loading, setLoading] = useState(true)
  const [partitionsLoading, setPartitionsLoading] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedEvidence, setSelectedEvidence] = useState<string>('EVD001')


  // Fetch evidence list on mount
  useEffect(() => {
    fetchEvidence()
  }, [])

  // Fetch partitions when evidence changes
  useEffect(() => {
    if (selectedEvidenceId) {
      fetchPartitions(selectedEvidenceId)
    }
  }, [selectedEvidenceId])

  const fetchEvidence = async () => {
    setLoading(true)
    const result = await listEvidence()
    if (result.error) {
      setError(result.error)
    } else {
      const evidence = (result.data as any)?.evidence || []
      setEvidenceList(evidence)
      if (evidence.length > 0) {
        setSelectedEvidenceId(evidence[0].id)
      }
    }
    setLoading(false)
  }

  const fetchPartitions = async (evidenceId: number) => {
    setPartitionsLoading(true)
    setError(null)
    const result = await listPartitions(evidenceId)
    if (result.error) {
      setError(result.error)
      setPartitions([])
    } else {
      // Ensure result.data is an array or extract it if wrapped
      const data = result.data
      if (Array.isArray(data)) {
        setPartitions(data)
      } else if (data && typeof data === 'object' && 'partitions' in data && Array.isArray((data as any).partitions)) {
        setPartitions((data as any).partitions)
      } else {
        console.warn('listPartitions returned unexpected data structure:', data)
        setPartitions([])
      }
    }
    setPartitionsLoading(false)
  }

  const handleScanPartitions = async () => {
    if (!selectedEvidenceId) return
    setScanning(true)
    setError(null)
    const result = await scanPartitions(selectedEvidenceId)
    if (result.error) {
      setError(result.error)
    } else {
      await fetchPartitions(selectedEvidenceId)
    }
    setScanning(false)
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
  }

  if (loading) {
    return (
      <div className="p-8">
        <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
          <div className="flex justify-center mb-4">
            <Loader size={24} className="animate-spin text-[#4fd1c5]" />
          </div>
          <p className="text-[#9ca3af]">Loading evidence...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-[#e5e7eb]">Partitions</h1>
        <p className="text-[#9ca3af] text-sm mt-1">View and analyze disk partitions</p>
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

      <div className="flex gap-4">
        <div className="flex-1 border border-[#1f2933] rounded bg-[#121821] p-4">
          <label className="block text-sm font-medium text-[#e5e7eb] mb-2">
            Select Evidence
          </label>
          <div className="relative">
            <select
              value={selectedEvidenceId || ''}
              onChange={(e) => setSelectedEvidenceId(Number(e.target.value))}
              className="w-full px-4 py-2 bg-[#0b0f14] border border-[#1f2933] rounded text-[#e5e7eb] focus:outline-none focus:border-[#4fd1c5]"
              disabled={evidenceList.length === 0}
            >
              {evidenceList.length === 0 ? (
                <option>No evidence available</option>
              ) : (
                evidenceList.map((ev) => (
                  <option key={ev.id} value={ev.id}>
                    {ev.filename} (ID: {ev.id})
                  </option>
                ))
              )}
            </select>
          </div>
        </div>
        <div className="flex items-end">
          <Button
            onClick={handleScanPartitions}
            disabled={!selectedEvidenceId || scanning}
            className="gap-2 bg-[#4fd1c5] text-[#0b0f14] hover:bg-[#45b8ad]"
          >
            {scanning ? (
              <>
                <Loader size={16} className="animate-spin" />
                Scanning...
              </>
            ) : (
              'Scan Partitions'
            )}
          </Button>
        </div>
      </div>

      {partitionsLoading ? (
        <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
          <div className="flex justify-center mb-4">
            <Loader size={24} className="animate-spin text-[#4fd1c5]" />
          </div>
          <p className="text-[#9ca3af]">Loading partitions...</p>
        </div>
      ) : partitions.length > 0 ? (
        <div className="border border-[#1f2933] rounded bg-[#121821] overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1f2933] bg-[#0b0f14]">
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Partition #
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Filesystem
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Start Offset
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Size
                </th>
              </tr>
            </thead>
            <tbody>
              {partitions.map((partition) => (
                <tr
                  key={partition.id}
                  className="border-b border-[#1f2933] hover:bg-[#1f2933] transition-colors"
                >
                  <td className="px-6 py-4 text-sm text-[#e5e7eb] font-mono">{partition.id}</td>
                  <td className="px-6 py-4 text-sm text-[#e5e7eb]">
                    {partition.partition_number}
                  </td>
                  <td className="px-6 py-4 text-sm text-[#e5e7eb]">
                    {partition.filesystem_type}
                  </td>
                  <td className="px-6 py-4 text-sm text-[#9ca3af] font-mono">
                    {partition.start_offset.toLocaleString()} sectors
                  </td>
                  <td className="px-6 py-4 text-sm text-[#9ca3af]">
                    {formatBytes(partition.size_bytes)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
          <p className="text-[#9ca3af]">
            {selectedEvidenceId ? 'No partitions found. Scan to detect partitions.' : 'Select evidence to view partitions.'}
          </p>
        </div>
      )}
    </div>
  )
}
