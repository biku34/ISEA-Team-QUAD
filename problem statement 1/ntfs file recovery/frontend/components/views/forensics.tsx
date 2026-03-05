'use client'

import { useState, useEffect } from 'react'
import { FileJson, BarChart3, Loader, AlertCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  listEvidence,
  getTimeline,
  getStatistics,
  generateReport,
} from '@/lib/api-client'

interface TimelineEvent {
  timestamp: string
  action: string
  file: string
}

interface Statistics {
  total_files: number
  deleted_files: number
  carved_files: number
  unallocated_space: number
}

export default function ForensicsView() {
  const [evidenceList, setEvidenceList] = useState<any[]>([])
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<number | null>(null)
  const [timeline, setTimeline] = useState<TimelineEvent[]>([])
  const [statistics, setStatistics] = useState<Statistics | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingData, setLoadingData] = useState(false)
  const [generating, setGenerating] = useState<'json' | 'pdf' | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchEvidence()
  }, [])

  useEffect(() => {
    if (selectedEvidenceId) {
      fetchData(selectedEvidenceId)
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

  const fetchData = async (evidenceId: number) => {
    setLoadingData(true)
    setError(null)

    const timelineResult = await getTimeline(evidenceId)
    const statsResult = await getStatistics(evidenceId)

    if (timelineResult.error || statsResult.error) {
      setError(timelineResult.error || statsResult.error || "An unknown error occurred")
    } else {
      setTimeline((timelineResult.data as any)?.events || [])

      const statsData = statsResult.data as any
      if (statsData) {
        setStatistics({
          total_files: (statsData.files_recovered || 0) + (statsData.files_carved || 0),
          deleted_files: statsData.deleted_files_enumerated || 0,
          carved_files: statsData.files_carved || 0,
          unallocated_space: statsData.total_recovered_bytes || 0 // Mapping bytes to this field as proxy or placeholder
        })
      } else {
        setStatistics(null)
      }
    }
    setLoadingData(false)
  }

  const handleGenerateReport = async (format: 'json' | 'pdf') => {
    if (!selectedEvidenceId) return
    setGenerating(format)
    setError(null)
    const result = await generateReport(selectedEvidenceId, format)
    if (result.error) {
      setError(result.error)
    } else {
      const data = result.data as any
      if (data && data.report_url) {
        window.open(data.report_url, '_blank')
      } else {
        alert('Report generated successfully')
      }
    }
    setGenerating(null)
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString()
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[#e5e7eb]">Forensics Analysis</h1>
          <p className="text-[#9ca3af] text-sm mt-1">
            Timeline and statistical analysis of forensic data
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={() => handleGenerateReport('json')}
            disabled={!selectedEvidenceId || !!generating}
            variant="outline"
            className="gap-2 border-[#1f2933] text-[#e5e7eb] hover:bg-[#1f2933]"
          >
            {generating === 'json' ? (
              <Loader size={16} className="animate-spin" />
            ) : (
              <FileJson size={16} />
            )}
            JSON Report
          </Button>
          <Button
            onClick={() => handleGenerateReport('pdf')}
            disabled={!selectedEvidenceId || !!generating}
            className="gap-2 bg-[#4fd1c5] text-[#0b0f14] hover:bg-[#45b8ad]"
          >
            {generating === 'pdf' ? (
              <Loader size={16} className="animate-spin" />
            ) : (
              <BarChart3 size={16} />
            )}
            PDF Report
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
          Select Evidence
        </label>
        <select
          value={selectedEvidenceId || ''}
          onChange={(e) => setSelectedEvidenceId(Number(e.target.value))}
          className="w-full px-4 py-2 bg-[#0b0f14] border border-[#1f2933] rounded text-[#e5e7eb] focus:outline-none focus:border-[#4fd1c5]"
        >
          {evidenceList.map((ev) => (
            <option key={ev.id} value={ev.id}>
              {ev.filename}
            </option>
          ))}
        </select>
      </div>

      {loadingData ? (
        <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
          <div className="flex justify-center mb-4">
            <Loader size={24} className="animate-spin text-[#4fd1c5]" />
          </div>
          <p className="text-[#9ca3af]">Loading forensic data...</p>
        </div>
      ) : (
        <>
          {statistics && (
            <div className="grid grid-cols-4 gap-4">
              <div className="border border-[#1f2933] rounded bg-[#121821] p-4">
                <p className="text-[#9ca3af] text-xs uppercase font-medium">Total Files</p>
                <p className="text-2xl font-bold text-[#4fd1c5] mt-2">
                  {statistics.total_files?.toLocaleString()}
                </p>
              </div>
              <div className="border border-[#1f2933] rounded bg-[#121821] p-4">
                <p className="text-[#9ca3af] text-xs uppercase font-medium">Deleted Files</p>
                <p className="text-2xl font-bold text-[#4fd1c5] mt-2">
                  {statistics.deleted_files?.toLocaleString()}
                </p>
              </div>
              <div className="border border-[#1f2933] rounded bg-[#121821] p-4">
                <p className="text-[#9ca3af] text-xs uppercase font-medium">Carved Files</p>
                <p className="text-2xl font-bold text-[#4fd1c5] mt-2">
                  {statistics.carved_files?.toLocaleString()}
                </p>
              </div>
              <div className="border border-[#1f2933] rounded bg-[#121821] p-4">
                <p className="text-[#9ca3af] text-xs uppercase font-medium">Unallocated Space</p>
                <p className="text-2xl font-bold text-[#4fd1c5] mt-2">
                  {formatBytes(statistics.unallocated_space || 0)}
                </p>
              </div>
            </div>
          )}

          {timeline.length > 0 && (
            <div className="border border-[#1f2933] rounded bg-[#121821]">
              <div className="border-b border-[#1f2933] p-4">
                <h2 className="text-lg font-semibold text-[#e5e7eb] flex items-center gap-2">
                  <BarChart3 size={20} />
                  MACB Timeline
                </h2>
              </div>
              <div className="max-h-96 overflow-y-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1f2933] bg-[#0b0f14] sticky top-0">
                      <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                        Timestamp
                      </th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                        Action
                      </th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                        File
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {timeline.map((event, idx) => (
                      <tr
                        key={idx}
                        className="border-b border-[#1f2933] hover:bg-[#1f2933] transition-colors"
                      >
                        <td className="px-4 py-2 text-[#9ca3af] text-xs whitespace-nowrap">
                          {formatDate(event.timestamp)}
                        </td>
                        <td className="px-4 py-2 text-[#e5e7eb]">{event.action}</td>
                        <td className="px-4 py-2 text-[#e5e7eb]">{event.file}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
