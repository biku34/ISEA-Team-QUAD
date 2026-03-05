'use client'

import { useState, useEffect } from 'react'
import { Zap, Loader, AlertCircle, CheckCircle, File, Download } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  listEvidence,
  listPartitions,
  carvFiles,
  getCarvingResults,
  downloadCarvedFile,
} from '@/lib/api-client'
import { useCarving } from '@/lib/carving-context'

interface CarvedFileDisplay {
  id: number
  carved_filename: string
  size_bytes: number
  signature_type: string
  sha256_hash: string
}

export default function CarvingView() {
  const { activeSessionId, sessionStatus, startMonitoring } = useCarving()
  const [evidenceList, setEvidenceList] = useState<any[]>([])
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<number | null>(null)
  const [partitions, setPartitions] = useState<any[]>([])
  const [selectedPartitionId, setSelectedPartitionId] = useState<number | null>(null)
  const [selectedFileTypes, setSelectedFileTypes] = useState<string[]>(['jpg', 'png', 'pdf'])

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Results State
  const [carvedResults, setCarvedResults] = useState<CarvedFileDisplay[]>([])
  const [downloading, setDownloading] = useState<number | null>(null)
  const [lastAlertedSession, setLastAlertedSession] = useState<string | null>(null)

  // Search state
  const [searchTerm, setSearchTerm] = useState('')

  const fileTypeOptions = [
    { id: 'jpg', label: 'JPEG Images' },
    { id: 'png', label: 'PNG Images' },
    { id: 'gif', label: 'GIF Images' },
    { id: 'pdf', label: 'PDF Documents' },
    { id: 'doc', label: 'Word Documents' },
    { id: 'xls', label: 'Excel Spreadsheets' },
    { id: 'zip', label: 'ZIP Archives' },
    { id: 'rar', label: 'RAR Archives' },
  ]

  useEffect(() => {
    fetchEvidence()
  }, [])

  useEffect(() => {
    if (selectedEvidenceId) {
      fetchPartitions(selectedEvidenceId)
    }
  }, [selectedEvidenceId])

  // Sync Results with Global Status
  useEffect(() => {
    if (activeSessionId && sessionStatus) {
      if (sessionStatus.files_carved_count > carvedResults.length) {
        fetchResults(activeSessionId)
      }

      // Completion Alert
      if (sessionStatus.status === 'completed' && lastAlertedSession !== activeSessionId) {
        setLastAlertedSession(activeSessionId)
        alert(`Carving Complete! Found ${sessionStatus.files_carved_count} files.`)
      }
    }
  }, [activeSessionId, sessionStatus, carvedResults.length, lastAlertedSession])

  const fetchEvidence = async () => {
    setLoading(true)
    const result = await listEvidence()
    if (result.error) {
      setError(result.error)
    } else {
      const evidence = (result.data as any)?.evidence || []
      setEvidenceList(evidence)
      if (evidence.length > 0 && !selectedEvidenceId) {
        setSelectedEvidenceId(evidence[0].id)
      }
    }
    setLoading(false)
  }

  const fetchPartitions = async (evidenceId: number) => {
    const result = await listPartitions(evidenceId)
    if (result.error) {
      setError(result.error)
    } else {
      const data = result.data
      let partitionsData: any[] = []
      if (Array.isArray(data)) {
        partitionsData = data
      } else if (data && typeof data === 'object' && 'partitions' in data && Array.isArray((data as any).partitions)) {
        partitionsData = (data as any).partitions
      }
      setPartitions(partitionsData)
      if (partitionsData.length > 0 && !selectedPartitionId) {
        setSelectedPartitionId(partitionsData[0].id)
      }
    }
  }

  const fetchResults = async (sid: string) => {
    const result = await getCarvingResults(sid)
    if (result.data) {
      setCarvedResults(result.data.files)
    }
  }

  const handleFileTypeChange = (id: string) => {
    setSelectedFileTypes(prev => {
      if (prev.includes(id)) return prev.filter(t => t !== id)
      return [...prev, id]
    })
  }

  const handleStartCarving = async () => {
    if (!selectedEvidenceId || !selectedPartitionId) return

    setCarvedResults([])
    setError(null)

    const result = await carvFiles(
      selectedEvidenceId,
      selectedPartitionId,
      selectedFileTypes
    )

    if (result.error) {
      setError(result.error)
    } else if (result.data && result.data.session) {
      startMonitoring(result.data.session.session_id)
      setLastAlertedSession(null)
    }
  }

  const handleDownload = async (fileId: number, filename: string) => {
    setDownloading(fileId)
    try {
      const url = await downloadCarvedFile(fileId)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
    } catch (err) {
      console.error(err)
      alert("Download failed")
    }
    setDownloading(null)
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
          <Loader size={24} className="animate-spin text-[#4fd1c5] mx-auto mb-4" />
          <p className="text-[#9ca3af]">Loading evidence...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-[#e5e7eb]">File Carving Action</h1>
        <p className="text-[#9ca3af] text-sm mt-1">Recover files from unallocated space based on file signatures</p>
      </div>

      {error && (
        <div className="border border-red-900 rounded bg-red-900/10 p-4 flex gap-3">
          <AlertCircle size={20} className="text-red-500 flex-shrink-0" />
          <div className="text-red-300 text-sm">{error}</div>
        </div>
      )}

      {/* Configuration Panel */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-1 space-y-6">
          <div className="border border-[#1f2933] rounded bg-[#121821] p-4 space-y-4">
            <h3 className="text-[#e5e7eb] font-medium border-b border-[#1f2933] pb-2">Configuration</h3>

            <div>
              <label className="block text-xs uppercase text-[#9ca3af] mb-1">Evidence Source</label>
              <select
                value={selectedEvidenceId || ''}
                onChange={(e) => setSelectedEvidenceId(Number(e.target.value))}
                className="w-full px-3 py-2 bg-[#0b0f14] border border-[#1f2933] rounded text-[#e5e7eb] text-sm focus:outline-none focus:border-[#4fd1c5]"
                disabled={sessionStatus?.status === 'in_progress'}
              >
                {evidenceList.map((ev) => (
                  <option key={ev.id} value={ev.id}>{ev.filename}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs uppercase text-[#9ca3af] mb-1">Target Partition</label>
              <select
                value={selectedPartitionId || ''}
                onChange={(e) => setSelectedPartitionId(Number(e.target.value))}
                className="w-full px-3 py-2 bg-[#0b0f14] border border-[#1f2933] rounded text-[#e5e7eb] text-sm focus:outline-none focus:border-[#4fd1c5]"
                disabled={partitions.length === 0 || sessionStatus?.status === 'in_progress'}
              >
                {partitions.length === 0 ? <option>No partitions</option> : partitions.map(p => (
                  <option key={p.id} value={p.id}>Partition {p.partition_number}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs uppercase text-[#9ca3af] mb-2">File Signatures</label>
              <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto pr-1">
                {fileTypeOptions.map((type) => (
                  <label key={type.id} className="flex items-center gap-2 cursor-pointer hover:bg-[#1f2933] p-1 rounded">
                    <input
                      type="checkbox"
                      checked={selectedFileTypes.includes(type.id)}
                      onChange={() => handleFileTypeChange(type.id)}
                      disabled={sessionStatus?.status === 'in_progress'}
                      className="rounded border-[#1f2933] bg-[#0b0f14]"
                    />
                    <span className="text-sm text-[#e5e7eb]">{type.label}</span>
                  </label>
                ))}
              </div>
            </div>

            <Button
              onClick={handleStartCarving}
              disabled={!selectedPartitionId || selectedFileTypes.length === 0 || sessionStatus?.status === 'in_progress'}
              className="w-full bg-[#4fd1c5] text-[#0b0f14] hover:bg-[#45b8ad]"
            >
              {sessionStatus?.status === 'in_progress' ? (
                <><Loader size={16} className="animate-spin mr-2" /> Carving Running...</>
              ) : (
                <><Zap size={16} className="mr-2" /> Start Carving</>
              )}
            </Button>
          </div>
        </div>

        {/* Status & Results Panel */}
        <div className="md:col-span-2 space-y-6">
          {sessionStatus && (
            <div className="border border-[#1f2933] rounded bg-[#121821] p-6 shadow-lg shadow-[#0b0f14]/50">
              <div className="flex items-center justify-between mb-4 border-b border-[#1f2933] pb-4">
                <div className="flex items-center gap-3">
                  <div className={`w-3 h-3 rounded-full ${sessionStatus.status === 'in_progress' ? 'bg-green-500 animate-pulse' : 'bg-[#4fd1c5]'}`}></div>
                  <h3 className="text-lg font-semibold text-[#e5e7eb]">
                    Task Status: <span className="uppercase text-[#4fd1c5] font-mono">{sessionStatus.status.replace('_', ' ')}</span>
                  </h3>
                </div>
                <span className="text-xs text-[#9ca3af] font-mono bg-[#0b0f14] px-2 py-1 rounded border border-[#1f2933]">
                  ID: {sessionStatus.session_id ? sessionStatus.session_id.substring(0, 8) : 'N/A'}
                </span>
              </div>

              <div className="bg-[#0b0f14] rounded p-4 mb-4 font-mono text-sm text-[#e5e7eb] border border-[#1f2933]">
                <div className="flex justify-between mb-2">
                  <span>Progress:</span>
                  <span className="text-[#4fd1c5]">{sessionStatus.progress_message}</span>
                </div>
                <div className="flex justify-between mb-2">
                  <span>Files Found:</span>
                  <span className="text-green-500">{sessionStatus.files_carved_count}</span>
                </div>
                {sessionStatus.start_time && (
                  <div className="flex justify-between text-[#9ca3af] text-xs">
                    <span>Started:</span>
                    <span>{new Date(sessionStatus.start_time).toLocaleTimeString()}</span>
                  </div>
                )}
              </div>

              {sessionStatus.status === 'in_progress' && (
                <div className="space-y-2">
                  <div className="flex justify-between text-xs text-[#9ca3af]">
                    <span>Overall Scan Progress</span>
                    <span>{sessionStatus.progress_percentage}%</span>
                  </div>
                  <div className="w-full bg-[#1f2933] rounded-full h-2 mb-2 overflow-hidden border border-[#1f2933]">
                    <div
                      className="bg-[#4fd1c5] h-2 rounded-full transition-all duration-500 ease-out shadow-[0_0_10px_rgba(79,209,197,0.3)]"
                      style={{ width: `${sessionStatus.progress_percentage}%` }}
                    ></div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Results Table */}
          {carvedResults.length > 0 && (
            <div className="border border-[#1f2933] rounded bg-[#121821] overflow-hidden">
              <div className="bg-[#0b0f14] px-4 py-3 border-b border-[#1f2933] flex justify-between items-center">
                <h3 className="font-medium text-[#e5e7eb]">Partial Results ({carvedResults.length})</h3>
                <input
                  type="text"
                  placeholder="Filter results..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="bg-[#121821] border border-[#1f2933] rounded px-3 py-1 text-sm text-[#e5e7eb] focus:outline-none focus:border-[#4fd1c5]"
                />
              </div>
              <div className="overflow-x-auto max-h-[500px]">
                <table className="w-full text-sm">
                  <thead className="bg-[#0b0f14] text-[#9ca3af] uppercase text-xs sticky top-0">
                    <tr>
                      <th className="px-4 py-2 text-left">Filename</th>
                      <th className="px-4 py-2 text-left">Type</th>
                      <th className="px-4 py-2 text-left">Size</th>
                      <th className="px-4 py-2 text-left">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {carvedResults
                      .filter(f => f.carved_filename.toLowerCase().includes(searchTerm.toLowerCase()))
                      .map((file) => (
                        <tr key={file.id} className="border-b border-[#1f2933] hover:bg-[#1f2933]">
                          <td className="px-4 py-2 text-[#e5e7eb] font-mono text-xs">{file.carved_filename}</td>
                          <td className="px-4 py-2 text-[#9ca3af] uppercase text-xs">{file.signature_type}</td>
                          <td className="px-4 py-2 text-[#9ca3af]">{formatBytes(file.size_bytes)}</td>
                          <td className="px-4 py-2">
                            <Button
                              onClick={() => handleDownload(file.id, file.carved_filename)}
                              disabled={downloading === file.id}
                              variant="ghost"
                              className="h-6 w-6 p-0 hover:text-[#4fd1c5]"
                            >
                              {downloading === file.id ? <Loader size={14} className="animate-spin" /> : <Download size={14} />}
                            </Button>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {sessionStatus && carvedResults.length === 0 && (
            <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center text-[#9ca3af]">
              <Loader size={24} className="mx-auto mb-4 animate-spin opacity-50" />
              <p>Task processing...</p>
              <p className="text-xs mt-2 text-[#6b7280]">Real-time results will appear here shortly.</p>
            </div>
          )}

          {!sessionStatus && !loading && (
            <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center text-[#9ca3af]">
              <File size={48} className="mx-auto mb-4 opacity-50" />
              <p>Configure and start a carving session to recover unallocated files.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
