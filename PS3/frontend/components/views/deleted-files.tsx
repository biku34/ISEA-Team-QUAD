'use client'

import { useState, useEffect } from 'react'
import { RotateCcw, Loader, AlertCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  listEvidence,
  listPartitions,
  listDeletedFiles,
  scanDeletedFiles,
  recoverFile,
} from '@/lib/api-client'

interface DeletedFile {
  id: number
  inode: number
  filename: string
  size_bytes: number
  deleted_time: string
}

export default function DeletedFilesView() {
  const [evidenceList, setEvidenceList] = useState<any[]>([])
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<number | null>(null)
  const [partitions, setPartitions] = useState<any[]>([])
  const [selectedPartitionId, setSelectedPartitionId] = useState<number | null>(null)
  const [deletedFiles, setDeletedFiles] = useState<DeletedFile[]>([])
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [selectedFileIds, setSelectedFileIds] = useState<number[]>([])
  const [recovering, setRecovering] = useState<number | null>(null)
  const [batchRecovering, setBatchRecovering] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchEvidence()
  }, [])

  useEffect(() => {
    if (selectedEvidenceId) {
      fetchPartitions(selectedEvidenceId)
    }
  }, [selectedEvidenceId])

  useEffect(() => {
    if (selectedPartitionId) {
      fetchDeletedFiles(selectedPartitionId)
      setSelectedFileIds([])
    }
  }, [selectedPartitionId])

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
    setLoading(true)
    setError(null)
    const result = await listPartitions(evidenceId)
    if (result.error) {
      setError(result.error)
      setPartitions([])
    } else {
      const data = result.data as any
      let partitionsData: any[] = []
      if (Array.isArray(data)) {
        partitionsData = data
      } else if (data && Array.isArray(data.partitions)) {
        partitionsData = data.partitions
      }
      setPartitions(partitionsData)
      if (partitionsData.length > 0) {
        setSelectedPartitionId(partitionsData[0].id)
      }
    }
    setLoading(false)
  }

  const fetchDeletedFiles = async (partitionId: number) => {
    setError(null)
    const result = await listDeletedFiles(partitionId)
    if (result.error) {
      setError(result.error)
      setDeletedFiles([])
    } else {
      const data = result.data as any
      if (Array.isArray(data)) {
        setDeletedFiles(data)
      } else if (data && Array.isArray(data.deleted_files)) {
        setDeletedFiles(data.deleted_files)
      } else if (data && Array.isArray(data.files)) {
        setDeletedFiles(data.files)
      } else {
        setDeletedFiles([])
      }
    }
  }

  const handleScan = async () => {
    if (!selectedEvidenceId || !selectedPartitionId) return
    setScanning(true)
    setError(null)
    const result = await scanDeletedFiles(selectedEvidenceId, selectedPartitionId)
    if (result.error) {
      setError(result.error)
    } else {
      await fetchDeletedFiles(selectedPartitionId)
    }
    setScanning(false)
  }

  const handleRecover = async (fileId: number) => {
    if (!selectedEvidenceId) return
    setRecovering(fileId)
    setError(null)
    const result = await recoverFile(fileId, selectedEvidenceId)
    if (result.error) {
      setError(result.error)
    } else {
      alert('File recovery initiated')
      await fetchDeletedFiles(selectedPartitionId!)
    }
    setRecovering(null)
  }

  const handleBatchRecover = async () => {
    if (!selectedEvidenceId || selectedFileIds.length === 0) return
    setBatchRecovering(true)
    setError(null)

    // Using import from lib/api-client
    const { batchRecoverFiles } = await import('@/lib/api-client')
    const result = await batchRecoverFiles(selectedFileIds, selectedEvidenceId)

    if (result.error) {
      setError(result.error)
    } else {
      alert(`Batch recovery of ${selectedFileIds.length} files initiated`)
      setSelectedFileIds([])
      await fetchDeletedFiles(selectedPartitionId!)
    }
    setBatchRecovering(false)
  }

  const handleSelectFile = (fileId: number) => {
    setSelectedFileIds(prev =>
      prev.includes(fileId) ? prev.filter(id => id !== fileId) : [...prev, fileId]
    )
  }

  const handleSelectAll = () => {
    if (selectedFileIds.length === deletedFiles.length) {
      setSelectedFileIds([])
    } else {
      setSelectedFileIds(deletedFiles.map(f => f.id))
    }
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
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
      <div>
        <h1 className="text-2xl font-semibold text-[#e5e7eb]">Deleted Files</h1>
        <p className="text-[#9ca3af] text-sm mt-1">Recover deleted files from evidence</p>
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

      <div className="grid grid-cols-2 gap-4">
        <div className="border border-[#1f2933] rounded bg-[#121821] p-4">
          <label className="block text-sm font-medium text-[#e5e7eb] mb-2">
            Evidence
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
        <div className="border border-[#1f2933] rounded bg-[#121821] p-4">
          <label className="block text-sm font-medium text-[#e5e7eb] mb-2">
            Partition
          </label>
          <select
            value={selectedPartitionId || ''}
            onChange={(e) => setSelectedPartitionId(Number(e.target.value))}
            className="w-full px-4 py-2 bg-[#0b0f14] border border-[#1f2933] rounded text-[#e5e7eb] focus:outline-none focus:border-[#4fd1c5]"
            disabled={partitions.length === 0}
          >
            {partitions.length === 0 ? (
              <option>No partitions</option>
            ) : (
              partitions.map((p) => (
                <option key={p.id} value={p.id}>
                  Partition {p.partition_number} ({p.filesystem_type})
                </option>
              ))
            )}
          </select>
        </div>
      </div>

      <div className="flex gap-2">
        <Button
          onClick={handleScan}
          disabled={!selectedPartitionId || scanning}
          className="gap-2 bg-[#4fd1c5] text-[#0b0f14] hover:bg-[#45b8ad]"
        >
          {scanning ? (
            <>
              <Loader size={16} className="animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <RotateCcw size={16} />
              Scan for Deleted Files
            </>
          )}
        </Button>

        {selectedFileIds.length > 0 && (
          <Button
            onClick={handleBatchRecover}
            disabled={batchRecovering}
            className="gap-2 bg-[#e5e7eb] text-[#0b0f14] hover:bg-[#d1d5db]"
          >
            {batchRecovering ? (
              <Loader size={16} className="animate-spin" />
            ) : (
              <RotateCcw size={16} />
            )}
            Recover Selected ({selectedFileIds.length})
          </Button>
        )}
      </div>

      {deletedFiles.length > 0 ? (
        <div className="border border-[#1f2933] rounded bg-[#121821] overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1f2933] bg-[#0b0f14]">
                <th className="px-4 py-2 text-left">
                  <input
                    type="checkbox"
                    checked={selectedFileIds.length === deletedFiles.length && deletedFiles.length > 0}
                    onChange={handleSelectAll}
                    className="rounded border-[#1f2933] bg-[#0b0f14]"
                  />
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Inode
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Filename
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Size
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Deleted Time
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Action
                </th>
              </tr>
            </thead>
            <tbody>
              {deletedFiles.map((file) => (
                <tr
                  key={file.id}
                  className={`border-b border-[#1f2933] hover:bg-[#1f2933] transition-colors ${selectedFileIds.includes(file.id) ? 'bg-[#1f2933]' : ''}`}
                >
                  <td className="px-4 py-2">
                    <input
                      type="checkbox"
                      checked={selectedFileIds.includes(file.id)}
                      onChange={() => handleSelectFile(file.id)}
                      className="rounded border-[#1f2933] bg-[#0b0f14]"
                    />
                  </td>
                  <td className="px-4 py-2 text-[#e5e7eb] font-mono">{file.inode}</td>
                  <td className="px-4 py-2 text-[#e5e7eb]">{file.filename}</td>
                  <td className="px-4 py-2 text-[#9ca3af]">{formatBytes(file.size_bytes)}</td>
                  <td className="px-4 py-2 text-[#9ca3af] text-xs">
                    {formatDate(file.deleted_time)}
                  </td>
                  <td className="px-4 py-2">
                    <Button
                      onClick={() => handleRecover(file.id)}
                      disabled={recovering === file.id}
                      className="h-7 gap-1 text-xs bg-[#4fd1c5] text-[#0b0f14] hover:bg-[#45b8ad]"
                    >
                      {recovering === file.id ? (
                        <Loader size={12} className="animate-spin" />
                      ) : (
                        <RotateCcw size={12} />
                      )}
                      Recover
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
          <p className="text-[#9ca3af]">
            {selectedPartitionId ? 'No deleted files found.' : 'Select a partition to view deleted files.'}
          </p>
        </div>
      )}
    </div>
  )
}
