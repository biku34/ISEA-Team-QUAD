'use client'

import { useState, useEffect } from 'react'
import { Download, CheckCircle, Loader, AlertCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { listRecoveredFiles, downloadRecoveredFile } from '@/lib/api-client'

interface RecoveredFile {
  id: number
  filename: string
  size_bytes: number
  recovery_time: string
  sha256_hash: string
}

export default function RecoveryView() {
  const [recoveredFiles, setRecoveredFiles] = useState<RecoveredFile[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [downloading, setDownloading] = useState<number | null>(null)

  useEffect(() => {
    fetchRecoveredFiles()
  }, [])

  const fetchRecoveredFiles = async () => {
    setLoading(true)
    setError(null)
    const result = await listRecoveredFiles()
    if (result.error) {
      setError(result.error)
    } else {
      const data = result.data as any
      let files: any[] = []

      if (Array.isArray(data)) {
        files = data
      } else if (data && Array.isArray(data.recovered_files)) {
        files = data.recovered_files
      }

      const mappedFiles = files.map((f: any) => ({
        id: f.id,
        filename: f.original_filename,
        size_bytes: f.size_bytes,
        recovery_time: f.recovered_at,
        sha256_hash: f.sha256_hash,
      }))

      setRecoveredFiles(mappedFiles)
    }
    setLoading(false)
  }

  const handleDownload = async (fileId: number) => {
    setDownloading(fileId)
    try {
      const url = await downloadRecoveredFile(fileId)
      const link = document.createElement('a')
      link.href = url
      link.download = recoveredFiles.find((f) => f.id === fileId)?.filename || 'download'
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
    } catch (err) {
      setError('Download failed')
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
          <p className="text-[#9ca3af]">Loading recovered files...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[#e5e7eb]">Recovered Files</h1>
          <p className="text-[#9ca3af] text-sm mt-1">
            {recoveredFiles.length} file{recoveredFiles.length !== 1 ? 's' : ''} recovered
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={fetchRecoveredFiles}
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

      {recoveredFiles.length > 0 ? (
        <div className="border border-[#1f2933] rounded bg-[#121821] overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1f2933] bg-[#0b0f14]">
                <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Filename
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Size
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Recovery Time
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  SHA-256
                </th>
                <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Action
                </th>
              </tr>
            </thead>
            <tbody>
              {recoveredFiles.map((file) => (
                <tr
                  key={file.id}
                  className="border-b border-[#1f2933] hover:bg-[#1f2933] transition-colors"
                >
                  <td className="px-4 py-2 text-[#e5e7eb]">{file.filename}</td>
                  <td className="px-4 py-2 text-[#9ca3af]">{formatBytes(file.size_bytes)}</td>
                  <td className="px-4 py-2 text-[#9ca3af] text-xs">
                    {formatDate(file.recovery_time)}
                  </td>
                  <td className="px-4 py-2 text-[#9ca3af] font-mono text-xs">
                    {file.sha256_hash.substring(0, 12)}...
                  </td>
                  <td className="px-4 py-2">
                    <Button
                      onClick={() => handleDownload(file.id)}
                      disabled={downloading === file.id}
                      className="h-7 gap-1 text-xs bg-[#4fd1c5] text-[#0b0f14] hover:bg-[#45b8ad]"
                    >
                      {downloading === file.id ? (
                        <Loader size={12} className="animate-spin" />
                      ) : (
                        <Download size={12} />
                      )}
                      Download
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
          <p className="text-[#9ca3af]">No recovered files yet.</p>
        </div>
      )}
    </div>
  )
}
