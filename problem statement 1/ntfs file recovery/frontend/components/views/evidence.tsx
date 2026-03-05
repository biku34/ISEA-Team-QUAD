'use client'

import React from "react"

import { useState, useEffect } from 'react'
import { Upload, CheckCircle, Eye, Trash2, AlertCircle, Loader, Layers } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import {
  listEvidence,
  verifyEvidenceHash,
  deleteEvidence,
  Evidence
} from '@/lib/api-client'
import { SegmentedUploadForm } from '@/components/upload/segmented-upload-form'
import { EvidenceDetailCard } from '@/components/evidence/evidence-detail-card'

export default function EvidenceView() {
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [verifying, setVerifying] = useState<number | null>(null)
  const [uploadDialogOpen, setUploadDialogOpen] = useState(false)
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null)

  // Fetch evidence on mount
  useEffect(() => {
    fetchEvidence()
  }, [])

  const fetchEvidence = async () => {
    setLoading(true)
    setError(null)
    const result = await listEvidence()
    if (result.error) {
      setError(result.error)
      setEvidence([])
    } else {
      setEvidence((result.data as any)?.evidence || [])
    }
    setLoading(false)
  }

  const handleUploadComplete = () => {
    setUploadDialogOpen(false)
    fetchEvidence()
  }

  const handleVerify = async (id: number, expectedHash: string) => {
    setVerifying(id)
    setError(null)
    const result = await verifyEvidenceHash(id, expectedHash)
    if (result.error) {
      setError(result.error)
    } else {
      await fetchEvidence()
    }
    setVerifying(null)
  }

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this evidence?')) return
    const result = await deleteEvidence(id)
    if (result.error) {
      setError(result.error)
    } else {
      await fetchEvidence()
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

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[#e5e7eb]">Evidence</h1>
          <p className="text-[#9ca3af] text-sm mt-1">Manage and track digital evidence</p>
        </div>
        <div className="flex gap-2">
          <Dialog open={uploadDialogOpen} onOpenChange={setUploadDialogOpen}>
            <DialogTrigger asChild>
              <Button className="gap-2 bg-[#4fd1c5] text-[#0b0f14] hover:bg-[#45b8ad]">
                <Upload size={16} />
                Upload Evidence
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto bg-[#121821] border-[#1f2933]">
              <DialogHeader>
                <DialogTitle className="text-[#e5e7eb]">Upload Evidence</DialogTitle>
              </DialogHeader>
              <SegmentedUploadForm
                onUploadComplete={handleUploadComplete}
                onCancel={() => setUploadDialogOpen(false)}
              />
            </DialogContent>
          </Dialog>
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

      {loading ? (
        <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
          <div className="flex justify-center mb-4">
            <Loader size={24} className="animate-spin text-[#4fd1c5]" />
          </div>
          <p className="text-[#9ca3af]">Loading evidence...</p>
        </div>
      ) : evidence.length > 0 ? (
        <div className="border border-[#1f2933] rounded bg-[#121821] overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1f2933] bg-[#0b0f14]">
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Filename
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Case
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Examiner
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Size
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  SHA-256
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Upload Time
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((item) => (
                <tr
                  key={item.id}
                  className="border-b border-[#1f2933] hover:bg-[#1f2933] transition-colors"
                >
                  <td className="px-6 py-4 text-sm text-[#e5e7eb] font-mono">{item.id}</td>
                  <td className="px-6 py-4 text-sm text-[#e5e7eb]">
                    <div className="flex items-center gap-2">
                      {item.is_segmented && (
                        <Layers size={16} className="text-[#4fd1c5] flex-shrink-0" />
                      )}
                      <span>{item.filename}</span>
                      {item.is_segmented && item.total_segments && (
                        <span className="text-xs text-[#9ca3af]">({item.total_segments} segments)</span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-[#e5e7eb]">{item.case_name}</td>
                  <td className="px-6 py-4 text-sm text-[#9ca3af]">{item.examiner}</td>
                  <td className="px-6 py-4 text-sm text-[#9ca3af]">
                    {formatBytes(item.size_bytes)}
                  </td>
                  <td className="px-6 py-4 text-sm text-[#9ca3af] font-mono">
                    {item.sha256_hash.substring(0, 16)}...
                  </td>
                  <td className="px-6 py-4 text-sm text-[#9ca3af] text-xs">
                    {formatDate(item.upload_time)}
                  </td>
                  <td className="px-6 py-4 text-sm">
                    <div className="flex gap-2">
                      <button
                        onClick={() => handleVerify(item.id, item.sha256_hash)}
                        disabled={verifying === item.id}
                        className="text-[#9ca3af] hover:text-[#4fd1c5] transition-colors disabled:opacity-50"
                        title="Verify hash"
                      >
                        {verifying === item.id ? (
                          <Loader size={16} className="animate-spin" />
                        ) : (
                          <CheckCircle size={16} />
                        )}
                      </button>
                      <button
                        onClick={() => handleDelete(item.id)}
                        className="text-[#9ca3af] hover:text-red-500 transition-colors"
                        title="Delete evidence"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
          <p className="text-[#9ca3af]">No evidence uploaded yet. Upload an E01 image to begin.</p>
        </div>
      )}
    </div>
  )
}
