/**
 * NTFS Forensic Recovery System - API Client
 * Handles all communication with the backend FastAPI server
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
const API_BASE_PATH = process.env.NEXT_PUBLIC_API_BASE_PATH || '/api/v1'

const API_ENDPOINT = `${API_URL}${API_BASE_PATH}`

/**
 * TypeScript Interfaces for Evidence
 */
export interface Evidence {
  id: number
  filename: string
  case_name: string
  examiner: string
  size_bytes: number
  sha256_hash: string
  upload_time: string
  is_segmented?: boolean
  segment_number?: number
  total_segments?: number
  case_number?: string
  organization?: string
  description?: string
}

export interface SegmentInfo {
  segment_number: number
  filename: string
  size_bytes: number
  sha256_hash: string
}

export interface SegmentedEvidenceResponse {
  success: boolean
  message: string
  evidence: Evidence
  segment_info: {
    total_segments: number
    total_size: number
    base_name: string
    segments: SegmentInfo[]
  }
  hash_verified: boolean
}

export interface UploadMetadata {
  caseName: string
  examiner: string
  caseNumber?: string
  organization?: string
  description?: string
  expectedHash?: string
}

/**
 * Generic API request handler with error handling
 */
export async function apiCall<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<{ data?: T; error?: string; status: number }> {
  try {
    const url = `${API_ENDPOINT}${endpoint}`

    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      let errorMessage = errorData.detail || `API Error: ${response.statusText}`

      if (typeof errorMessage !== 'string') {
        if (Array.isArray(errorMessage)) {
          // Handle Pydantic validation errors which are arrays of objects
          errorMessage = errorMessage.map((err: any) => err.msg || JSON.stringify(err)).join(', ')
        } else {
          errorMessage = JSON.stringify(errorMessage)
        }
      }

      return {
        error: errorMessage,
        status: response.status,
      }
    }

    const data = await response.json()
    return { data, status: response.status }
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'Unknown error'
    return { error: `Network error: ${message}`, status: 0 }
  }
}

/**
 * Evidence Management APIs
 */
export async function uploadEvidence(
  file: File,
  caseName: string,
  examiner: string
) {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('case_name', caseName)
  formData.append('examiner', examiner)

  try {
    const url = `${API_ENDPOINT}/evidence/upload`
    const response = await fetch(url, {
      method: 'POST',
      body: formData,
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      return { error: errorData.detail || 'Upload failed', status: response.status }
    }

    const data = await response.json()
    return { data, status: response.status }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error'
    return { error: `Upload error: ${message}`, status: 0 }
  }
}

/**
 * Upload multiple segment files (E01, E02, E03, etc.)
 */
/**
 * Sequential Segmented Upload
 * Handles large E01 sets by uploading segments one-by-one
 */
export async function uploadSegmentedEvidence(
  files: File[],
  metadata: UploadMetadata,
  onProgress?: (progress: { loaded: number; total: number; percent: number, currentFile?: string }) => void
): Promise<{ data?: any; error?: string; status: number }> {
  try {
    // 1. Initiate Session
    const initData = new FormData()
    initData.append('case_name', metadata.caseName)
    initData.append('examiner', metadata.examiner)
    initData.append('total_segments', files.length.toString())
    if (metadata.caseNumber) initData.append('case_number', metadata.caseNumber)
    if (metadata.organization) initData.append('organization', metadata.organization)
    if (metadata.description) initData.append('description', metadata.description)
    if (metadata.expectedHash) initData.append('expected_hash', metadata.expectedHash)

    const initRes = await fetch(`${API_ENDPOINT}/evidence/upload-segmented/initiate`, {
      method: 'POST',
      body: initData
    })

    if (!initRes.ok) {
      const err = await initRes.json().catch(() => ({}))
      return { error: err.detail || 'Failed to initiate upload session', status: initRes.status }
    }

    const { upload_id } = await initRes.json()
    let totalLoaded = 0
    const totalSize = files.reduce((acc, f) => acc + f.size, 0)

    // 2. Upload each segment
    for (const file of files) {
      const segmentData = new FormData()
      segmentData.append('file', file)

      const segmentRes = await new Promise<{ ok: boolean, status: number, data?: any }>((resolve) => {
        const xhr = new XMLHttpRequest()
        xhr.open('POST', `${API_ENDPOINT}/evidence/upload-segmented/upload/${upload_id}`)

        xhr.upload.addEventListener('progress', (e) => {
          if (e.lengthComputable && onProgress) {
            const currentFileLoaded = e.loaded
            const overallLoaded = totalLoaded + currentFileLoaded
            onProgress({
              loaded: overallLoaded,
              total: totalSize,
              percent: (overallLoaded / totalSize) * 100,
              currentFile: file.name
            })
          }
        })

        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve({ ok: true, status: xhr.status, data: JSON.parse(xhr.responseText) })
          } else {
            resolve({ ok: false, status: xhr.status })
          }
        }
        xhr.onerror = () => resolve({ ok: false, status: 0 })
        xhr.send(segmentData)
      })

      if (!segmentRes.ok) {
        return { error: `Failed to upload segment ${file.name}`, status: segmentRes.status }
      }

      totalLoaded += file.size
    }

    // 3. Finalize
    const finalizeRes = await fetch(`${API_ENDPOINT}/evidence/upload-segmented/finalize/${upload_id}`, {
      method: 'POST'
    })

    if (!finalizeRes.ok) {
      const err = await finalizeRes.json().catch(() => ({}))
      return { error: err.detail || 'Failed to finalize upload', status: finalizeRes.status }
    }

    const finalData = await finalizeRes.json()
    return { data: finalData, status: finalizeRes.status }

  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error'
    return { error: `Upload error: ${message}`, status: 0 }
  }
}

export async function listEvidence() {
  return apiCall('/evidence/list', { method: 'GET' })
}

export async function getEvidenceDetails(id: number) {
  return apiCall(`/evidence/${id}`, { method: 'GET' })
}

export async function verifyEvidenceHash(id: number, expectedHash: string) {
  return apiCall('/evidence/verify/' + id, {
    method: 'POST',
    body: JSON.stringify({ expected_hash: expectedHash }),
  })
}

export async function deleteEvidence(id: number) {
  return apiCall(`/evidence/${id}?confirm=true`, { method: 'DELETE' })
}

/**
 * Scanning APIs
 */
export async function scanPartitions(evidenceId: number) {
  return apiCall(`/scan/partitions?evidence_id=${evidenceId}`, {
    method: 'POST',
  })
}

export async function listPartitions(evidenceId: number) {
  return apiCall(`/scan/partitions/${evidenceId}`, { method: 'GET' })
}

export async function scanDeletedFiles(
  evidenceId: number,
  partitionId: number
) {
  return apiCall(
    `/scan/deleted?evidence_id=${evidenceId}&partition_id=${partitionId}`,
    {
      method: 'POST',
    }
  )
}

export async function listDeletedFiles(partitionId: number) {
  return apiCall(`/scan/deleted/${partitionId}`, { method: 'GET' })
}

/**
 * Recovery APIs
 */
export async function recoverFile(fileId: number, evidenceId: number) {
  return apiCall(`/recovery/recover/${fileId}?evidence_id=${evidenceId}`, {
    method: 'POST',
  })
}

export interface CarvingSessionStatus {
  session_id: string
  evidence_id: number
  partition_id: number
  status: 'queued' | 'in_progress' | 'completed' | 'failed'
  progress_message: string
  progress_percentage: number
  start_time?: string
  end_time?: string
  files_carved_count: number
  error_message?: string
}

export interface CarvingResults {
  session_id: string
  total_files: number
  files: any[]
}

export async function carvFiles(
  evidenceId: number,
  partitionId: number,
  fileTypes?: string[]
) {
  const params = new URLSearchParams()
  params.append('evidence_id', evidenceId.toString())
  params.append('partition_id', partitionId.toString())

  if (fileTypes && fileTypes.length > 0) {
    fileTypes.forEach(type => params.append('file_types', type))
  }

  return apiCall<{ success: boolean; message: string; session: CarvingSessionStatus }>(
    `/recovery/carve?${params.toString()}`,
    { method: 'POST' }
  )
}

export async function getCarvingStatus(sessionId: string) {
  return apiCall<CarvingSessionStatus>(`/recovery/carve/status/${sessionId}`, { method: 'GET' })
}

export async function getCarvingResults(sessionId: string) {
  return apiCall<CarvingResults>(`/recovery/carve/results/${sessionId}`, { method: 'GET' })
}

export async function batchRecoverFiles(fileIds: number[], evidenceId: number) {
  return apiCall('/recovery/batch-recover', {
    method: 'POST',
    body: JSON.stringify({
      file_ids: fileIds,
      evidence_id: evidenceId,
    }),
  })
}

/**
 * Forensics APIs
 */
export async function getTimeline(evidenceId: number) {
  return apiCall(`/forensics/timeline/${evidenceId}`, { method: 'GET' })
}

export async function getFileMetadata(fileId: number) {
  return apiCall(`/forensics/metadata/${fileId}`, { method: 'GET' })
}

export async function getAuditLog(limit = 100, offset = 0) {
  const params = new URLSearchParams({
    limit: limit.toString(),
    offset: offset.toString(),
  })
  return apiCall(`/forensics/audit/log?${params}`, { method: 'GET' })
}

export async function generateReport(
  evidenceId: number,
  format: 'json' | 'pdf' = 'json'
) {
  const params = new URLSearchParams({
    evidence_id: evidenceId.toString(),
    report_type: format
  })
  return apiCall(`/forensics/report/generate?${params.toString()}`, {
    method: 'POST'
  })
}

export async function getStatistics(evidenceId: number) {
  return apiCall(`/forensics/statistics/${evidenceId}`, { method: 'GET' })
}

/**
 * Files APIs
 */
export async function listRecoveredFiles(skip = 0, limit = 100) {
  const params = new URLSearchParams({
    skip: skip.toString(),
    limit: limit.toString(),
  })
  return apiCall(`/files/recovered?${params}`, { method: 'GET' })
}

export async function listCarvedFiles(skip = 0, limit = 100) {
  const params = new URLSearchParams({
    skip: skip.toString(),
    limit: limit.toString(),
  })
  return apiCall(`/files/carved?${params}`, { method: 'GET' })
}

export async function downloadRecoveredFile(fileId: number) {
  return `${API_ENDPOINT}/files/download/recovered/${fileId}`
}

export async function downloadCarvedFile(fileId: number) {
  return `${API_ENDPOINT}/files/download/carved/${fileId}`
}

export async function getRecoveredFileInfo(fileId: number) {
  return apiCall(`/files/info/recovered/${fileId}`, { method: 'GET' })
}

export async function getCarvedFileInfo(fileId: number) {
  return apiCall(`/files/info/carved/${fileId}`, { method: 'GET' })
}

export async function searchFiles(
  query: string,
  source: 'all' | 'recovered' | 'carved' = 'all'
) {
  const params = new URLSearchParams({
    query: query,
    file_source: source,
  })
  return apiCall(`/files/search?${params.toString()}`, { method: 'GET' })
}

export async function resetInvestigation() {
  return apiCall('/investigation/reset', { method: 'POST' })
}

/**
 * File System Browsing APIs
 */
export async function getFileSystemHierarchy(partitionId: number) {
  return apiCall(`/scan/hierarchy/${partitionId}`, { method: 'GET' })
}

export async function listDirectoryContents(partitionId: number, inode?: number) {
  const inodeParam = inode ? `?inode=${inode}` : ''
  return apiCall(`/scan/ls/${partitionId}${inodeParam}`, { method: 'GET' })
}
