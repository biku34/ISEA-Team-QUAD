'use client'

import { useState, useEffect } from 'react'
import {
    Loader,
    AlertCircle,
    HardDrive,
    FileText,
    Hash,
    Calendar,
    User,
    Building2,
    Database,
    Layers,
    Info,
    Shield,
    FileStack,
    Clock,
    CheckCircle,
    XCircle
} from 'lucide-react'
import { listEvidence, getEvidenceDetails, listPartitions, getStatistics } from '@/lib/api-client'

interface Evidence {
    id: number
    filename: string
    file_path: string
    size_bytes: number
    sha256_hash: string
    hash_verified: boolean
    expected_hash?: string
    case_name: string
    case_number?: string
    examiner: string
    organization?: string
    description?: string
    is_segmented: boolean
    segment_number?: number
    total_segments?: number
    upload_time: string
    analysis_status: string
    partition_scan_completed: boolean
    deleted_scan_completed: boolean
}

interface Partition {
    id: number
    partition_number: number
    filesystem_type: string
    start_offset: number
    size_bytes: number
    slot: number
    is_ntfs: boolean
    scan_status: string
    deleted_file_count?: number
}

interface Statistics {
    partitions_found: number
    deleted_files_enumerated: number
    files_recovered: number
    total_recovered_bytes: number
    files_carved: number
}

export default function DiskInformationView() {
    const [evidenceList, setEvidenceList] = useState<Evidence[]>([])
    const [selectedEvidenceId, setSelectedEvidenceId] = useState<number | null>(null)
    const [evidenceDetails, setEvidenceDetails] = useState<Evidence | null>(null)
    const [partitions, setPartitions] = useState<Partition[]>([])
    const [statistics, setStatistics] = useState<Statistics | null>(null)
    const [loading, setLoading] = useState(true)
    const [loadingDetails, setLoadingDetails] = useState(false)
    const [error, setError] = useState<string | null>(null)

    useEffect(() => {
        fetchEvidence()
    }, [])

    useEffect(() => {
        if (selectedEvidenceId) {
            fetchDiskDetails(selectedEvidenceId)
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

    const fetchDiskDetails = async (evidenceId: number) => {
        setLoadingDetails(true)
        setError(null)

        // Fetch evidence details
        const detailsResult = await getEvidenceDetails(evidenceId)
        if (detailsResult.error) {
            setError(detailsResult.error)
        } else {
            setEvidenceDetails(detailsResult.data as Evidence)
        }

        // Fetch partitions
        const partitionsResult = await listPartitions(evidenceId)
        if (partitionsResult.error) {
            setError(partitionsResult.error)
        } else {
            const data = partitionsResult.data
            if (Array.isArray(data)) {
                setPartitions(data)
            } else if (data && typeof data === 'object' && 'partitions' in data) {
                setPartitions((data as any).partitions)
            }
        }

        // Fetch statistics
        const statsResult = await getStatistics(evidenceId)
        if (!statsResult.error && statsResult.data) {
            setStatistics(statsResult.data as Statistics)
        }

        setLoadingDetails(false)
    }

    const formatBytes = (bytes: number) => {
        if (bytes === 0) return '0 Bytes'
        const k = 1024
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
        const i = Math.floor(Math.log(bytes) / Math.log(k))
        return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
    }

    const formatDate = (dateString: string) => {
        if (!dateString) return 'N/A'
        try {
            return new Date(dateString).toLocaleString()
        } catch {
            return 'Invalid Date'
        }
    }

    // Calculate original disk capacity from partition table
    const calculateDiskCapacity = (): number => {
        if (partitions.length === 0) return 0

        // Find the maximum end offset from all partitions
        // Disk capacity = (max_end_offset + 1) * sector_size
        const maxEndSector = Math.max(...partitions.map(p => p.start_offset + (p.size_bytes / 512)))
        const sectorSize = 512 // Standard sector size
        return maxEndSector * sectorSize
    }

    const InfoCard = ({
        title,
        children,
        icon: Icon,
        className = ''
    }: {
        title: string
        children: React.ReactNode
        icon: any
        className?: string
    }) => (
        <div className={`border border-[#1f2933] rounded bg-[#121821] overflow-hidden ${className}`}>
            <div className="border-b border-[#1f2933] bg-[#0b0f14] px-4 py-3 flex items-center gap-2">
                <Icon size={18} className="text-[#4fd1c5]" />
                <h3 className="text-sm font-semibold text-[#e5e7eb]">{title}</h3>
            </div>
            <div className="p-4">
                {children}
            </div>
        </div>
    )

    const InfoRow = ({
        label,
        value,
        mono = false
    }: {
        label: string
        value: string | number | React.ReactNode
        mono?: boolean
    }) => (
        <div className="flex justify-between items-start py-2 border-b border-[#1f2933] last:border-0">
            <span className="text-sm text-[#9ca3af]">{label}</span>
            <span className={`text-sm text-[#e5e7eb] text-right ${mono ? 'font-mono' : ''}`}>
                {value}
            </span>
        </div>
    )

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
                <h1 className="text-2xl font-semibold text-[#e5e7eb]">Disk Information</h1>
                <p className="text-[#9ca3af] text-sm mt-1">
                    Complete metadata and information about forensic evidence
                </p>
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
                    disabled={evidenceList.length === 0}
                >
                    {evidenceList.length === 0 ? (
                        <option>No evidence available</option>
                    ) : (
                        evidenceList.map((ev) => (
                            <option key={ev.id} value={ev.id}>
                                {ev.filename} - {ev.case_name}
                            </option>
                        ))
                    )}
                </select>
            </div>

            {loadingDetails ? (
                <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
                    <div className="flex justify-center mb-4">
                        <Loader size={24} className="animate-spin text-[#4fd1c5]" />
                    </div>
                    <p className="text-[#9ca3af]">Loading disk information...</p>
                </div>
            ) : evidenceDetails ? (
                <>
                    {/* Summary Statistics */}
                    {statistics && (
                        <div className="grid grid-cols-5 gap-4">
                            <div className="border border-[#1f2933] rounded bg-[#121821] p-4 text-center">
                                <Layers className="mx-auto mb-2 text-[#4fd1c5]" size={24} />
                                <p className="text-xs text-[#9ca3af] uppercase">Partitions</p>
                                <p className="text-2xl font-bold text-[#e5e7eb] mt-1">
                                    {statistics.partitions_found}
                                </p>
                            </div>
                            <div className="border border-[#1f2933] rounded bg-[#121821] p-4 text-center">
                                <FileStack className="mx-auto mb-2 text-[#4fd1c5]" size={24} />
                                <p className="text-xs text-[#9ca3af] uppercase">Deleted Files</p>
                                <p className="text-2xl font-bold text-[#e5e7eb] mt-1">
                                    {statistics.deleted_files_enumerated?.toLocaleString()}
                                </p>
                            </div>
                            <div className="border border-[#1f2933] rounded bg-[#121821] p-4 text-center">
                                <CheckCircle className="mx-auto mb-2 text-green-400" size={24} />
                                <p className="text-xs text-[#9ca3af] uppercase">Recovered</p>
                                <p className="text-2xl font-bold text-[#e5e7eb] mt-1">
                                    {statistics.files_recovered?.toLocaleString()}
                                </p>
                            </div>
                            <div className="border border-[#1f2933] rounded bg-[#121821] p-4 text-center">
                                <Database className="mx-auto mb-2 text-[#4fd1c5]" size={24} />
                                <p className="text-xs text-[#9ca3af] uppercase">Carved Files</p>
                                <p className="text-2xl font-bold text-[#e5e7eb] mt-1">
                                    {statistics.files_carved?.toLocaleString()}
                                </p>
                            </div>
                            <div className="border border-[#1f2933] rounded bg-[#121821] p-4 text-center">
                                <HardDrive className="mx-auto mb-2 text-[#4fd1c5]" size={24} />
                                <p className="text-xs text-[#9ca3af] uppercase">Recovered Data</p>
                                <p className="text-xl font-bold text-[#e5e7eb] mt-1">
                                    {formatBytes(statistics.total_recovered_bytes)}
                                </p>
                            </div>
                        </div>
                    )}

                    <div className="grid grid-cols-2 gap-6">
                        {/* Case Information */}
                        <InfoCard title="Case Information" icon={FileText}>
                            <div className="space-y-1">
                                <InfoRow label="Case Name" value={evidenceDetails.case_name} />
                                {evidenceDetails.case_number && (
                                    <InfoRow label="Case Number" value={evidenceDetails.case_number} mono />
                                )}
                                <InfoRow label="Examiner" value={evidenceDetails.examiner} />
                                {evidenceDetails.organization && (
                                    <InfoRow label="Organization" value={evidenceDetails.organization} />
                                )}
                                {evidenceDetails.description && (
                                    <InfoRow label="Description" value={evidenceDetails.description} />
                                )}
                                <InfoRow
                                    label="Analysis Status"
                                    value={
                                        <span className="inline-flex items-center gap-1 px-2 py-1 bg-[#4fd1c5]/20 text-[#4fd1c5] rounded text-xs">
                                            {evidenceDetails.analysis_status}
                                        </span>
                                    }
                                />
                            </div>
                        </InfoCard>

                        {/* Evidence File */}
                        <InfoCard title="Evidence File" icon={HardDrive}>
                            <div className="space-y-1">
                                <InfoRow label="Filename" value={evidenceDetails.filename} mono />
                                <InfoRow label="File Path" value={evidenceDetails.file_path} mono />
                                <InfoRow
                                    label="E01 File Size"
                                    value={formatBytes(evidenceDetails.size_bytes)}
                                />
                                {partitions.length > 0 && (
                                    <>
                                        <InfoRow
                                            label="Original Disk Capacity"
                                            value={
                                                <span className="font-semibold text-[#4fd1c5]">
                                                    {formatBytes(calculateDiskCapacity())}
                                                </span>
                                            }
                                        />
                                        <InfoRow
                                            label="Compression Ratio"
                                            value={
                                                <span className="text-green-400">
                                                    {((1 - evidenceDetails.size_bytes / calculateDiskCapacity()) * 100).toFixed(1)}% compressed
                                                </span>
                                            }
                                        />
                                    </>
                                )}
                                <InfoRow label="Upload Time" value={formatDate(evidenceDetails.upload_time)} />
                                <InfoRow
                                    label="Segmented File"
                                    value={evidenceDetails.is_segmented ? 'Yes' : 'No'}
                                />
                                {evidenceDetails.is_segmented && (
                                    <>
                                        <InfoRow
                                            label="Segment Number"
                                            value={evidenceDetails.segment_number || 'N/A'}
                                        />
                                        <InfoRow
                                            label="Total Segments"
                                            value={evidenceDetails.total_segments || 'N/A'}
                                        />
                                    </>
                                )}
                            </div>
                        </InfoCard>
                    </div>

                    <div className="grid grid-cols-2 gap-6">
                        {/* Hash Verification */}
                        <InfoCard title="Hash & Integrity" icon={Shield}>
                            <div className="space-y-1">
                                <InfoRow
                                    label="SHA-256 Hash"
                                    value={
                                        <span className="text-xs break-all">{evidenceDetails.sha256_hash}</span>
                                    }
                                />
                                {evidenceDetails.expected_hash && (
                                    <InfoRow
                                        label="Expected Hash"
                                        value={
                                            <span className="text-xs break-all">{evidenceDetails.expected_hash}</span>
                                        }
                                    />
                                )}
                                <InfoRow
                                    label="Hash Verified"
                                    value={
                                        evidenceDetails.hash_verified ? (
                                            <span className="inline-flex items-center gap-1 text-green-400">
                                                <CheckCircle size={16} />
                                                Verified
                                            </span>
                                        ) : (
                                            <span className="inline-flex items-center gap-1 text-yellow-400">
                                                <XCircle size={16} />
                                                Not Verified
                                            </span>
                                        )
                                    }
                                />
                            </div>
                        </InfoCard>

                        {/* Scan Status */}
                        <InfoCard title="Scan Status" icon={Info}>
                            <div className="space-y-1">
                                <InfoRow
                                    label="Partition Scan"
                                    value={
                                        evidenceDetails.partition_scan_completed ? (
                                            <span className="inline-flex items-center gap-1 text-green-400">
                                                <CheckCircle size={16} />
                                                Completed
                                            </span>
                                        ) : (
                                            <span className="inline-flex items-center gap-1 text-[#9ca3af]">
                                                <Clock size={16} />
                                                Not Started
                                            </span>
                                        )
                                    }
                                />
                                <InfoRow
                                    label="Deleted Files Scan"
                                    value={
                                        evidenceDetails.deleted_scan_completed ? (
                                            <span className="inline-flex items-center gap-1 text-green-400">
                                                <CheckCircle size={16} />
                                                Completed
                                            </span>
                                        ) : (
                                            <span className="inline-flex items-center gap-1 text-[#9ca3af]">
                                                <Clock size={16} />
                                                Not Started
                                            </span>
                                        )
                                    }
                                />
                            </div>
                        </InfoCard>
                    </div>

                    {/* Partition Table */}
                    {partitions.length > 0 && (
                        <InfoCard title="Partition Table" icon={Layers} className="col-span-2">
                            <div className="overflow-x-auto">
                                <table className="w-full text-sm">
                                    <thead>
                                        <tr className="border-b border-[#1f2933]">
                                            <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                                                #
                                            </th>
                                            <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                                                Slot
                                            </th>
                                            <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                                                Filesystem
                                            </th>
                                            <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                                                Start Offset
                                            </th>
                                            <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                                                Size
                                            </th>
                                            <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                                                Status
                                            </th>
                                            <th className="px-4 py-2 text-left text-xs font-medium text-[#9ca3af] uppercase">
                                                Deleted Files
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {partitions.map((partition) => (
                                            <tr
                                                key={partition.id}
                                                className="border-b border-[#1f2933] hover:bg-[#1f2933] transition-colors"
                                            >
                                                <td className="px-4 py-3 text-[#e5e7eb]">
                                                    {partition.partition_number}
                                                </td>
                                                <td className="px-4 py-3 text-[#e5e7eb] font-mono">
                                                    {partition.slot}
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs ${partition.is_ntfs
                                                        ? 'bg-[#4fd1c5]/20 text-[#4fd1c5]'
                                                        : 'bg-[#9ca3af]/20 text-[#9ca3af]'
                                                        }`}>
                                                        {partition.filesystem_type}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-3 text-[#9ca3af] font-mono text-xs">
                                                    {partition.start_offset.toLocaleString()}
                                                </td>
                                                <td className="px-4 py-3 text-[#e5e7eb]">
                                                    {formatBytes(partition.size_bytes)}
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className={`text-xs ${partition.scan_status === 'completed'
                                                        ? 'text-green-400'
                                                        : partition.scan_status === 'scanning'
                                                            ? 'text-yellow-400'
                                                            : 'text-[#9ca3af]'
                                                        }`}>
                                                        {partition.scan_status}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-3 text-[#e5e7eb]">
                                                    {partition.deleted_file_count?.toLocaleString() || '-'}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </InfoCard>
                    )}
                </>
            ) : (
                <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
                    <HardDrive className="mx-auto mb-4 text-[#6b7280]" size={48} />
                    <p className="text-[#9ca3af]">Select evidence to view disk information</p>
                </div>
            )}
        </div>
    )
}
