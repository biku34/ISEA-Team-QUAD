'use client'

import React, { useState } from 'react'
import { ChevronDown, ChevronUp, Layers } from 'lucide-react'
import { Evidence, SegmentInfo } from '@/lib/api-client'
import { cn } from '@/lib/utils'

interface EvidenceDetailCardProps {
    evidence: Evidence
    segmentInfo?: {
        total_segments: number
        total_size: number
        base_name: string
        segments: SegmentInfo[]
    }
}

export function EvidenceDetailCard({ evidence, segmentInfo }: EvidenceDetailCardProps) {
    const [isExpanded, setIsExpanded] = useState(false)

    const formatBytes = (bytes: number) => {
        if (bytes === 0) return '0 Bytes'
        const k = 1024
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
        const i = Math.floor(Math.log(bytes) / Math.log(k))
        return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
    }

    const formatHash = (hash: string, length = 16) => {
        return hash.substring(0, length) + '...'
    }

    if (!evidence.is_segmented) {
        return null
    }

    return (
        <div className="border border-[#1f2933] rounded-lg bg-[#0b0f14] overflow-hidden">
            <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="w-full px-4 py-3 flex items-center justify-between hover:bg-[#121821] transition-colors"
            >
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-[#4fd1c5]/10 rounded">
                        <Layers size={20} className="text-[#4fd1c5]" />
                    </div>
                    <div className="text-left">
                        <p className="text-sm font-medium text-[#e5e7eb]">
                            Segmented Evidence
                        </p>
                        <p className="text-xs text-[#9ca3af]">
                            {evidence.total_segments} segments • {formatBytes(evidence.size_bytes)}
                        </p>
                    </div>
                </div>
                {isExpanded ? (
                    <ChevronUp size={20} className="text-[#9ca3af]" />
                ) : (
                    <ChevronDown size={20} className="text-[#9ca3af]" />
                )}
            </button>

            {isExpanded && segmentInfo && (
                <div className="px-4 pb-4 space-y-3 border-t border-[#1f2933] pt-3">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                            <p className="text-[#9ca3af] text-xs mb-1">Base Name</p>
                            <p className="text-[#e5e7eb] font-mono">{segmentInfo.base_name}</p>
                        </div>
                        <div>
                            <p className="text-[#9ca3af] text-xs mb-1">Total Segments</p>
                            <p className="text-[#e5e7eb]">{segmentInfo.total_segments}</p>
                        </div>
                    </div>

                    <div>
                        <p className="text-[#9ca3af] text-xs mb-2">Segment Details</p>
                        <div className="space-y-2 max-h-[300px] overflow-y-auto">
                            {segmentInfo.segments.map((segment) => (
                                <div
                                    key={segment.segment_number}
                                    className="bg-[#121821] rounded p-3 space-y-1"
                                >
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm font-medium text-[#e5e7eb]">
                                            Segment {segment.segment_number}
                                        </span>
                                        <span className="text-xs text-[#9ca3af]">
                                            {formatBytes(segment.size_bytes)}
                                        </span>
                                    </div>
                                    <p className="text-xs text-[#9ca3af] truncate">
                                        {segment.filename}
                                    </p>
                                    <p className="text-xs text-[#9ca3af] font-mono">
                                        SHA-256: {formatHash(segment.sha256_hash, 24)}
                                    </p>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}
