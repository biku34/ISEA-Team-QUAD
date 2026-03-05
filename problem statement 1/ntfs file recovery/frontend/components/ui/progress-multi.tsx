'use client'

import React from 'react'
import { cn } from '@/lib/utils'
import { Progress } from '@/components/ui/progress'
import { CheckCircle, Loader, AlertCircle } from 'lucide-react'

export interface FileProgress {
    filename: string
    size: number
    loaded: number
    status: 'pending' | 'uploading' | 'complete' | 'error'
    error?: string
}

interface ProgressMultiProps {
    files: FileProgress[]
    overallProgress: number
    className?: string
}

export function ProgressMulti({ files, overallProgress, className }: ProgressMultiProps) {
    const totalSize = files.reduce((sum, f) => sum + f.size, 0)
    const uploadedSize = files.reduce((sum, f) => sum + f.loaded, 0)

    const formatBytes = (bytes: number) => {
        if (bytes === 0) return '0 B'
        const k = 1024
        const sizes = ['B', 'KB', 'MB', 'GB']
        const i = Math.floor(Math.log(bytes) / Math.log(k))
        return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
    }

    return (
        <div className={cn('space-y-4', className)}>
            <div>
                <div className="flex justify-between items-center mb-2">
                    <p className="text-sm font-medium text-[#e5e7eb]">Overall Progress</p>
                    <p className="text-sm text-[#9ca3af]">
                        {formatBytes(uploadedSize)} / {formatBytes(totalSize)} ({Math.round(overallProgress)}%)
                    </p>
                </div>
                <Progress value={overallProgress} className="h-2" />
            </div>

            <div className="space-y-2">
                <p className="text-xs font-medium text-[#9ca3af] uppercase">Segments</p>
                {files.map((file, index) => {
                    const progress = file.size > 0 ? (file.loaded / file.size) * 100 : 0

                    return (
                        <div key={index} className="bg-[#0b0f14] rounded p-3 space-y-2">
                            <div className="flex items-center justify-between gap-2">
                                <div className="flex items-center gap-2 min-w-0 flex-1">
                                    {file.status === 'complete' && (
                                        <CheckCircle size={16} className="text-green-500 flex-shrink-0" />
                                    )}
                                    {file.status === 'uploading' && (
                                        <Loader size={16} className="text-[#4fd1c5] animate-spin flex-shrink-0" />
                                    )}
                                    {file.status === 'error' && (
                                        <AlertCircle size={16} className="text-red-500 flex-shrink-0" />
                                    )}
                                    {file.status === 'pending' && (
                                        <div className="w-4 h-4 rounded-full border-2 border-[#9ca3af] flex-shrink-0" />
                                    )}
                                    <span className="text-sm text-[#e5e7eb] truncate">{file.filename}</span>
                                </div>
                                <span className="text-xs text-[#9ca3af] whitespace-nowrap">
                                    {file.status === 'complete'
                                        ? formatBytes(file.size)
                                        : `${formatBytes(file.loaded)} / ${formatBytes(file.size)}`
                                    }
                                </span>
                            </div>

                            {file.status !== 'pending' && (
                                <Progress
                                    value={progress}
                                    className={cn(
                                        'h-1',
                                        file.status === 'error' && 'bg-red-900/20'
                                    )}
                                />
                            )}

                            {file.error && (
                                <p className="text-xs text-red-400">{file.error}</p>
                            )}
                        </div>
                    )
                })}
            </div>
        </div>
    )
}
