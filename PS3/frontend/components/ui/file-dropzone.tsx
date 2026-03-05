'use client'

import React, { useCallback, useState } from 'react'
import { Upload, File as FileIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface FileDropzoneProps {
    onFilesSelected: (files: File[]) => void
    accept?: string
    multiple?: boolean
    disabled?: boolean
    maxSize?: number
    className?: string
}

export function FileDropzone({
    onFilesSelected,
    accept = '.E01,.E02,.E03,.E04,.E05,.E06,.E07,.E08,.E09,.e01,.e02,.e03,.e04,.e05,.e06,.e07,.e08,.e09',
    multiple = true,
    disabled = false,
    maxSize,
    className
}: FileDropzoneProps) {
    const [isDragging, setIsDragging] = useState(false)

    const handleDragEnter = useCallback((e: React.DragEvent) => {
        e.preventDefault()
        e.stopPropagation()
        if (!disabled) {
            setIsDragging(true)
        }
    }, [disabled])

    const handleDragLeave = useCallback((e: React.DragEvent) => {
        e.preventDefault()
        e.stopPropagation()
        setIsDragging(false)
    }, [])

    const handleDragOver = useCallback((e: React.DragEvent) => {
        e.preventDefault()
        e.stopPropagation()
    }, [])

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault()
        e.stopPropagation()
        setIsDragging(false)

        if (disabled) return

        const files = Array.from(e.dataTransfer.files)
        if (files.length > 0) {
            onFilesSelected(files)
        }
    }, [disabled, onFilesSelected])

    const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
        const files = Array.from(e.target.files || [])
        if (files.length > 0) {
            onFilesSelected(files)
        }
    }, [onFilesSelected])

    return (
        <div
            className={cn(
                'relative border-2 border-dashed rounded-lg transition-all duration-200',
                isDragging
                    ? 'border-[#4fd1c5] bg-[#4fd1c5]/10'
                    : 'border-[#1f2933] bg-[#0b0f14] hover:border-[#4fd1c5]/50',
                disabled && 'opacity-50 cursor-not-allowed',
                className
            )}
            onDragEnter={handleDragEnter}
            onDragLeave={handleDragLeave}
            onDragOver={handleDragOver}
            onDrop={handleDrop}
        >
            <input
                type="file"
                accept={accept}
                multiple={multiple}
                onChange={handleFileInput}
                disabled={disabled}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer disabled:cursor-not-allowed"
                id="file-upload"
            />
            <label
                htmlFor="file-upload"
                className="flex flex-col items-center justify-center p-8 cursor-pointer"
            >
                <div className={cn(
                    'mb-4 p-4 rounded-full transition-colors',
                    isDragging ? 'bg-[#4fd1c5]/20' : 'bg-[#1f2933]'
                )}>
                    <Upload className={cn(
                        'w-8 h-8 transition-colors',
                        isDragging ? 'text-[#4fd1c5]' : 'text-[#9ca3af]'
                    )} />
                </div>
                <p className="text-[#e5e7eb] font-medium mb-1">
                    {isDragging ? 'Drop files here' : 'Drag & drop files here'}
                </p>
                <p className="text-[#9ca3af] text-sm mb-1">or click to browse</p>
                {multiple && (
                    <p className="text-[#9ca3af] text-xs mt-2">
                        Select all segments at once (E01, E02, E03...)
                    </p>
                )}
                {maxSize && (
                    <p className="text-[#9ca3af] text-xs mt-1">
                        Maximum file size: {Math.round(maxSize / 1024 / 1024 / 1024)}GB per file
                    </p>
                )}
            </label>
        </div>
    )
}
