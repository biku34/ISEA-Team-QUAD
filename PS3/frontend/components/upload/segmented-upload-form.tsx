'use client'

import React, { useState } from 'react'
import { Upload, X, CheckCircle, AlertCircle, FileStack } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { FileDropzone } from '@/components/ui/file-dropzone'
import { ProgressMulti, FileProgress } from '@/components/ui/progress-multi'
import {
    validateSegments,
    formatBytes,
    ParsedSegment,
    ValidationResult
} from './segment-validator'
import { uploadEvidence, uploadSegmentedEvidence, UploadMetadata } from '@/lib/api-client'

interface SegmentedUploadFormProps {
    onUploadComplete: () => void
    onCancel?: () => void
}

export function SegmentedUploadForm({ onUploadComplete, onCancel }: SegmentedUploadFormProps) {
    const [uploadMode, setUploadMode] = useState<'single' | 'multi'>('single')
    const [selectedFiles, setSelectedFiles] = useState<File[]>([])
    const [validation, setValidation] = useState<ValidationResult | null>(null)
    const [uploading, setUploading] = useState(false)
    const [uploadProgress, setUploadProgress] = useState<FileProgress[]>([])
    const [overallProgress, setOverallProgress] = useState(0)
    const [error, setError] = useState<string | null>(null)

    // Form fields
    const [caseName, setCaseName] = useState('')
    const [examiner, setExaminer] = useState('')
    const [caseNumber, setCaseNumber] = useState('')
    const [organization, setOrganization] = useState('')
    const [description, setDescription] = useState('')
    const [expectedHash, setExpectedHash] = useState('')

    const handleFilesSelected = (files: File[]) => {
        setSelectedFiles(files)
        setError(null)

        if (uploadMode === 'multi') {
            const result = validateSegments(files)
            setValidation(result)
            if (!result.valid) {
                setError(result.error || 'Validation failed')
            }
        } else {
            setValidation({ valid: true })
        }
    }

    const handleRemoveFile = (index: number) => {
        const newFiles = selectedFiles.filter((_, i) => i !== index)
        setSelectedFiles(newFiles)
        if (uploadMode === 'multi' && newFiles.length > 0) {
            const result = validateSegments(newFiles)
            setValidation(result)
        } else {
            setValidation(null)
        }
    }

    const handleUpload = async () => {
        if (selectedFiles.length === 0) {
            setError('Please select files to upload')
            return
        }

        if (!caseName || !examiner) {
            setError('Case name and examiner are required')
            return
        }

        if (uploadMode === 'multi' && (!validation || !validation.valid)) {
            setError('Please fix validation errors before uploading')
            return
        }

        setUploading(true)
        setError(null)

        try {
            if (uploadMode === 'single') {
                // Single file upload
                const result = await uploadEvidence(selectedFiles[0], caseName, examiner)

                if (result.error) {
                    setError(result.error)
                } else {
                    onUploadComplete()
                }
            } else {
                // Multi-segment upload
                const metadata: UploadMetadata = {
                    caseName,
                    examiner,
                    caseNumber: caseNumber || undefined,
                    organization: organization || undefined,
                    description: description || undefined,
                    expectedHash: expectedHash || undefined
                }

                // Initialize progress tracking
                const initialProgress: FileProgress[] = selectedFiles.map(file => ({
                    filename: file.name,
                    size: file.size,
                    loaded: 0,
                    status: 'pending' as const
                }))
                setUploadProgress(initialProgress)

                const result = await uploadSegmentedEvidence(
                    selectedFiles,
                    metadata,
                    (progressData) => {
                        setOverallProgress(progressData.percent)

                        setUploadProgress(prev => prev.map(p => {
                            // If this is the current file, update it
                            if (p.filename === progressData.currentFile) {
                                return {
                                    ...p,
                                    status: 'uploading' as const,
                                    loaded: progressData.loaded - (progressData.percent > 0 ? (progressData.loaded - (p.size * (progressData.percent / 100))) : 0) // Complex calc not needed, keep it simple
                                }
                            }
                            // If file is already finished in the sequence
                            const fileIndex = selectedFiles.findIndex(f => f.name === p.filename)
                            const currentFileIndex = selectedFiles.findIndex(f => f.name === progressData.currentFile)

                            if (fileIndex < currentFileIndex) {
                                return { ...p, status: 'complete' as const, loaded: p.size }
                            }

                            return p
                        }))
                    }
                )

                if (result.error) {
                    setError(result.error)
                    setUploadProgress(prev => prev.map(p => ({
                        ...p,
                        status: p.status === 'complete' ? 'complete' : 'error' as const,
                        error: p.status === 'complete' ? undefined : result.error
                    })))
                } else {
                    setUploadProgress(prev => prev.map(p => ({
                        ...p,
                        status: 'complete' as const,
                        loaded: p.size
                    })))
                    setOverallProgress(100)

                    // Wait a moment to show completion before closing
                    setTimeout(() => {
                        onUploadComplete()
                    }, 1000)
                }
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Upload failed')
        } finally {
            setUploading(false)
        }
    }

    const canUpload = selectedFiles.length > 0 && caseName && examiner && (uploadMode === 'single' || (validation?.valid ?? false))

    return (
        <div className="space-y-6">
            <Tabs value={uploadMode} onValueChange={(v) => {
                setUploadMode(v as 'single' | 'multi')
                setSelectedFiles([])
                setValidation(null)
                setError(null)
            }}>
                <TabsList className="grid w-full grid-cols-2">
                    <TabsTrigger value="single">Single File</TabsTrigger>
                    <TabsTrigger value="multi">Multi-Segment</TabsTrigger>
                </TabsList>

                <TabsContent value="single" className="space-y-4">
                    <FileDropzone
                        onFilesSelected={(files) => handleFilesSelected([files[0]])}
                        multiple={false}
                        disabled={uploading}
                    />
                </TabsContent>

                <TabsContent value="multi" className="space-y-4">
                    <FileDropzone
                        onFilesSelected={handleFilesSelected}
                        multiple={true}
                        disabled={uploading}
                    />
                </TabsContent>
            </Tabs>

            {/* Selected Files Display */}
            {selectedFiles.length > 0 && !uploading && (
                <div className="border border-[#1f2933] rounded-lg bg-[#0b0f14] p-4 space-y-3">
                    <div className="flex items-center justify-between">
                        <h3 className="text-sm font-medium text-[#e5e7eb]">Selected Files</h3>
                        {uploadMode === 'multi' && validation && (
                            <span className={`text-xs px-2 py-1 rounded ${validation.valid
                                ? 'bg-green-900/20 text-green-400'
                                : 'bg-red-900/20 text-red-400'
                                }`}>
                                {validation.valid ? '✓ Valid' : '✗ Invalid'}
                            </span>
                        )}
                    </div>

                    <div className="space-y-2">
                        {selectedFiles.map((file, index) => (
                            <div
                                key={index}
                                className="flex items-center justify-between p-2 bg-[#121821] rounded"
                            >
                                <div className="flex items-center gap-2 min-w-0 flex-1">
                                    <FileStack size={16} className="text-[#4fd1c5] flex-shrink-0" />
                                    <span className="text-sm text-[#e5e7eb] truncate">{file.name}</span>
                                    <span className="text-xs text-[#9ca3af]">({formatBytes(file.size)})</span>
                                </div>
                                <button
                                    onClick={() => handleRemoveFile(index)}
                                    className="text-[#9ca3af] hover:text-red-500 transition-colors"
                                    disabled={uploading}
                                >
                                    <X size={16} />
                                </button>
                            </div>
                        ))}
                    </div>

                    {uploadMode === 'multi' && validation && (
                        <div className="pt-2 border-t border-[#1f2933]">
                            <p className="text-sm text-[#e5e7eb]">
                                Total: {selectedFiles.length} segments, {formatBytes(validation.totalSize || 0)}
                            </p>
                            {validation.baseName && (
                                <p className="text-xs text-[#9ca3af]">Base name: {validation.baseName}</p>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* Validation Errors */}
            {error && !uploading && (
                <div className="border border-red-900 rounded bg-red-900/10 p-3 flex gap-2">
                    <AlertCircle size={16} className="text-red-500 flex-shrink-0 mt-0.5" />
                    <p className="text-sm text-red-400">{error}</p>
                </div>
            )}

            {/* Upload Progress */}
            {uploading && uploadMode === 'multi' && uploadProgress.length > 0 && (
                <ProgressMulti
                    files={uploadProgress}
                    overallProgress={overallProgress}
                />
            )}

            {/* Metadata Form */}
            <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                        <Label htmlFor="caseName" className="text-[#e5e7eb]">
                            Case Name <span className="text-red-500">*</span>
                        </Label>
                        <Input
                            id="caseName"
                            value={caseName}
                            onChange={(e) => setCaseName(e.target.value)}
                            placeholder="CASE-2024-001"
                            disabled={uploading}
                            className="bg-[#0b0f14] border-[#1f2933]"
                        />
                    </div>

                    <div className="space-y-2">
                        <Label htmlFor="examiner" className="text-[#e5e7eb]">
                            Examiner Name <span className="text-red-500">*</span>
                        </Label>
                        <Input
                            id="examiner"
                            value={examiner}
                            onChange={(e) => setExaminer(e.target.value)}
                            placeholder="John Doe"
                            disabled={uploading}
                            className="bg-[#0b0f14] border-[#1f2933]"
                        />
                    </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                        <Label htmlFor="caseNumber" className="text-[#e5e7eb]">Case Number</Label>
                        <Input
                            id="caseNumber"
                            value={caseNumber}
                            onChange={(e) => setCaseNumber(e.target.value)}
                            placeholder="Optional"
                            disabled={uploading}
                            className="bg-[#0b0f14] border-[#1f2933]"
                        />
                    </div>

                    <div className="space-y-2">
                        <Label htmlFor="organization" className="text-[#e5e7eb]">Organization</Label>
                        <Input
                            id="organization"
                            value={organization}
                            onChange={(e) => setOrganization(e.target.value)}
                            placeholder="Optional"
                            disabled={uploading}
                            className="bg-[#0b0f14] border-[#1f2933]"
                        />
                    </div>
                </div>

                <div className="space-y-2">
                    <Label htmlFor="description" className="text-[#e5e7eb]">Description</Label>
                    <Textarea
                        id="description"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        placeholder="Optional description..."
                        disabled={uploading}
                        className="bg-[#0b0f14] border-[#1f2933] min-h-[80px]"
                    />
                </div>

                {uploadMode === 'multi' && (
                    <div className="space-y-2">
                        <Label htmlFor="expectedHash" className="text-[#e5e7eb]">
                            Expected SHA-256 Hash (Primary Segment)
                        </Label>
                        <Input
                            id="expectedHash"
                            value={expectedHash}
                            onChange={(e) => setExpectedHash(e.target.value)}
                            placeholder="Optional - for verification"
                            disabled={uploading}
                            className="bg-[#0b0f14] border-[#1f2933] font-mono text-xs"
                        />
                    </div>
                )}
            </div>

            {/* Action Buttons */}
            <div className="flex justify-end gap-3">
                {onCancel && (
                    <Button
                        variant="outline"
                        onClick={onCancel}
                        disabled={uploading}
                        className="border-[#1f2933]"
                    >
                        Cancel
                    </Button>
                )}
                <Button
                    onClick={handleUpload}
                    disabled={!canUpload || uploading}
                    className="gap-2 bg-[#4fd1c5] text-[#0b0f14] hover:bg-[#45b8ad]"
                >
                    {uploading ? (
                        <>
                            <div className="w-4 h-4 border-2 border-[#0b0f14] border-t-transparent rounded-full animate-spin" />
                            Uploading...
                        </>
                    ) : (
                        <>
                            <Upload size={16} />
                            Upload {uploadMode === 'multi' ? 'Segments' : 'Evidence'}
                        </>
                    )}
                </Button>
            </div>
        </div>
    )
}
