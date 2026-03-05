'use client'

import { useState, useEffect, useMemo } from 'react'
import { Download, Zap, Loader, AlertCircle, FileType, Filter } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { listCarvedFiles, downloadCarvedFile } from '@/lib/api-client'

interface CarvedFile {
    id: number
    carved_filename: string
    size_bytes: number
    signature_type: string
    sha256_hash: string
    created_at: string
}

export default function CarvedFilesView() {
    const [carvedFiles, setCarvedFiles] = useState<CarvedFile[]>([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)
    const [downloading, setDownloading] = useState<number | null>(null)
    const [sortByType, setSortByType] = useState(true)

    useEffect(() => {
        fetchCarvedFiles()
    }, [])

    const fetchCarvedFiles = async () => {
        setLoading(true)
        setError(null)
        const result = await listCarvedFiles()
        if (result.error) {
            setError(result.error)
        } else {
            const data = result.data as any
            if (Array.isArray(data)) {
                setCarvedFiles(data)
            } else if (data && Array.isArray(data.carved_files)) {
                setCarvedFiles(data.carved_files)
            } else {
                setCarvedFiles([])
            }
        }
        setLoading(false)
    }

    const getTypeStyle = (type: string) => {
        const t = type.toLowerCase()
        if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'heic'].includes(t)) {
            return {
                bg: 'bg-orange-500/20',
                text: 'text-orange-400',
                border: 'border-orange-500/30',
                group: 'Images'
            }
        }
        if (['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf'].includes(t)) {
            return {
                bg: 'bg-blue-500/20',
                text: 'text-blue-400',
                border: 'border-blue-500/30',
                group: 'Documents'
            }
        }
        if (['zip', 'rar', '7z', 'tar', 'gz', 'iso'].includes(t)) {
            return {
                bg: 'bg-purple-500/20',
                text: 'text-purple-400',
                border: 'border-purple-500/30',
                group: 'Archives'
            }
        }
        if (['exe', 'dll', 'bin', 'sys', 'bat', 'sh'].includes(t)) {
            return {
                bg: 'bg-red-500/20',
                text: 'text-red-400',
                border: 'border-red-500/30',
                group: 'System/Executables'
            }
        }
        if (['mp3', 'wav', 'ogg', 'm4a', 'mp4', 'avi', 'mkv', 'mov'].includes(t)) {
            return {
                bg: 'bg-green-500/20',
                text: 'text-green-400',
                border: 'border-green-500/30',
                group: 'Media'
            }
        }
        return {
            bg: 'bg-slate-500/20',
            text: 'text-slate-400',
            border: 'border-slate-500/30',
            group: 'Unknown'
        }
    }

    const processedFiles = useMemo(() => {
        if (!sortByType) return carvedFiles

        return [...carvedFiles].sort((a, b) => {
            const typeA = getTypeStyle(a.signature_type).group
            const typeB = getTypeStyle(b.signature_type).group

            if (typeA !== typeB) {
                return typeA.localeCompare(typeB)
            }
            return a.carved_filename.localeCompare(b.carved_filename)
        })
    }, [carvedFiles, sortByType])

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

    if (loading) {
        return (
            <div className="p-8">
                <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center">
                    <Loader size={24} className="animate-spin text-[#4fd1c5] mx-auto mb-4" />
                    <p className="text-[#9ca3af]">Loading carved files...</p>
                </div>
            </div>
        )
    }

    return (
        <div className="p-8 space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-semibold text-[#e5e7eb] flex items-center gap-2">
                        <FileType className="text-[#4fd1c5]" />
                        Carved Files
                    </h1>
                    <p className="text-[#9ca3af] text-sm mt-1">
                        {carvedFiles.length} file{carvedFiles.length !== 1 ? 's' : ''} organized by signature type
                    </p>
                </div>
                <div className="flex gap-2">
                    <Button
                        onClick={() => setSortByType(!sortByType)}
                        variant="outline"
                        className={`gap-2 border-[#1f2933] transition-colors ${sortByType ? 'bg-[#4fd1c5]/10 border-[#4fd1c5]/30 text-[#4fd1c5]' : 'text-[#9ca3af]'}`}
                    >
                        <Filter size={16} />
                        {sortByType ? 'Grouped by Type' : 'Natural Order'}
                    </Button>
                    <Button
                        onClick={fetchCarvedFiles}
                        variant="outline"
                        className="gap-2 border-[#1f2933] text-[#e5e7eb] hover:bg-[#1f2933]"
                    >
                        <Loader size={16} />
                        Refresh
                    </Button>
                </div>
            </div>

            {error && (
                <div className="border border-red-900 rounded bg-red-900/10 p-4 flex gap-3">
                    <AlertCircle size={20} className="text-red-500 flex-shrink-0" />
                    <div className="text-red-300 text-sm">{error}</div>
                </div>
            )}

            {processedFiles.length > 0 ? (
                <div className="border border-[#1f2933] rounded bg-[#121821] overflow-hidden">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="border-b border-[#1f2933] bg-[#0b0f14]">
                                <th className="px-4 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">Filename</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">Type</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">Category</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">Size</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">SHA-256</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase text-right">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {processedFiles.map((file) => {
                                const style = getTypeStyle(file.signature_type)
                                return (
                                    <tr key={file.id} className="border-b border-[#1f2933] hover:bg-[#1f2933] transition-colors group">
                                        <td className="px-4 py-3 text-[#e5e7eb] font-mono text-xs">{file.carved_filename}</td>
                                        <td className="px-4 py-3">
                                            <span className={`px-2 py-0.5 rounded-full border ${style.bg} ${style.text} ${style.border} text-[10px] uppercase font-bold`}>
                                                {file.signature_type}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className="text-[#9ca3af] text-xs">
                                                {style.group}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 text-[#9ca3af]">{formatBytes(file.size_bytes)}</td>
                                        <td className="px-4 py-3 text-[#9ca3af] font-mono text-xs">
                                            {file.sha256_hash ? file.sha256_hash.substring(0, 16) : 'N/A'}...
                                        </td>
                                        <td className="px-4 py-3 text-right">
                                            <Button
                                                onClick={() => handleDownload(file.id, file.carved_filename)}
                                                disabled={downloading === file.id}
                                                variant="ghost"
                                                className="h-8 w-8 p-0 hover:text-[#4fd1c5] hover:bg-[#4fd1c5]/10 opacity-60 group-hover:opacity-100 transition-opacity"
                                            >
                                                {downloading === file.id ? <Loader size={16} className="animate-spin" /> : <Download size={16} />}
                                            </Button>
                                        </td>
                                    </tr>
                                )
                            })}
                        </tbody>
                    </table>
                </div>
            ) : (
                <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center text-[#9ca3af]">
                    <Zap size={48} className="mx-auto mb-4 opacity-50" />
                    <p>No carved files found yet. Start a carving session in the "Carving Action" view.</p>
                </div>
            )}
        </div>
    )
}
