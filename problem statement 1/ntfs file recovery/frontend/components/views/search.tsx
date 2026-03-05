'use client'

import { useState } from 'react'
import { Search, Download, File, Loader, AlertCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { searchFiles, downloadRecoveredFile, downloadCarvedFile } from '@/lib/api-client'

interface SearchResult {
    id: number
    filename?: string
    carved_filename?: string
    size_bytes: number
    sha256_hash: string
    type: 'recovered' | 'carved'
}

export default function SearchView() {
    const [query, setQuery] = useState('')
    const [searchType, setSearchType] = useState<'all' | 'recovered' | 'carved'>('all')
    const [results, setResults] = useState<SearchResult[]>([])
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const [downloading, setDownloading] = useState<number | null>(null)

    const handleSearch = async (e?: React.FormEvent) => {
        if (e) e.preventDefault()
        if (!query.trim()) return

        setLoading(true)
        setError(null)
        const result = await searchFiles(query, searchType)
        if (result.error) {
            setError(result.error)
            setResults([])
        } else {
            const data = result.data as any
            const recovered = (data.recovered_files || []).map((f: any) => ({
                ...f,
                filename: f.original_filename,
                type: 'recovered' as const
            }))
            const carved = (data.carved_files || []).map((f: any) => ({
                ...f,
                filename: f.carved_filename,
                type: 'carved' as const
            }))
            setResults([...recovered, ...carved])
        }
        setLoading(false)
    }

    const handleDownload = async (file: SearchResult) => {
        setDownloading(file.id)
        try {
            const url = file.type === 'recovered'
                ? await downloadRecoveredFile(file.id)
                : await downloadCarvedFile(file.id)

            const link = document.createElement('a')
            link.href = url
            link.download = file.filename || file.carved_filename || 'download'
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

    const getDisplayName = (file: SearchResult) => {
        return file.filename || `File #${file.id}`
    }

    return (
        <div className="p-8 space-y-6">
            <div>
                <h1 className="text-2xl font-semibold text-[#e5e7eb]">Global File Search</h1>
                <p className="text-[#9ca3af] text-sm mt-1">Search through all recovered and carved files</p>
            </div>

            <form onSubmit={handleSearch} className="flex gap-4 items-end bg-[#121821] p-6 rounded-lg border border-[#1f2933]">
                <div className="flex-1 space-y-2">
                    <label className="text-sm font-medium text-[#e5e7eb]">Search Query</label>
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-[#9ca3af]" size={18} />
                        <input
                            type="text"
                            value={query}
                            onChange={(e) => setQuery(e.target.value)}
                            placeholder="Enter filename, extension or hash..."
                            className="w-full pl-10 pr-4 py-2 bg-[#0b0f14] border border-[#1f2933] rounded text-[#e5e7eb] focus:outline-none focus:border-[#4fd1c5]"
                        />
                    </div>
                </div>

                <div className="w-48 space-y-2">
                    <label className="text-sm font-medium text-[#e5e7eb]">File Type</label>
                    <select
                        value={searchType}
                        onChange={(e) => setSearchType(e.target.value as any)}
                        className="w-full px-4 py-2 bg-[#0b0f14] border border-[#1f2933] rounded text-[#e5e7eb] focus:outline-none focus:border-[#4fd1c5]"
                    >
                        <option value="all">All Sources</option>
                        <option value="recovered">Recovered</option>
                        <option value="carved">Carved</option>
                    </select>
                </div>

                <Button
                    type="submit"
                    disabled={loading || !query.trim()}
                    className="bg-[#4fd1c5] text-[#0b0f14] hover:bg-[#45b8ad] h-10 px-8"
                >
                    {loading ? <Loader size={18} className="animate-spin" /> : 'Search'}
                </Button>
            </form>

            {error && (
                <div className="border border-red-900 rounded bg-red-900/10 p-4 flex gap-3">
                    <AlertCircle size={20} className="text-red-500 flex-shrink-0" />
                    <div className="text-red-300 text-sm">{error}</div>
                </div>
            )}

            {results.length > 0 ? (
                <div className="border border-[#1f2933] rounded bg-[#121821] overflow-hidden">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="border-b border-[#1f2933] bg-[#0b0f14]">
                                <th className="px-4 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">Type</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">Filename</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">Size</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">SHA-256</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-[#9ca3af] uppercase">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {results.map((file) => (
                                <tr key={`${file.type}-${file.id}`} className="border-b border-[#1f2933] hover:bg-[#1f2933] transition-colors">
                                    <td className="px-4 py-3">
                                        <span className={`px-2 py-0.5 rounded-full text-[10px] uppercase font-bold ${file.type === 'recovered' ? 'bg-[#4fd1c5]/20 text-[#4fd1c5]' : 'bg-purple-500/20 text-purple-400'
                                            }`}>
                                            {file.type}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3 text-[#e5e7eb] font-medium">{getDisplayName(file)}</td>
                                    <td className="px-4 py-3 text-[#9ca3af]">{formatBytes(file.size_bytes)}</td>
                                    <td className="px-4 py-3 text-[#9ca3af] font-mono text-xs">{file.sha256_hash?.substring(0, 16)}...</td>
                                    <td className="px-4 py-3">
                                        <Button
                                            onClick={() => handleDownload(file)}
                                            disabled={downloading === file.id}
                                            variant="ghost"
                                            className="h-8 w-8 p-0 hover:text-[#4fd1c5] hover:bg-transparent"
                                        >
                                            {downloading === file.id ? <Loader size={16} className="animate-spin" /> : <Download size={16} />}
                                        </Button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            ) : query && !loading ? (
                <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center text-[#9ca3af]">
                    <File size={48} className="mx-auto mb-4 opacity-50" />
                    <p>No results found for "{query}"</p>
                </div>
            ) : !loading && (
                <div className="border border-[#1f2933] rounded bg-[#121821] p-12 text-center text-[#9ca3af]">
                    <Search size={48} className="mx-auto mb-4 opacity-50" />
                    <p>Enter a search query to find files across all evidence sources.</p>
                </div>
            )}
        </div>
    )
}
