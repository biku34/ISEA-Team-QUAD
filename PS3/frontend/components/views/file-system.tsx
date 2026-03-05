'use client'

import { useState, useEffect } from 'react'
import { Loader, AlertCircle, Folder, File, FileText, Image, Video, Music, Archive, Code, ChevronRight, ChevronDown, HardDrive, Calendar, Database } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { listEvidence, listPartitions, getFileSystemHierarchy, listDirectoryContents } from '@/lib/api-client'

interface FileSystemItem {
    path: string
    filename: string
    inode: number
    inode_full: string
    size_bytes: number
    time_accessed: string | null
    time_modified: string | null
    time_changed: string | null
    time_birth: string | null
    is_directory: boolean
    mft_flags: string
    file_type?: string
    extension?: string
}

interface Evidence {
    id: number
    filename: string
}

interface Partition {
    id: number
    partition_number: number
    filesystem_type: string
    start_offset: number
    size_bytes: number
}

interface TreeNode extends FileSystemItem {
    children?: TreeNode[]
    expanded?: boolean
    loaded?: boolean
}

export default function FileSystemView() {
    const [evidenceList, setEvidenceList] = useState<Evidence[]>([])
    const [selectedEvidenceId, setSelectedEvidenceId] = useState<number | null>(null)
    const [partitions, setPartitions] = useState<Partition[]>([])
    const [selectedPartitionId, setSelectedPartitionId] = useState<number | null>(null)
    const [loading, setLoading] = useState(true)
    const [filesLoading, setFilesLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const [fileTree, setFileTree] = useState<TreeNode[]>([])
    const [selectedFile, setSelectedFile] = useState<FileSystemItem | null>(null)
    const [viewMode, setViewMode] = useState<'tree' | 'flat'>('tree')

    // Fetch evidence list on mount
    useEffect(() => {
        fetchEvidence()
    }, [])

    // Fetch partitions when evidence changes
    useEffect(() => {
        if (selectedEvidenceId) {
            fetchPartitions(selectedEvidenceId)
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

    const fetchPartitions = async (evidenceId: number) => {
        setError(null)
        const result = await listPartitions(evidenceId)
        if (result.error) {
            setError(result.error)
            setPartitions([])
        } else {
            const data = result.data
            if (Array.isArray(data)) {
                setPartitions(data)
            } else if (data && typeof data === 'object' && 'partitions' in data && Array.isArray((data as any).partitions)) {
                setPartitions((data as any).partitions)
            } else {
                console.warn('listPartitions returned unexpected data structure:', data)
                setPartitions([])
            }
        }
    }

    const loadFileSystem = async () => {
        if (!selectedPartitionId) return

        setFilesLoading(true)
        setError(null)

        const result = await getFileSystemHierarchy(selectedPartitionId)
        if (result.error) {
            setError(result.error)
            setFileTree([])
        } else {
            const files = (result.data as any)?.files || []
            if (viewMode === 'tree') {
                const tree = buildFileTree(files)
                setFileTree(tree)
            } else {
                setFileTree(files)
            }
        }

        setFilesLoading(false)
    }

    const buildFileTree = (files: FileSystemItem[]): TreeNode[] => {
        const rootNodes: TreeNode[] = []
        const nodeMap = new Map<string, TreeNode>()

        // Sort files by path to ensure parents are processed before children
        const sortedFiles = [...files].sort((a, b) => a.path.localeCompare(b.path))

        for (const file of sortedFiles) {
            const node: TreeNode = {
                ...file,
                children: file.is_directory ? [] : undefined,
                expanded: false,
                loaded: false
            }

            nodeMap.set(file.path, node)

            // Find parent path
            const pathParts = file.path.split('/').filter(p => p)
            if (pathParts.length <= 1) {
                // Root level
                rootNodes.push(node)
            } else {
                // Find parent
                const parentPath = '/' + pathParts.slice(0, -1).join('/')
                const parent = nodeMap.get(parentPath)
                if (parent && parent.children) {
                    parent.children.push(node)
                } else {
                    // Parent not found, add to root (shouldn't happen with sorted files)
                    rootNodes.push(node)
                }
            }
        }

        return rootNodes
    }

    const toggleNode = (node: TreeNode) => {
        const updateTree = (nodes: TreeNode[]): TreeNode[] => {
            return nodes.map(n => {
                if (n.path === node.path) {
                    return { ...n, expanded: !n.expanded }
                }
                if (n.children) {
                    return { ...n, children: updateTree(n.children) }
                }
                return n
            })
        }

        setFileTree(updateTree(fileTree))
    }

    const getFileIcon = (item: FileSystemItem) => {
        if (item.is_directory) return Folder

        const ext = item.extension?.toLowerCase() || ''
        if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp'].includes(ext)) return Image
        if (['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv'].includes(ext)) return Video
        if (['mp3', 'wav', 'flac', 'aac', 'ogg', 'wma'].includes(ext)) return Music
        if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2'].includes(ext)) return Archive
        if (['js', 'ts', 'py', 'java', 'c', 'cpp', 'cs', 'php', 'rb', 'go', 'rs'].includes(ext)) return Code
        if (['txt', 'md', 'log', 'json', 'xml', 'csv'].includes(ext)) return FileText

        return File
    }

    const formatBytes = (bytes: number) => {
        if (bytes === 0) return '0 Bytes'
        const k = 1024
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
        const i = Math.floor(Math.log(bytes) / Math.log(k))
        return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
    }

    const formatDate = (dateString: string | null) => {
        if (!dateString) return 'N/A'
        try {
            return new Date(dateString).toLocaleString()
        } catch {
            return 'Invalid Date'
        }
    }

    const renderTreeNode = (node: TreeNode, level: number = 0): React.JSX.Element => {
        const Icon = getFileIcon(node)
        const hasChildren = node.is_directory && node.children && node.children.length > 0

        return (
            <div key={node.path}>
                <div
                    className={`flex items-center gap-2 px-4 py-2 hover:bg-[#1f2933] cursor-pointer transition-colors ${selectedFile?.path === node.path ? 'bg-[#1f2933]' : ''
                        }`}
                    style={{ paddingLeft: `${level * 20 + 16}px` }}
                    onClick={() => {
                        if (node.is_directory) {
                            toggleNode(node)
                        }
                        setSelectedFile(node)
                    }}
                >
                    {node.is_directory && (
                        <div className="flex-shrink-0">
                            {node.expanded ? (
                                <ChevronDown size={16} className="text-[#9ca3af]" />
                            ) : (
                                <ChevronRight size={16} className="text-[#9ca3af]" />
                            )}
                        </div>
                    )}
                    {!node.is_directory && <div className="w-4" />}
                    <Icon size={16} className={node.is_directory ? 'text-[#4fd1c5]' : 'text-[#9ca3af]'} />
                    <span className="text-sm text-[#e5e7eb] truncate flex-1">{node.filename}</span>
                    {!node.is_directory && (
                        <span className="text-xs text-[#6b7280] flex-shrink-0">{formatBytes(node.size_bytes)}</span>
                    )}
                </div>
                {node.is_directory && node.expanded && hasChildren && (
                    <div>
                        {node.children!.map(child => renderTreeNode(child, level + 1))}
                    </div>
                )}
            </div>
        )
    }

    const renderFlatList = (items: FileSystemItem[]) => {
        return items.map((item) => {
            const Icon = getFileIcon(item)
            return (
                <div
                    key={item.path}
                    className={`flex items-center gap-3 px-4 py-3 hover:bg-[#1f2933] cursor-pointer transition-colors border-b border-[#1f2933] ${selectedFile?.path === item.path ? 'bg-[#1f2933]' : ''
                        }`}
                    onClick={() => setSelectedFile(item)}
                >
                    <Icon size={18} className={item.is_directory ? 'text-[#4fd1c5]' : 'text-[#9ca3af]'} />
                    <span className="text-sm text-[#e5e7eb] flex-1 truncate">{item.path}</span>
                    <span className="text-xs text-[#6b7280]">{item.is_directory ? 'Directory' : formatBytes(item.size_bytes)}</span>
                </div>
            )
        })
    }

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
        <div className="p-8 space-y-6 h-full flex flex-col">
            <div>
                <h1 className="text-2xl font-semibold text-[#e5e7eb]">File System Browser</h1>
                <p className="text-[#9ca3af] text-sm mt-1">Browse complete NTFS file system structure</p>
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

            <div className="flex gap-4">
                <div className="flex-1 border border-[#1f2933] rounded bg-[#121821] p-4">
                    <label className="block text-sm font-medium text-[#e5e7eb] mb-2">
                        Select Evidence
                    </label>
                    <select
                        value={selectedEvidenceId || ''}
                        onChange={(e) => {
                            setSelectedEvidenceId(Number(e.target.value))
                            setSelectedPartitionId(null)
                            setFileTree([])
                        }}
                        className="w-full px-4 py-2 bg-[#0b0f14] border border-[#1f2933] rounded text-[#e5e7eb] focus:outline-none focus:border-[#4fd1c5]"
                        disabled={evidenceList.length === 0}
                    >
                        {evidenceList.length === 0 ? (
                            <option>No evidence available</option>
                        ) : (
                            evidenceList.map((ev) => (
                                <option key={ev.id} value={ev.id}>
                                    {ev.filename} (ID: {ev.id})
                                </option>
                            ))
                        )}
                    </select>
                </div>

                <div className="flex-1 border border-[#1f2933] rounded bg-[#121821] p-4">
                    <label className="block text-sm font-medium text-[#e5e7eb] mb-2">
                        Select Partition
                    </label>
                    <select
                        value={selectedPartitionId || ''}
                        onChange={(e) => {
                            setSelectedPartitionId(Number(e.target.value))
                            setFileTree([])
                        }}
                        className="w-full px-4 py-2 bg-[#0b0f14] border border-[#1f2933] rounded text-[#e5e7eb] focus:outline-none focus:border-[#4fd1c5]"
                        disabled={partitions.length === 0}
                    >
                        <option value="">Select a partition</option>
                        {partitions.map((part) => (
                            <option key={part.id} value={part.id}>
                                Partition {part.partition_number} - {part.filesystem_type} ({formatBytes(part.size_bytes)})
                            </option>
                        ))}
                    </select>
                </div>

                <div className="flex items-end gap-2">
                    <Button
                        onClick={loadFileSystem}
                        disabled={!selectedPartitionId || filesLoading}
                        className="gap-2 bg-[#4fd1c5] text-[#0b0f14] hover:bg-[#45b8ad]"
                    >
                        {filesLoading ? (
                            <>
                                <Loader size={16} className="animate-spin" />
                                Loading...
                            </>
                        ) : (
                            <>
                                <HardDrive size={16} />
                                Browse
                            </>
                        )}
                    </Button>

                    <div className="flex gap-1 border border-[#1f2933] rounded overflow-hidden">
                        <button
                            onClick={() => setViewMode('tree')}
                            className={`px-3 py-2 text-sm transition-colors ${viewMode === 'tree'
                                ? 'bg-[#4fd1c5] text-[#0b0f14]'
                                : 'bg-[#121821] text-[#9ca3af] hover:bg-[#1f2933]'
                                }`}
                        >
                            Tree
                        </button>
                        <button
                            onClick={() => setViewMode('flat')}
                            className={`px-3 py-2 text-sm transition-colors ${viewMode === 'flat'
                                ? 'bg-[#4fd1c5] text-[#0b0f14]'
                                : 'bg-[#121821] text-[#9ca3af] hover:bg-[#1f2933]'
                                }`}
                        >
                            Flat
                        </button>
                    </div>
                </div>
            </div>

            <div className="flex-1 flex gap-4 overflow-hidden">
                {/* File List Panel */}
                <div className="flex-1 border border-[#1f2933] rounded bg-[#121821] overflow-hidden flex flex-col">
                    <div className="border-b border-[#1f2933] bg-[#0b0f14] px-4 py-3">
                        <h3 className="text-sm font-medium text-[#e5e7eb]">Files & Directories</h3>
                        {fileTree.length > 0 && (
                            <p className="text-xs text-[#6b7280] mt-1">
                                {fileTree.length} items {viewMode === 'tree' ? '(root level)' : 'total'}
                            </p>
                        )}
                    </div>

                    <div className="flex-1 overflow-y-auto">
                        {filesLoading ? (
                            <div className="p-12 text-center">
                                <div className="flex justify-center mb-4">
                                    <Loader size={24} className="animate-spin text-[#4fd1c5]" />
                                </div>
                                <p className="text-[#9ca3af]">Loading file system...</p>
                            </div>
                        ) : fileTree.length > 0 ? (
                            viewMode === 'tree' ? (
                                <div className="py-2">
                                    {fileTree.map(node => renderTreeNode(node))}
                                </div>
                            ) : (
                                <div>
                                    {renderFlatList(fileTree as FileSystemItem[])}
                                </div>
                            )
                        ) : (
                            <div className="p-12 text-center">
                                <HardDrive className="mx-auto mb-4 text-[#6b7280]" size={48} />
                                <p className="text-[#9ca3af]">
                                    {selectedPartitionId
                                        ? 'Click "Browse" to load the file system'
                                        : 'Select a partition to browse'}
                                </p>
                            </div>
                        )}
                    </div>
                </div>

                {/* Details Panel */}
                {selectedFile && (
                    <div className="w-96 border border-[#1f2933] rounded bg-[#121821] overflow-hidden flex flex-col">
                        <div className="border-b border-[#1f2933] bg-[#0b0f14] px-4 py-3">
                            <h3 className="text-sm font-medium text-[#e5e7eb]">Details</h3>
                        </div>

                        <div className="flex-1 overflow-y-auto p-4 space-y-4">
                            <div>
                                <label className="text-xs text-[#6b7280] uppercase tracking-wide">Name</label>
                                <p className="text-sm text-[#e5e7eb] break-all mt-1">{selectedFile.filename}</p>
                            </div>

                            <div>
                                <label className="text-xs text-[#6b7280] uppercase tracking-wide">Path</label>
                                <p className="text-sm text-[#e5e7eb] break-all mt-1 font-mono">{selectedFile.path}</p>
                            </div>

                            <div>
                                <label className="text-xs text-[#6b7280] uppercase tracking-wide">Type</label>
                                <p className="text-sm text-[#e5e7eb] mt-1">
                                    {selectedFile.is_directory ? 'Directory' : (selectedFile.file_type || 'File')}
                                </p>
                            </div>

                            {!selectedFile.is_directory && (
                                <div>
                                    <label className="text-xs text-[#6b7280] uppercase tracking-wide">Size</label>
                                    <div className="flex items-center gap-2 mt-1">
                                        <Database size={14} className="text-[#6b7280]" />
                                        <p className="text-sm text-[#e5e7eb]">{formatBytes(selectedFile.size_bytes)}</p>
                                    </div>
                                </div>
                            )}

                            <div>
                                <label className="text-xs text-[#6b7280] uppercase tracking-wide">Inode</label>
                                <p className="text-sm text-[#e5e7eb] mt-1 font-mono">{selectedFile.inode_full}</p>
                            </div>

                            <div>
                                <label className="text-xs text-[#6b7280] uppercase tracking-wide">MFT Flags</label>
                                <p className="text-sm text-[#e5e7eb] mt-1 font-mono">{selectedFile.mft_flags}</p>
                            </div>

                            <div className="border-t border-[#1f2933] pt-4">
                                <label className="text-xs text-[#6b7280] uppercase tracking-wide flex items-center gap-2 mb-3">
                                    <Calendar size={14} />
                                    Timestamps
                                </label>

                                <div className="space-y-2">
                                    <div>
                                        <label className="text-xs text-[#6b7280]">Created (Birth)</label>
                                        <p className="text-xs text-[#e5e7eb] font-mono mt-0.5">{formatDate(selectedFile.time_birth)}</p>
                                    </div>
                                    <div>
                                        <label className="text-xs text-[#6b7280]">Modified</label>
                                        <p className="text-xs text-[#e5e7eb] font-mono mt-0.5">{formatDate(selectedFile.time_modified)}</p>
                                    </div>
                                    <div>
                                        <label className="text-xs text-[#6b7280]">Accessed</label>
                                        <p className="text-xs text-[#e5e7eb] font-mono mt-0.5">{formatDate(selectedFile.time_accessed)}</p>
                                    </div>
                                    <div>
                                        <label className="text-xs text-[#6b7280]">Changed</label>
                                        <p className="text-xs text-[#e5e7eb] font-mono mt-0.5">{formatDate(selectedFile.time_changed)}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    )
}
