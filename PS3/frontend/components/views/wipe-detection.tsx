'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Button } from '@/components/ui/button'
import { Loader2, ShieldAlert, CheckCircle2, XCircle, AlertTriangle, AlertCircle, RefreshCw } from 'lucide-react'
import { listPartitions, extractArtifacts, getArtifacts, runWipeAnalysis, listEvidence } from '@/lib/api-client'

export default function WipeDetectionView() {
    const [partitions, setPartitions] = useState<any[]>([])
    const [selectedPartition, setSelectedPartition] = useState<string>('')

    // Evidence Selection
    const [evidenceList, setEvidenceList] = useState<any[]>([])
    const [activeEvidenceId, setActiveEvidenceId] = useState<number | null>(null)

    // Phase 1 status
    const [artifacts, setArtifacts] = useState<any[]>([])
    const [isExtracting, setIsExtracting] = useState(false)
    const [extractError, setExtractError] = useState<string | null>(null)

    // Phase 2-4 status
    const [minSuspicion, setMinSuspicion] = useState<number>(50)
    const [isAnalyzing, setIsAnalyzing] = useState(false)
    const [analysisError, setAnalysisError] = useState<string | null>(null)
    const [results, setResults] = useState<any | null>(null)

    useEffect(() => {
        const init = async () => {
            const evRes = await listEvidence()
            if (evRes.data) {
                const evidenceListData = (evRes.data as any)?.evidence || []
                setEvidenceList(evidenceListData)
                if (evidenceListData.length > 0) {
                    const firstEvId = evidenceListData[0].id
                    setActiveEvidenceId(firstEvId)
                }
            }
        }
        init()
    }, [])

    useEffect(() => {
        if (activeEvidenceId !== null) {
            fetchPartitions(activeEvidenceId)
            checkArtifactStatus(activeEvidenceId)
        }
    }, [activeEvidenceId])

    const fetchPartitions = async (evId: number) => {
        const res = await listPartitions(evId)
        if (res.data) {
            const data = res.data as any
            let partitionsArray: any[] = []

            if (Array.isArray(data)) {
                partitionsArray = data
            } else if (data && typeof data === 'object' && 'partitions' in data && Array.isArray(data.partitions)) {
                partitionsArray = data.partitions
            }

            setPartitions(partitionsArray)
            if (partitionsArray.length > 0 && !selectedPartition) {
                setSelectedPartition(partitionsArray[0].id.toString())
            }
        } else {
            setPartitions([])
        }
    }

    const checkArtifactStatus = async (evId: number) => {
        const res = await getArtifacts(evId)
        if (res.data) {
            const data = res.data as any
            // Safely handle different response structures (list vs object wrapping list)
            if (Array.isArray(data)) {
                setArtifacts(data)
            } else if (data.artifacts && Array.isArray(data.artifacts)) {
                setArtifacts(data.artifacts)
            } else {
                setArtifacts([])
            }
        } else {
            setArtifacts([])
        }
    }

    const handleExtract = async () => {
        if (!selectedPartition || activeEvidenceId === null) return
        setIsExtracting(true)
        setExtractError(null)

        const res = await extractArtifacts(activeEvidenceId, parseInt(selectedPartition))
        if (res.error) {
            setExtractError(res.error)
        } else {
            await checkArtifactStatus(activeEvidenceId)
        }
        setIsExtracting(false)
    }

    const handleAnalyze = async () => {
        if (!selectedPartition || activeEvidenceId === null) return
        setIsAnalyzing(true)
        setAnalysisError(null)
        setResults(null)

        const res = await runWipeAnalysis(activeEvidenceId, parseInt(selectedPartition), minSuspicion)
        if (res.error) {
            setAnalysisError(res.error)
        } else {
            setResults(res.data)
        }
        setIsAnalyzing(false)
    }

    const coreArtifactNames = ['$MFT', '$Bitmap', '$Boot', '$AttrDef']
    const optionalArtifactNames = ['$UsnJrnl:$J', '$LogFile']
    const expectedArtifactNames = [...coreArtifactNames, ...optionalArtifactNames]

    // Safe array fallback before filtering
    const safeArtifacts = Array.isArray(artifacts) ? artifacts : []
    const extractedArtifactNames = safeArtifacts
        .filter(a => a?.extraction_status === 'success')
        .map(a => a?.artifact_name)

    const allRequiredExtracted = coreArtifactNames.every(name => extractedArtifactNames.includes(name))

    return (
        <div className="p-6 max-w-7xl mx-auto space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight text-[#f3f4f6] flex items-center gap-3">
                        <ShieldAlert className="h-8 w-8 text-[#4fd1c5]" />
                        Wipe Detection Engine
                    </h1>
                    <p className="text-[#9ca3af] mt-2">
                        Multi-phase forensic analysis to detect anti-forensic wiping tools and targeted data destruction.
                    </p>
                </div>

                <div className="flex items-center gap-4">
                    <Select value={activeEvidenceId?.toString() || ''} onValueChange={(val) => {
                        setActiveEvidenceId(Number(val))
                        setSelectedPartition('') // Reset partition when evidence changes
                    }}>
                        <SelectTrigger className="w-[280px] bg-[#0b0f14] border-[#1f2933] text-[#e5e7eb]">
                            <SelectValue placeholder="Select evidence..." />
                        </SelectTrigger>
                        <SelectContent className="bg-[#0b0f14] border-[#1f2933]">
                            {evidenceList.map((ev) => (
                                <SelectItem key={ev.id} value={ev.id.toString()} className="text-[#e5e7eb] focus:bg-[#1f2933]">
                                    {ev.filename} (ID: {ev.id})
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>

                    <Select value={selectedPartition} onValueChange={setSelectedPartition}>
                        <SelectTrigger className="w-[280px] bg-[#0b0f14] border-[#1f2933] text-[#e5e7eb]">
                            <SelectValue placeholder="Select partition to analyze..." />
                        </SelectTrigger>
                        <SelectContent className="bg-[#0b0f14] border-[#1f2933]">
                            {(Array.isArray(partitions) ? partitions : []).map((p) => (
                                <SelectItem key={p.id} value={p.id.toString()} className="text-[#e5e7eb] focus:bg-[#1f2933]">
                                    Partition {p.id} — {p.fs_type || 'Unknown FS'} ({p.size_bytes ? (p.size_bytes / (1024 * 1024 * 1024)).toFixed(2) : '?'} GB)
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Phase 1: Artifact Extraction */}
                <Card className="bg-[#111827] border-[#1f2933]">
                    <CardHeader>
                        <CardTitle className="text-[#f3f4f6] flex items-center gap-2">
                            <span className="bg-[#1f2933] text-[#9ca3af] text-xs px-2 py-1 rounded font-mono">Phase 1</span>
                            System Artifact Extraction
                        </CardTitle>
                        <CardDescription className="text-[#9ca3af]">
                            Core NTFS system files required for cross-reference analysis.
                        </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="grid grid-cols-2 gap-3 mb-6">
                            {expectedArtifactNames.map(name => {
                                const isExtracted = extractedArtifactNames.includes(name)
                                const isOptional = optionalArtifactNames.includes(name)
                                return (
                                    <div key={name} className="flex items-center gap-2 text-sm bg-[#0b0f14] p-3 rounded-md border border-[#1f2933]">
                                        {isExtracted ? (
                                            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                                        ) : isOptional ? (
                                            <AlertCircle className="h-4 w-4 text-yellow-500" />
                                        ) : (
                                            <XCircle className="h-4 w-4 text-red-500" />
                                        )}
                                        <span className={isExtracted ? 'text-[#e5e7eb]' : 'text-[#6b7280]'}>
                                            {name}
                                            {isOptional && <span className="ml-1 text-[10px] text-gray-500">(Optional)</span>}
                                        </span>
                                    </div>
                                )
                            })}
                        </div>

                        {extractError && (
                            <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-md text-red-400 text-sm mb-4">
                                {extractError}
                            </div>
                        )}

                        <Button
                            onClick={handleExtract}
                            disabled={isExtracting || !selectedPartition}
                            className="w-full bg-[#1f2933] hover:bg-[#374151] text-[#f3f4f6]"
                        >
                            {isExtracting ? (
                                <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Extracting Artifacts...</>
                            ) : (
                                <><RefreshCw className="mr-2 h-4 w-4" /> {allRequiredExtracted ? 'Re-extract Artifacts' : 'Extract Missing Artifacts'}</>
                            )}
                        </Button>
                    </CardContent>
                </Card>

                {/* Phase 2-4: Analysis Engine */}
                <Card className="bg-[#111827] border-[#1f2933]">
                    <CardHeader>
                        <CardTitle className="text-[#f3f4f6] flex items-center gap-2">
                            <span className="bg-[#1f2933] text-[#9ca3af] text-xs px-2 py-1 rounded font-mono">Phase 2-4</span>
                            Wipe Detection Engine
                        </CardTitle>
                        <CardDescription className="text-[#9ca3af]">
                            Cross-reference MFT history, USN journal, and raw cluster entropy.
                        </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-6">

                        <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                                <label className="text-[#e5e7eb]">Minimum Suspicion Threshold</label>
                                <span className="text-[#4fd1c5] font-mono">{minSuspicion}</span>
                            </div>
                            <input
                                type="range"
                                min="0" max="100"
                                value={minSuspicion}
                                onChange={(e) => setMinSuspicion(parseInt(e.target.value))}
                                className="w-full accent-[#4fd1c5]"
                            />
                            <p className="text-xs text-[#6b7280]">
                                Scores ≥ 80 are High confidence. 0 is natural unallocated space.
                            </p>
                        </div>

                        {analysisError && (
                            <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-md text-red-400 text-sm mb-4">
                                {analysisError}
                            </div>
                        )}

                        <Button
                            onClick={handleAnalyze}
                            disabled={isAnalyzing || !allRequiredExtracted || !selectedPartition}
                            className={`w-full ${allRequiredExtracted ? 'bg-[#4fd1c5] hover:bg-[#38bfae] text-[#0b0f14]' : 'bg-[#1f2933] text-[#6b7280] cursor-not-allowed'}`}
                        >
                            {isAnalyzing ? (
                                <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Cross-Referencing Evidence...</>
                            ) : (
                                <><ShieldAlert className="mr-2 h-4 w-4" /> Run Wipe Analysis</>
                            )}
                        </Button>

                        {!allRequiredExtracted && (
                            <p className="text-xs text-amber-500/80 text-center flex items-center justify-center gap-1">
                                <AlertCircle className="h-3 w-3" /> Phase 1 artifacts must be extracted first.
                            </p>
                        )}

                    </CardContent>
                </Card>
            </div>

            {/* Results Section */}
            {results && (
                <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                        <Card className="bg-[#0b0f14] border-[#1f2933]">
                            <CardContent className="p-4 flex flex-col items-center justify-center min-h-[100px]">
                                <span className="text-4xl font-bold text-[#4fd1c5] opacity-80">{results.data_maps.total_clusters_in_bitmap?.toLocaleString() || 'N/A'}</span>
                                <span className="text-[11px] text-[#9ca3af] uppercase tracking-wider mt-1 text-center">Total Volume Clusters</span>
                            </CardContent>
                        </Card>
                        <Card className="bg-[#0b0f14] border-[#1f2933]">
                            <CardContent className="p-4 flex flex-col items-center justify-center min-h-[100px]">
                                <span className="text-4xl font-bold text-[#f3f4f6]">{results.summary.suspicious_total}</span>
                                <span className="text-sm text-[#9ca3af] uppercase tracking-wider mt-1">Suspicious</span>
                            </CardContent>
                        </Card>
                        <Card className="bg-[#0b0f14] border-red-500/30">
                            <CardContent className="p-4 flex flex-col items-center justify-center min-h-[100px]">
                                <span className="text-4xl font-bold text-red-500">{results.summary.high_confidence}</span>
                                <span className="text-sm text-red-400/80 uppercase tracking-wider mt-1">High Conf</span>
                            </CardContent>
                        </Card>
                        <Card className="bg-[#0b0f14] border-amber-500/30">
                            <CardContent className="p-4 flex flex-col items-center justify-center min-h-[100px]">
                                <span className="text-4xl font-bold text-amber-500">{results.summary.medium_confidence}</span>
                                <span className="text-sm text-amber-400/80 uppercase tracking-wider mt-1">Med Conf</span>
                            </CardContent>
                        </Card>
                        <Card className="bg-[#0b0f14] border-[#1f2933]">
                            <CardContent className="p-4 flex flex-col justify-center text-xs text-[#9ca3af] space-y-2 min-h-[100px]">
                                <div className="flex justify-between"><span>MFT Extracted:</span> <span className="text-[#e5e7eb] font-mono">{results.data_maps.mft_entries_mapped.toLocaleString()}</span></div>
                                <div className="flex justify-between"><span>USN Records:</span> <span className="text-[#e5e7eb] font-mono">{results.data_maps.usn_file_references.toLocaleString()}</span></div>
                                <div className="flex justify-between"><span>LogFile Evts:</span> <span className="text-[#e5e7eb] font-mono">{results.data_maps.logfile_events.toLocaleString()}</span></div>
                            </CardContent>
                        </Card>
                    </div>

                    <Card className="bg-[#111827] border-[#1f2933]">
                        <CardHeader>
                            <CardTitle className="text-[#f3f4f6]">Forensic Findings</CardTitle>
                        </CardHeader>
                        <CardContent>
                            {results.suspicious_clusters.length === 0 ? (
                                <div className="text-center py-12 text-[#6b7280]">
                                    <CheckCircle2 className="h-12 w-12 mx-auto mb-3 opacity-20" />
                                    <p>No suspicious wiped clusters found above the threshold of {minSuspicion}.</p>
                                </div>
                            ) : (
                                <div className="overflow-x-auto">
                                    <table className="w-full text-sm text-left">
                                        <thead className="text-xs uppercase bg-[#0b0f14] text-[#9ca3af]">
                                            <tr>
                                                <th className="px-4 py-3 rounded-tl-md">Cluster LCN</th>
                                                <th className="px-4 py-3">Confidence</th>
                                                <th className="px-4 py-3">Score</th>
                                                <th className="px-4 py-3">Pattern</th>
                                                <th className="px-4 py-3">Previous Owner</th>
                                                <th className="px-4 py-3">Audit Trails</th>
                                                <th className="px-4 py-3 rounded-tr-md">Rules Triggered</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {results.suspicious_clusters.map((c: any) => (
                                                <tr key={c.cluster} className="border-t border-[#1f2933] hover:bg-[#1f2933]/50">
                                                    <td className="px-4 py-3 font-mono text-[#e5e7eb]">{c.cluster.toLocaleString()}</td>
                                                    <td className="px-4 py-3">
                                                        <span className={`px-2 py-1 text-xs font-medium rounded ${c.confidence_level === 'HIGH' ? 'bg-red-500/20 text-red-400' :
                                                            c.confidence_level === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400' :
                                                                'bg-[#374151] text-[#9ca3af]'
                                                            }`}>
                                                            {c.confidence_level}
                                                        </span>
                                                    </td>
                                                    <td className="px-4 py-3 text-[#4fd1c5] font-mono">{c.suspicion_score}</td>
                                                    <td className="px-4 py-3 text-[#e5e7eb]">
                                                        {c.wipe_pattern}
                                                        <div className="text-[10px] text-[#6b7280] mt-0.5">Ent: {c.entropy.toFixed(2)}</div>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <span className="text-[#e5e7eb] truncate max-w-[150px] block" title={c.previous_owner}>
                                                            {c.previous_owner || <span className="text-[#4b5563] italic">Unknown</span>}
                                                        </span>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <div className="flex flex-col gap-1">
                                                            {c.usn_events?.length > 0 && (
                                                                <span className="text-[10px] bg-blue-500/10 text-blue-400 px-1.5 py-0.5 rounded w-fit">USN</span>
                                                            )}
                                                            {c.logfile_events?.length > 0 && (
                                                                <span className="text-[10px] bg-purple-500/10 text-purple-400 px-1.5 py-0.5 rounded w-fit">LOG</span>
                                                            )}
                                                            {(!c.usn_events?.length && !c.logfile_events?.length) && (
                                                                <span className="text-[#4b5563]">-</span>
                                                            )}
                                                        </div>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <ul className="list-none text-xs text-[#9ca3af] space-y-1">
                                                            {c.rules_triggered.map((r: string, i: number) => (
                                                                <li key={i}>{r.split('(')[0]}</li>
                                                            ))}
                                                        </ul>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </div>
            )}
        </div>
    )
}
