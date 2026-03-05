'use client';

import { FileText, HardDrive, Trash2, RotateCcw, Zap, Microscope, FileJson, LogIn, Search, RefreshCcw, FolderTree, Info, ShieldAlert } from 'lucide-react'
import { resetInvestigation } from '@/lib/api-client'
import { useState } from 'react'

interface SidebarProps {
  activeView: string
  setActiveView: (view: any) => void
}

const menuItems = [
  { id: 'evidence', label: 'Evidence', icon: FileText },
  { id: 'disk-information', label: 'Disk Information', icon: Info },
  { id: 'partitions', label: 'Partitions', icon: HardDrive },
  { id: 'file-system', label: 'File System', icon: FolderTree },
  { id: 'deleted-files', label: 'Deleted Files', icon: Trash2 },
  { id: 'recovery', label: 'Recovered Files', icon: RotateCcw },
  { id: 'carving', label: 'Carving Action', icon: Zap },
  { id: 'carved-files', label: 'Carved Files', icon: FileJson },
  { id: 'search', label: 'Search', icon: Search },
  { id: 'forensics', label: 'Forensics', icon: Microscope },
  { id: 'wipe-detection', label: 'Wipe Detection', icon: ShieldAlert },
  { id: 'audit-log', label: 'Audit Log', icon: LogIn },
]

export default function Sidebar({ activeView, setActiveView }: SidebarProps) {
  const [resetting, setResetting] = useState(false)

  const handleReset = async () => {
    if (!window.confirm('WARNING: This will completely reset the investigation environment. All metadata, database records, and carving processes will be terminated/deleted. Are you absolutely sure?')) {
      return
    }

    setResetting(true)
    const result = await resetInvestigation()
    if (result.error) {
      alert(`Reset failed: ${result.error}`)
    } else {
      alert('Forensic environment has been successfully reset.')
      window.location.reload()
    }
    setResetting(false)
  }

  return (
    <aside className="w-56 border-r border-[#1f2933] bg-[#0b0f14] p-4 flex flex-col">
      <nav className="space-y-2 flex-1">
        {menuItems.map((item) => {
          const Icon = item.icon
          const isActive = activeView === item.id
          return (
            <button
              key={item.id}
              onClick={() => setActiveView(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded text-sm transition-colors ${isActive
                ? 'bg-[#4fd1c5] text-[#0b0f14] font-medium'
                : 'text-[#9ca3af] hover:text-[#e5e7eb] hover:bg-[#1f2933]'
                }`}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </button>
          )
        })}
      </nav>

      <div className="mt-auto pt-4 border-t border-[#1f2933]">
        <button
          onClick={handleReset}
          disabled={resetting}
          className="w-full flex items-center gap-3 px-4 py-3 rounded text-sm text-red-400 hover:text-red-300 hover:bg-red-400/10 transition-colors disabled:opacity-50"
        >
          <RefreshCcw size={18} className={resetting ? 'animate-spin' : ''} />
          <span>{resetting ? 'Resetting...' : 'Reset System'}</span>
        </button>
      </div>
    </aside>
  )
}
