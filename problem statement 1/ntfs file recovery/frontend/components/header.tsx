import { useCarving } from '@/lib/carving-context'
import { Zap, Loader, CheckCircle } from 'lucide-react'

export default function Header() {
  const { sessionStatus, stopMonitoring } = useCarving()

  return (
    <header className="border-b border-[#1f2933] bg-[#121821] px-8 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="text-lg font-semibold text-[#e5e7eb]">
            NFSU - NTFS Forensic Recovery System
          </div>

          {sessionStatus && (
            <div className={`relative overflow-hidden flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium border transition-all animate-in fade-in slide-in-from-top-2 ${sessionStatus.status === 'in_progress'
              ? 'bg-amber-500/10 border-amber-500/30 text-amber-500'
              : sessionStatus.status === 'completed'
                ? 'bg-green-500/10 border-green-500/30 text-green-500'
                : 'bg-red-500/10 border-red-500/30 text-red-500'
              }`}>
              {sessionStatus.status === 'in_progress' ? (
                <Loader size={12} className="animate-spin" />
              ) : sessionStatus.status === 'completed' ? (
                <CheckCircle size={12} />
              ) : (
                <Zap size={12} />
              )}
              <span className="uppercase tracking-wider">
                Carving: {sessionStatus.status.replace('_', ' ')}
                {sessionStatus.progress_percentage > 0 && sessionStatus.status === 'in_progress' && ` (${sessionStatus.progress_percentage}%)`}
              </span>

              {sessionStatus.status === 'in_progress' && (
                <div className="absolute bottom-0 left-0 h-[2px] bg-amber-500/50 transition-all duration-500" style={{ width: `${sessionStatus.progress_percentage}%` }}></div>
              )}

              {sessionStatus.status !== 'in_progress' && (
                <button
                  onClick={stopMonitoring}
                  className="ml-1 hover:text-[#e5e7eb] transition-colors"
                >
                  ×
                </button>
              )}
            </div>
          )}
        </div>

        <div className="text-sm text-[#9ca3af]">
          Examiner Console
        </div>
      </div>
    </header>
  )
}
