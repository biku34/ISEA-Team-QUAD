'use client'

import { useState } from 'react'
import Header from '@/components/header'
import Sidebar from '@/components/sidebar'
import EvidenceView from '@/components/views/evidence'
import DiskInformationView from '@/components/views/disk-information'
import PartitionsView from '@/components/views/partitions'
import FileSystemView from '@/components/views/file-system'
import DeletedFilesView from '@/components/views/deleted-files'
import RecoveryView from '@/components/views/recovery'
import CarvingView from '@/components/views/carving'
import CarvedFilesView from '@/components/views/carved-files'
import SearchView from './../components/views/search'
import ForensicsView from '@/components/views/forensics'
import WipeDetectionView from '@/components/views/wipe-detection'
import AuditLogView from '@/components/views/audit-log'

import { CarvingProvider } from '@/lib/carving-context'

type ViewType = 'evidence' | 'disk-information' | 'partitions' | 'file-system' | 'deleted-files' | 'recovery' | 'carving' | 'carved-files' | 'search' | 'forensics' | 'wipe-detection' | 'audit-log'

export default function DashboardPage() {
  const [activeView, setActiveView] = useState<ViewType>('evidence')

  const renderView = () => {
    switch (activeView) {
      case 'evidence':
        return <EvidenceView />
      case 'disk-information':
        return <DiskInformationView />
      case 'partitions':
        return <PartitionsView />
      case 'file-system':
        return <FileSystemView />
      case 'deleted-files':
        return <DeletedFilesView />
      case 'recovery':
        return <RecoveryView />
      case 'carving':
        return <CarvingView />
      case 'carved-files':
        return <CarvedFilesView />
      case 'search':
        return <SearchView />
      case 'forensics':
        return <ForensicsView />
      case 'wipe-detection':
        return <WipeDetectionView />
      case 'audit-log':
        return <AuditLogView />
      default:
        return <EvidenceView />
    }
  }

  return (
    <CarvingProvider>
      <div className="flex h-screen bg-[#0b0f14]">
        <Sidebar activeView={activeView} setActiveView={setActiveView} />
        <div className="flex flex-1 flex-col">
          <Header />
          <main className="flex-1 overflow-y-auto">
            {renderView()}
          </main>
        </div>
      </div>
    </CarvingProvider>
  )
}
