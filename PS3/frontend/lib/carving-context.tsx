'use client'

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { getCarvingStatus, CarvingSessionStatus } from '@/lib/api-client'

interface CarvingContextType {
    activeSessionId: string | null
    sessionStatus: CarvingSessionStatus | null
    startMonitoring: (sessionId: string) => void
    stopMonitoring: () => void
}

const CarvingContext = createContext<CarvingContextType | undefined>(undefined)

export function CarvingProvider({ children }: { children: React.ReactNode }) {
    const [activeSessionId, setActiveSessionId] = useState<string | null>(null)
    const [sessionStatus, setSessionStatus] = useState<CarvingSessionStatus | null>(null)

    const stopMonitoring = useCallback(() => {
        setActiveSessionId(null)
        setSessionStatus(null)
        localStorage.removeItem('active_carving_session')
    }, [])

    const startMonitoring = useCallback((sessionId: string) => {
        setActiveSessionId(sessionId)
        localStorage.setItem('active_carving_session', sessionId)
    }, [])

    // Initialize from localStorage
    useEffect(() => {
        const saved = localStorage.getItem('active_carving_session')
        if (saved) {
            setActiveSessionId(saved)
        }
    }, [])

    const lastStatusRef = React.useRef<string | undefined>(undefined)

    // Global Polling Effect
    useEffect(() => {
        let intervalId: NodeJS.Timeout | undefined

        if (activeSessionId) {
            const poll = async () => {
                const result = await getCarvingStatus(activeSessionId)
                if (result.data) {
                    const newStatus = result.data.status

                    if (newStatus === 'completed' && lastStatusRef.current === 'in_progress') {
                        alert(`Carving Complete! ${result.data.files_carved_count} files discovered.`)
                    }

                    lastStatusRef.current = newStatus
                    setSessionStatus(result.data)
                } else if (result.error) {
                    console.error("Global carving poll error:", result.error)
                    if (result.status === 404) {
                        stopMonitoring()
                    }
                }
            }

            poll()
            intervalId = setInterval(poll, 3000)
        }

        return () => {
            if (intervalId) {
                clearInterval(intervalId)
                lastStatusRef.current = undefined
            }
        }
    }, [activeSessionId, stopMonitoring])

    return (
        <CarvingContext.Provider value={{ activeSessionId, sessionStatus, startMonitoring, stopMonitoring }}>
            {children}
        </CarvingContext.Provider>
    )
}

export function useCarving() {
    const context = useContext(CarvingContext)
    if (context === undefined) {
        throw new Error('useCarving must be used within a CarvingProvider')
    }
    return context
}
