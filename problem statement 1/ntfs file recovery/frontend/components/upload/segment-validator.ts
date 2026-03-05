/**
 * Segment Validation Utilities for E01 Files
 */

export interface ParsedSegment {
    file: File
    basename: string
    number: number
    extension: string
}

export interface ValidationResult {
    valid: boolean
    error?: string
    segments?: ParsedSegment[]
    totalSize?: number
    baseName?: string
}

/**
 * Parse E01-style segment filename
 * Supports: evidence.E01, evidence.e01, evidence.Ex01, etc.
 */
export function parseSegmentFilename(filename: string): ParsedSegment | null {
    // Match patterns like: evidence.E01, evidence.e01, evidence.Ex01
    const match = filename.match(/^(.+)\.(E|e|Ex|ex)(\d{2})$/i)

    if (!match) return null

    return {
        file: null as any, // Will be set by caller
        basename: match[1],
        number: parseInt(match[3], 10),
        extension: match[0].substring(match[0].lastIndexOf('.'))
    }
}

/**
 * Validate a set of segment files
 */
export function validateSegments(files: File[]): ValidationResult {
    if (files.length === 0) {
        return { valid: false, error: 'No files selected' }
    }

    // Parse all filenames
    const segments: ParsedSegment[] = []

    for (const file of files) {
        const parsed = parseSegmentFilename(file.name)
        if (!parsed) {
            return {
                valid: false,
                error: `Invalid filename format: ${file.name}. Expected format: name.E01, name.E02, etc.`
            }
        }
        parsed.file = file
        segments.push(parsed)
    }

    // Sort by segment number
    segments.sort((a, b) => a.number - b.number)

    // Check all have same base name
    const baseNames = new Set(segments.map(s => s.basename.toLowerCase()))
    if (baseNames.size > 1) {
        const names = Array.from(baseNames).join(', ')
        return {
            valid: false,
            error: `All segments must have the same base name. Found: ${names}`
        }
    }

    const baseName = segments[0].basename

    // Check starts with segment 1 (E01)
    if (segments[0].number !== 1) {
        return {
            valid: false,
            error: `First segment must be .E01 (or .e01). Found: ${segments[0].extension}`
        }
    }

    // Check for gaps in sequence
    const numbers = segments.map(s => s.number)
    const maxNumber = Math.max(...numbers)

    for (let i = 1; i <= maxNumber; i++) {
        if (!numbers.includes(i)) {
            const paddedNumber = String(i).padStart(2, '0')
            return {
                valid: false,
                error: `Missing segment E${paddedNumber}. Please select all segments in sequence.`
            }
        }
    }

    // Check for duplicates
    const numberSet = new Set(numbers)
    if (numberSet.size !== numbers.length) {
        return {
            valid: false,
            error: 'Duplicate segments detected. Each segment should be selected only once.'
        }
    }

    // Calculate total size
    const totalSize = segments.reduce((sum, seg) => sum + seg.file.size, 0)

    return {
        valid: true,
        segments,
        totalSize,
        baseName
    }
}

/**
 * Format bytes to human-readable string
 */
export function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
}

/**
 * Check if a file is potentially a segment file
 */
export function isSegmentFile(filename: string): boolean {
    return /\.(E|e|Ex|ex)\d{2}$/i.test(filename)
}
