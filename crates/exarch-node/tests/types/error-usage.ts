import {
  createArchive,
  extractArchiveToMemoryWithProgress,
  extractArchiveWithProgress,
  listArchiveBytes,
  listArchiveBytesWithProgress,
  verifyArchiveBytesWithProgress,
} from '../../index'
import type {
  CreateOptions,
  ExarchErrorReadCallback,
} from '../../index'
import type {
  AbortSignalLike,
  ErrorCode,
  ExarchCoreError,
  ExarchError,
  ExarchErrorPlain,
  ExarchErrorRolledBack,
  InvalidArchiveSubCode,
  IoKind,
  MemoryEntry,
  QuotaSubCode,
  SecurityViolationSubCode,
  StoredMemoryEntry,
  ZipBombSubCode,
} from '../../index'
import type { ArchiveEntry, MemoryExtraction, VerificationIssue } from '../../index'

export function describeListed(entry: ArchiveEntry): string {
  switch (entry.entryType) {
    case 'File':
      return `${entry.size}`
    case 'Directory':
      return entry.path
    case 'Symlink':
    case 'Hardlink':
      return entry.target.state === 'recorded' ? entry.target.path : entry.target.state
  }
}

export function sizeIsFileOnly(entry: ArchiveEntry): void {
  if (entry.entryType === 'Directory') {
    // @ts-expect-error a directory has no size
    void entry.size
  }
}

export function issueCodes(issue: VerificationIssue): string | undefined {
  if (issue.code === 'SECURITY_VIOLATION') {
    const sub: SecurityViolationSubCode = issue.subCode
    return sub
  }
  if (issue.code === undefined) {
    return issue.subCode
  }
  return issue.code
}

export function pairedSubCode(err: ExarchCoreError): string | undefined {
  if (err.code === 'INVALID_ARCHIVE') {
    const sub: InvalidArchiveSubCode | undefined = err.subCode
    return sub
  }
  if (err.code === 'QUOTA_EXCEEDED') {
    const sub: QuotaSubCode = err.subCode
    return sub
  }
  if (err.code === 'ZIP_BOMB') {
    const sub: ZipBombSubCode = err.subCode
    return sub
  }
  if (err.code === 'SECURITY_VIOLATION') {
    const sub: SecurityViolationSubCode = err.subCode
    return sub
  }
  return undefined
}

export function entryNamePath(err: ExarchCoreError): string | undefined {
  if (err.code === 'INVALID_ARCHIVE') {
    return err.nonUtf8EntryPath
  }
  if (err.code === 'PATH_TRAVERSAL') {
    // @ts-expect-error only an INVALID_ARCHIVE carries an entry path
    const path: string = err.nonUtf8EntryPath
    return path
  }
  return undefined
}

export function ioKindOf(err: ExarchCoreError): IoKind | undefined {
  if (err.code === 'IO_ERROR') {
    const kind: IoKind = err.ioKind
    return kind
  }
  return undefined
}

export function impossiblePairings(err: ExarchCoreError): void {
  if (err.code === 'PATH_TRAVERSAL') {
    // @ts-expect-error a path traversal carries no sub-code
    const sub: 'INTEGRITY' = err.subCode
    void sub
  }
  if (err.code === 'SECURITY_VIOLATION') {
    // @ts-expect-error INTEGRITY is an INVALID_ARCHIVE sub-code
    const sub: 'INTEGRITY' = err.subCode
    void sub
  }
}

export function describeEntry(entry: MemoryEntry): string {
  switch (entry.kind) {
    case 'file':
      return `${entry.data.length}`
    case 'directory':
      return entry.path
    case 'symlink':
    case 'hardlink':
      return entry.target
  }
}

export function storedEntries(result: MemoryExtraction): StoredMemoryEntry[] {
  return result.entries
}

// @ts-expect-error a stored entry is never a hardlink
export const storedHardlink: StoredMemoryEntry['kind'] = 'hardlink'

export function describeFailure(caught: unknown): string {
  const err = caught as ExarchError

  if (err.writes === 'kept') {
    return `${err.filesExtracted} files, ${err.bytesWritten} bytes, ${err.warnings.length} warnings`
  }
  if (err.writes === 'rolled_back') {
    return 'rolled back'
  }
  if (err.filesAdded !== undefined) {
    return `${err.filesAdded} files added`
  }
  if (err.relaxableBy !== undefined) {
    return err.relaxableBy
  }
  if (err.subCode !== undefined) {
    return err.subCode
  }
  return err.code
}

// @ts-expect-error subCode only has the core spellings
export const badSubCode: InvalidArchiveSubCode = 'TAR_OTHER'

export const trailerSubCode: SecurityViolationSubCode = 'TAR_TRAILER'
export const pathNameSubCode: SecurityViolationSubCode = 'PATH_NAME'

// @ts-expect-error a security sub-code is one of the core families
export const badSecuritySubCode: SecurityViolationSubCode = 'TAR_OTHER'

export function isCoreCode(err: ExarchError, wanted: ErrorCode): boolean {
  return err.code === wanted
}

// @ts-expect-error a plain error never carries PROGRESS_CALLBACK_ERROR
export const plainCode: ExarchErrorPlain['code'] = 'PROGRESS_CALLBACK_ERROR'

// @ts-expect-error a rolled-back error never carries PROGRESS_CALLBACK_ERROR
export const rolledBackCode: ExarchErrorRolledBack['code'] = 'PROGRESS_CALLBACK_ERROR'

export function readCallbackFailure(err: ExarchError): number | undefined {
  if (err.code === 'PROGRESS_CALLBACK_ERROR' && err.writes === undefined) {
    return err.filesAdded
  }
  return undefined
}

export const readCallbackShape: ExarchErrorReadCallback = {
  name: 'Error',
  message: 'threw',
  code: 'PROGRESS_CALLBACK_ERROR',
}

// An unknown total is null at runtime, so the progress argument must not allow
// number methods on it, in every progress variant.
export function progressTotals(data: Uint8Array): Promise<unknown>[] {
  return [
    extractArchiveWithProgress('a', 'b', null, null, (_err, [, total]) => {
      // @ts-expect-error total is number | null
      total.toFixed(0)
    }),
    extractArchiveToMemoryWithProgress(data, null, null, null, null, null, (_err, [, total]) => {
      // @ts-expect-error total is number | null
      total.toFixed(0)
    }),
    listArchiveBytesWithProgress(data, null, null, (_err, [, total]) => {
      // @ts-expect-error total is number | null
      total.toFixed(0)
    }),
    verifyArchiveBytesWithProgress(data, null, null, null, (_err, [, total]) => {
      // @ts-expect-error total is number | null
      total.toFixed(0)
    }),
  ]
}

export const createOptions: CreateOptions = { format: 'TarGz', overwrite: false }

export function createWithOptions(): Promise<unknown> {
  return createArchive('out.tar.gz', ['src'], null, createOptions)
}

export const quotaCode: ExarchErrorPlain['code'] = 'QUOTA_EXCEEDED'

export function abortableCalls(data: Uint8Array): Promise<unknown>[] {
  const controller = new AbortController()
  const structural: AbortSignalLike = {
    aborted: false,
    addEventListener: () => {},
    removeEventListener: () => {},
  }
  return [
    listArchiveBytes(data, null, null, controller.signal),
    listArchiveBytes(data, null, null, structural),
    listArchiveBytes(data, null, null, undefined),
  ]
}
