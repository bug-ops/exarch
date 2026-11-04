import { listArchiveBytes } from '../../index'
import type {
  AbortSignalLike,
  ErrorCode,
  ExarchError,
  ExarchErrorPlain,
  ExarchErrorRolledBack,
  InvalidArchiveSubCode,
  SecurityViolationSubCode,
} from '../../index'

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
