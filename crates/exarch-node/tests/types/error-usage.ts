import type {
  ErrorCode,
  ExarchError,
  ExarchErrorPlain,
  ExarchErrorRolledBack,
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
  return err.code
}

export function isCoreCode(err: ExarchError, wanted: ErrorCode): boolean {
  return err.code === wanted
}

// @ts-expect-error a plain error never carries PROGRESS_CALLBACK_ERROR
export const plainCode: ExarchErrorPlain['code'] = 'PROGRESS_CALLBACK_ERROR'

// @ts-expect-error a rolled-back error never carries PROGRESS_CALLBACK_ERROR
export const rolledBackCode: ExarchErrorRolledBack['code'] = 'PROGRESS_CALLBACK_ERROR'

export const quotaCode: ExarchErrorPlain['code'] = 'QUOTA_EXCEEDED'
