import { WholepactError } from '@wholepact/sdk';
/** Only the local service's explicit pre-commit conflicts are safe to release.
 * A transport error, malformed response or missing acknowledgement stays unknown. */
export function inspectionRejectedBeforeCommit(error:unknown): boolean {
  return error instanceof WholepactError && error.status === 409
    && typeof error.requestId === 'string' && error.requestId.length > 0
    && error.operationId === null
    && ['REVISION_CONFLICT', 'INVALID_TRANSITION'].includes(error.code);
}
