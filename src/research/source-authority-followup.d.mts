import type { EntityObservation } from '../discovery/entities/identity.mjs';
import type { OccurrenceObservation } from '../discovery/occurrences/identity.mjs';

export interface PrivateSourceAuthorityEvidenceReference {
  readonly evidenceId: string;
  readonly version: number;
  readonly contentHash: string;
}

export interface PrivateSourceAuthorityQuestion {
  readonly questionId: string;
  readonly kind: 'occurrence' | 'entity' | 'source_input';
  /** Fixed trusted wording. Source text, names, URLs and fact values are never interpolated. */
  readonly prompt: string;
  readonly candidateRef: Readonly<{
    kind: 'occurrence' | 'entity';
    candidateId: string;
  }> | null;
  readonly evidenceRefs: readonly PrivateSourceAuthorityEvidenceReference[];
}

export interface PrivateSourceAuthorityReview {
  readonly schema: 'ei-private-source-authority-review/v1';
  readonly status: 'review_required';
  readonly authority: 'unknown';
  readonly execution: 'not_dispatched';
  readonly questions: readonly PrivateSourceAuthorityQuestion[];
  readonly omittedQuestionCount: number;
  readonly reasonCodes: readonly string[];
}

/** Private internal input; this helper does not authenticate an arbitrary caller's references. */
export declare function composeSourceAuthorityReview(input: Readonly<{
  occurrenceCandidates: readonly OccurrenceObservation[];
  entityCandidates: readonly EntityObservation[];
  sources: readonly (PrivateSourceAuthorityEvidenceReference & Readonly<{ sourceAuthority: 'not_evaluated' }>)[];
  limitations: readonly string[];
  stopReasons: readonly string[];
}>): PrivateSourceAuthorityReview | undefined;

/** The caller must establish settled work and current release authorization first. */
export declare function composeNoSourceAuthorityReview(
  limitations: readonly string[],
  stopReasons: readonly string[],
): PrivateSourceAuthorityReview | undefined;
