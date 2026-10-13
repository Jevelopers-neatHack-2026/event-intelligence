import type {
  PrivateRetrievalDraft, PrivateRetrievalIncomplete, PrivateRetrievalResult,
} from '../../../src/research/private-retrieval.mjs';
import type {
  PrivateSourceAuthorityQuestion, PrivateSourceAuthorityReview,
} from '../../../src/research/source-authority-followup.mjs';

// The additive fields do not require old private fixtures to fabricate a review.
const historical: PrivateRetrievalIncomplete = {
  schema: 'ei-private-retrieval-draft/v1', runId: 'historical-private-result',
  status: 'incomplete', completeness: 'incomplete', draft: null, limitations: [],
};
declare const historicalDraft: Omit<PrivateRetrievalDraft, 'sourceAuthorityReview'>;
const compatibleDraft: PrivateRetrievalDraft = historicalDraft;

function inspect(result: PrivateRetrievalResult): void {
  const review: PrivateSourceAuthorityReview | undefined = result.sourceAuthorityReview;
  if (review) {
    review.schema satisfies 'ei-private-source-authority-review/v1';
    review.authority satisfies 'unknown';
    review.status satisfies 'review_required';
    review.execution satisfies 'not_dispatched';
    review.omittedQuestionCount satisfies number;
    const question: PrivateSourceAuthorityQuestion | undefined = review.questions[0];
    if (question) {
      question.kind satisfies 'occurrence' | 'entity' | 'source_input';
      question.candidateRef?.candidateId satisfies string | undefined;
      question.evidenceRefs[0]?.version satisfies number | undefined;
      question.evidenceRefs[0]?.contentHash satisfies string | undefined;
      // @ts-expect-error Private references remain immutable.
      question.evidenceRefs[0].contentHash = 'replacement';
      // @ts-expect-error Follow-up instructions are not caller-editable.
      question.prompt = 'replacement';
    }
    // @ts-expect-error There is no dispatched or verified variant.
    review.execution = 'dispatched';
    // @ts-expect-error The bounded question collection is readonly.
    review.questions.push({});
  }
  if ('draft' in result) {
    result.draft satisfies null;
    result.runId satisfies string;
  } else {
    result.sourceAuthority satisfies 'not_evaluated';
    result.sources[0]?.sourceAuthority satisfies 'not_evaluated' | undefined;
    result.facts satisfies PrivateRetrievalDraft['facts'];
  }
}

void historical;
void compatibleDraft;
void inspect;
