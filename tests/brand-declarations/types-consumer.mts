import { createBrandDeclarationReader, type BrandDeclarations, type BrandDeclarationReader,
  DECLARATION_PROFILE, BrandDeclarationError } from '../../src/brand-research/declarations/index.mjs';
import type { EvidenceStoreOptions, EvidenceHandle } from '../../src/evidence/store.mjs';
interface Request { principal: { tenantId: string } }
declare const options: EvidenceStoreOptions<Request> & { authorizePrivateAccess: () => boolean };
declare const evidence: EvidenceHandle;
declare const request: Request;
const reader: BrandDeclarationReader<Request> = createBrandDeclarationReader({ evidenceStoreOptions: options });
const result: Promise<BrandDeclarations> = reader.read({ evidence, request });
void result.then((value) => {
  const profile: typeof DECLARATION_PROFILE = value.profile;
  const permission: 'unknown' = value.permission;
  const approved: false = value.canonicalAdoption;
  void [profile, permission, approved];
  // @ts-expect-error observed declarations cannot be licensed font authority
  const licensed: true = value.fontAvailability;
  // @ts-expect-error private immutable output cannot gain permissions
  value.permission = 'approved';
  void licensed;
});
// @ts-expect-error opaque evidence cannot be forged by string ID
void reader.read({ evidence: 'evidence-id', request });
// @ts-expect-error authenticated request type remains required
void reader.read({ evidence, request: { tenant: 'caller-asserted' } });
// @ts-expect-error private payload callback belongs to the adapter
createBrandDeclarationReader({ evidenceStoreOptions: { ...options, consumePrivatePayload: () => 'arbitrary' } });
const error = new BrandDeclarationError('EVIDENCE_DENIED');
void error.code;
