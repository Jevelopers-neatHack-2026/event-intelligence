// Appended only for the explicitly selected Research-a.2 diagnostic.
import type { EventIntelligencePackage_2_0_0 } from '@jevelopers/shared-contracts';
import { checkResearchIssuance } from '@jevelopers/shared-contracts/research-issuance';
import type { ResearchIssuanceContext } from '@jevelopers/shared-contracts/research-issuance';
declare const issuanceContext: ResearchIssuanceContext;
const issuanceCheck = checkResearchIssuance('EventIntelligencePackage', local, issuanceContext);
if (!issuanceCheck.ok) {
  const issuanceCode: string = issuanceCheck.errors[0].code;
  void issuanceCode;
}
// @ts-expect-error A local history snapshot is not an issued EIP2 record.
const notAnIssuedPackage: EventIntelligencePackage_2_0_0 = local;
void notAnIssuedPackage;
