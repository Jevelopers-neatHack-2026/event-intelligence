import assert from 'node:assert/strict';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { composeInspectionReport, INSPECTION_MATRIX_SCHEMA } from '../../../src/extraction/inspection-report/index.mjs';
import { composeInspectionMediaReport } from '../../../src/extraction/inspection-report/media.mjs';
import { composeInspectionOcrReport } from '../../../src/extraction/inspection-report/ocr.mjs';
import { sourceSnapshot, projectedObservation, ROOT, hash, jsonBytes } from '../../inspection-report/media/support.mjs';
import { refreshCallerRecords, resultBytes } from '../../inspection-report/ocr/support.mjs';
import { readScannedPdf } from '../../../src/extraction/scanned-pdf/index.mjs';
import { readScannedPdfOcr } from '../../../src/extraction/scanned-pdf-ocr/index.mjs';
import { imagePdf } from '../scanned-pdf/fixtures.mjs';
import { readStaticPng } from '../../../src/extraction/png/index.mjs';
import { createStaticImageOcrReader } from '../../../src/extraction/static-image-ocr/index.mjs';
import { encodedPng, expectedText } from '../static-image-ocr/fixtures.mjs';
export { hash, jsonBytes, refreshCallerRecords, resultBytes, expectedText };
export const copy = structuredClone;
export function captured(name, value) {
  const dir = process.env.EI_OCR_CANDIDATE_CAPTURE;
  if (!dir) return;
  assert.ok(path.isAbsolute(dir) && path.relative(ROOT, dir).startsWith('..' + path.sep));
  mkdirSync(dir,{recursive:true});writeFileSync(path.join(dir,name), value,{flag:'wx'});
}
export function candidateInput(input) {const a=composeInspectionOcrReport(input);return {input,reportBytes:a.copyBytes(),expectedSha256:a.sha256};}
export function changeWords(input, words) {
  const o=input.observations[0];o.result.words=words;o.result.tokenUtf8Bytes=words.reduce((n,w)=>n+Buffer.byteLength(w.text),0);
  o.result.status=words.length?'text-observations':'no-text-observed';o.expectedResultSha256=hash(resultBytes(o.result));refreshCallerRecords(input);return input;
}
export function syntheticWords(template, lines) {
  return lines.flatMap((tokens,line)=>tokens.map((text,word)=>({...template,block:1,paragraph:1,line:line+1,word:word+1,text,
    box:{left:word%100*10,top:line%30*10,width:8,height:8}})));
}
let fixturePromise;
export function nativeFixture(){return fixturePromise ??= createFixture();}
async function createFixture(){
  assert.equal(process.versions.node,'22.23.3');assert.equal(process.platform,'linux');
  const before=sourceSnapshot(), packageBytes=readFileSync(path.join(ROOT,'package.json'));
  const schemaBytes=readFileSync(path.join(ROOT,'tests/contracts/research-contract-v1/candidate-upstream/schemas/EventIntelligencePackage/1.0.0.json'));
  const matrixBytes=jsonBytes({schemaVersion:INSPECTION_MATRIX_SCHEMA,version:'synthetic-selected-matrix/1',requiredFormats:['png','scanned-pdf']});
  const pins={sourceRevision:before.revision,package:{version:JSON.parse(packageBytes).version,sha256:hash(packageBytes)},
    evidenceSchema:{id:'https://schemas.jevelopers.org/EventIntelligencePackage/1.0.0',version:'1.0.0',versionPointer:'/properties/schema_version/const',sha256:hash(schemaBytes)},supportMatrix:{version:'synthetic-selected-matrix/1',sha256:hash(matrixBytes)}};
  const core={expectedPins:pins,artifacts:{package:packageBytes,evidenceSchema:schemaBytes,supportMatrix:matrixBytes},requiredMode:'mock',mappingState:'held',executions:[],observations:[]};
  const coreArtifact=composeInspectionReport(core), snapshot=jsonBytes(before);
  // No predecessor suite result is synthesized. Empty execution streams retain
  // incomplete/missing-summary reasons while actual observation bytes are bound.
  const execution=(id,component)=>({id,component,pins,mode:'mock',origin:'local-synthetic',stdoutBytes:Buffer.alloc(0),stderrBytes:Buffer.alloc(0),childStderrBytes:null,exitCode:null,signal:null});
  const media={prerequisite:{input:core,reportBytes:coreArtifact.copyBytes(),expectedSha256:coreArtifact.sha256},source:{selectedTree:before.tree,beforeBytes:snapshot,expectedBeforeSha256:hash(snapshot),afterBytes:snapshot,expectedAfterSha256:hash(snapshot)},runtimeReceipts:[(()=>{const bytes=readFileSync(path.join(ROOT,'tools/scanned-pdf/runtime/manifest.json'));return {component:'scanned-pdf',bytes,expectedSha256:hash(bytes)};})()],executions:[execution('static-png','static-png'),execution('scanned-pdf','scanned-pdf')],observations:[]};
  const reader=createStaticImageOcrReader({runtimeDirectory:process.env.EI_STATIC_IMAGE_OCR_RASTER_RUNTIME});
  const labelled=readFileSync(new URL('./fixtures/labelled.png',import.meta.url)), provenance=JSON.parse(readFileSync(new URL('./fixtures/provenance.json',import.meta.url)));
  assert.equal(hash(labelled),provenance.sha256);assert.equal(labelled.length,provenance.bytes);
  const observations=[];
  for(const [id,source] of [['labelled',labelled],['doors',encodedPng().bytes]]) {
    const decoded=await readStaticPng(source);assert.equal(decoded.kind,'decoded',JSON.stringify(decoded));
    media.observations.push(projectedObservation('static-png','png',id,decoded,source,pins));
    const result=await reader.read(source);assert.equal(result.kind,'observed',JSON.stringify(result));
    observations.push({id,component:'static-image-ocr',mediaObservationId:id,executionId:'static-image-ocr',result,expectedResultSha256:hash(resultBytes(result))});
    captured(id+'.native-result.json',resultBytes(result));
  }
  // A fresh two-page synthetic scanned document from the same labelled pixels.
  const labelledPixels=await readStaticPng(labelled);assert.equal(labelledPixels.kind,'decoded');
  const rgba=labelledPixels.copyRgbaBytes(),rgb=Buffer.alloc(labelledPixels.width*labelledPixels.height*3);
  for(let p=0;p<rgb.length/3;p++)rgb.set(rgba.subarray(p*4,p*4+3),p*3);
  const pdf=imagePdf(Array.from({length:2},()=>({width:labelledPixels.width,height:labelledPixels.height,rgb})));
  const pdfPixels=await readScannedPdf(pdf);assert.equal(pdfPixels.kind,'decoded',JSON.stringify(pdfPixels));
  media.observations.push(projectedObservation('scanned-pdf','scanned-pdf','labelled-pdf',pdfPixels,pdf,pins));
  const pdfResult=await readScannedPdfOcr(pdf);assert.equal(pdfResult.kind,'observed',JSON.stringify(pdfResult));
  observations.push({id:'labelled-pdf',component:'scanned-pdf-ocr',mediaObservationId:'labelled-pdf',executionId:'scanned-pdf-ocr',result:pdfResult,expectedResultSha256:hash(resultBytes(pdfResult))});
  captured('labelled-pdf.native-result.json',resultBytes(pdfResult));
  const controller=new AbortController();controller.abort();const cancelled=await reader.read(labelled,{signal:controller.signal});assert.equal(cancelled.code,'CANCELLED');
  const recovery=await reader.read(encodedPng({blank:true}).bytes);assert.equal(recovery.kind,'observed');assert.equal(recovery.words.length,0);
  captured('native-cancel-recovery.json',jsonBytes({cancelled,recovery}));
  assert.deepEqual(sourceSnapshot(),before,'native reader calls preserve selected source bytes/modes');
  const ma=composeInspectionMediaReport(media), runtime=readFileSync(path.join(ROOT,'tools/local-ocr/runtime/manifest.json'));
  const input={prerequisite:{input:media,reportBytes:ma.copyBytes(),expectedSha256:ma.sha256},runtimeReceipt:{bytes:runtime,expectedSha256:hash(runtime)},requiredFormats:['png','scanned-pdf'],executions:['static-image-ocr','scanned-pdf-ocr'].map(c=>({...execution(c,c),callerRecordBytes:null,expectedCallerRecordSha256:null})),observations};refreshCallerRecords(input);
  captured('native-fixture-origin.json',jsonBytes({source:before,mode:'current native calls on two synthetic PNGs and one two-page scanned PDF; no predecessor suite invoked or claimed',pins,provenance,missingExecutionSummaries:true,observations:observations.map(({id,expectedResultSha256})=>({id,expectedResultSha256}))}));
  return input;
}
