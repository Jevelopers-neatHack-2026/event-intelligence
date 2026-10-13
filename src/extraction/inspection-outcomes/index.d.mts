import type { StaticPngReadResult, StaticPngReaderOptions } from "../png/index.mjs";
import type { StaticJpegWebpReadResult, StaticJpegWebpOptions } from "../jpeg-webp/index.mjs";
import type { ScannedPdfDecoded, ScannedPdfRejected, ScannedPdfOptions } from "../scanned-pdf/index.mjs";
import type { PdfTextReadResult, PdfTextReaderOptions } from "../pdf/index.mjs";

export type InspectionReader = "png" | "jpeg-webp" | "scanned-pdf" | "text-pdf";
interface Base<R extends InspectionReader> {
  readonly schemaVersion: "ei-private-inspection-outcome/1";
  readonly reader: R;
}
export interface InspectionBoundaryFailure<R extends InspectionReader> extends Base<R> {
  readonly kind: "boundary-failure";
  readonly category: "INVALID_INPUT" | "INVALID_OPTIONS" | "INVALID_CONFIGURATION" | "INTERNAL_FAILURE";
  readonly reason: "INVALID_INPUT" | "INVALID_OPTIONS" | "INVALID_CONFIGURATION" | "UNEXPECTED_READER_FAILURE";
}
export type InspectionReaderResult<R extends InspectionReader, T> = T extends { readonly kind: "rejected"; readonly code: infer C extends string }
  ? Base<R> & { readonly kind: "reader-result"; readonly category: C | "RESOURCE_LIMIT"; readonly reason: C; readonly result: T }
  : Base<R> & { readonly kind: "reader-result"; readonly category: "OBSERVATION"; readonly reason: null; readonly result: T };
export type InspectionOutcome<R extends InspectionReader, T> = InspectionReaderResult<R, T> | InspectionBoundaryFailure<R>;
export type PngOutcome = InspectionOutcome<"png", StaticPngReadResult>;
export type JpegWebpOutcome = InspectionOutcome<"jpeg-webp", StaticJpegWebpReadResult>;
export type ScannedPdfOutcome = InspectionOutcome<"scanned-pdf", ScannedPdfDecoded | ScannedPdfRejected>;
export type TextPdfOutcome = InspectionOutcome<"text-pdf", PdfTextReadResult>;
/** Excludes arbitrary progress callbacks. Text PDF retains its existing relative timeout only. */
export type TextPdfOutcomeOptions = Omit<PdfTextReaderOptions, "onPageComplete">;
export function readPngOutcome(input: Uint8Array, options?: StaticPngReaderOptions): Promise<PngOutcome>;
export function readScannedPdfOutcome(input: Uint8Array, options?: ScannedPdfOptions): Promise<ScannedPdfOutcome>;
export function readTextPdfOutcome(input: Uint8Array, options?: TextPdfOutcomeOptions): Promise<TextPdfOutcome>;
export interface JpegWebpOutcomeReader {
  readonly read: (input: Uint8Array, options?: StaticJpegWebpOptions) => Promise<JpegWebpOutcome>;
}
export function createJpegWebpOutcomeReader(configuration: { readonly runtimeDirectory: string }): JpegWebpOutcomeReader;
