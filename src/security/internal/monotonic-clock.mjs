import { performance } from 'node:perf_hooks';

// Private composition deadlines and controlled transport use this one native
// clock/domain: milliseconds on this process's performance timeline. Capture
// the native method once; never translate an independent hrtime/wall budget.
const nativeNow = performance.now.bind(performance);
export function monotonicNow() { return nativeNow(); }
