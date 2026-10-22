import packageJson from '../../package.json';

export type FrontendCrashCode = 'UI_RENDER_FAILED' | 'UI_UNCAUGHT_ERROR' | 'UI_UNHANDLED_REJECTION';
export interface FrontendCrashReceipt {
  schemaVersion: 1;
  appVersion: string;
  code: FrontendCrashCode;
  phase: 'render' | 'event' | 'async';
  timestamp: string;
  stack: Array<{ line: number; column: number }>;
}

// Error messages, URLs, function names and filenames can contain user input.
// Keep only bounded numeric bundle locations; map them against the exact build.
export function createFrontendCrashReceipt(code: FrontendCrashCode, failure: unknown): FrontendCrashReceipt {
  const stack: FrontendCrashReceipt['stack'] = [];
  try {
    if (failure instanceof Error && typeof failure.stack === 'string') {
      for (const line of failure.stack.slice(0, 16384).split('\n').slice(1, 65)) {
        const match = line.match(/\.(?:[cm]?js|tsx?)(?:\?[^\s:)]{0,128})?:(\d{1,8}):(\d{1,8})\)?\s*$/);
        if (match) stack.push({ line: Number(match[1]), column: Number(match[2]) });
        if (stack.length === 16) break;
      }
    }
  } catch { /* An arbitrary rejection can have throwing accessors. */ }
  return {
    schemaVersion: 1,
    appVersion: packageJson.version,
    code,
    phase: code === 'UI_RENDER_FAILED' ? 'render' : code === 'UI_UNCAUGHT_ERROR' ? 'event' : 'async',
    timestamp: new Date().toISOString(),
    stack
  };
}

let recorded = 0;
let nativeLogger: Promise<typeof import('./runtime')> | null = null;
// Bound repetitive failures per process; the native sink is also size bounded.
export function recordFrontendCrash(receipt: FrontendCrashReceipt): void {
  if (recorded >= 16) return;
  recorded += 1;
  // The fallback must load even if a native/shared module fails initialization.
  nativeLogger ??= import('./runtime');
  void nativeLogger.then(runtime => runtime.writeNativeInterfaceLog('CRASH_RECEIPT', JSON.stringify(receipt))).catch(() => undefined);
}

export function listenForFrontendCrashes(target: Window): () => void {
  const error = (event: ErrorEvent) => recordFrontendCrash(createFrontendCrashReceipt('UI_UNCAUGHT_ERROR', event.error));
  const rejection = (event: PromiseRejectionEvent) => recordFrontendCrash(createFrontendCrashReceipt('UI_UNHANDLED_REJECTION', event.reason));
  target.addEventListener('error', error);
  target.addEventListener('unhandledrejection', rejection);
  return () => {
    target.removeEventListener('error', error);
    target.removeEventListener('unhandledrejection', rejection);
  };
}
