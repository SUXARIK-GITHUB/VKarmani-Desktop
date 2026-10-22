import type { NativeStateSnapshot } from '../../src/services/nativeState';

export type PatchRequest = { generation: string; expectedRevision: string; expectedSessionGeneration: string; operationId: string; changes: Array<{ scope: string; key: string; value: unknown }> };
export class NativeStateFake {
  snapshot: NativeStateSnapshot = {
    schemaVersion: 2, generation: 'a'.repeat(48), revision: '0', updatedAt: '0', readOnly: false, recoveryToken: null,
    payload: { public: {}, protected: {}, accessKey: null, sessionGeneration: '0', legacyWebView: null }
  };
  async invoke(command: string, args: Record<string, unknown> = {}): Promise<unknown> {
    if (command === 'load_state_snapshot') return structuredClone(this.snapshot);
    if (command !== 'commit_state_patch') throw new Error('Unexpected test RPC: ' + command);
    const request = args.request as PatchRequest;
    if (request.generation !== this.snapshot.generation || request.expectedRevision !== this.snapshot.revision || request.expectedSessionGeneration !== this.snapshot.payload.sessionGeneration) throw { code: 'STATE_CONFLICT', category: 'storage' };
    for (const change of request.changes) {
      if (change.scope === 'credential') {
        if (this.snapshot.payload.accessKey !== change.value) {
          this.snapshot.payload.accessKey = change.value as string | null;
          this.snapshot.payload.sessionGeneration = (BigInt(this.snapshot.payload.sessionGeneration) + 1n).toString();
          delete this.snapshot.payload.protected.lastKnownServers;
          delete this.snapshot.payload.public.lastKnownServers;
        }
      } else if (change.scope === 'legacy') this.snapshot.payload.legacyWebView = structuredClone(change.value as Record<string, unknown>);
      else {
        const values = change.scope === 'protected' ? this.snapshot.payload.protected : this.snapshot.payload.public;
        if (change.value === null) delete values[change.key];
        else values[change.key] = structuredClone(change.value);
      }
    }
    this.snapshot.revision = (BigInt(this.snapshot.revision) + 1n).toString();
    return { snapshot: structuredClone(this.snapshot), deduplicated: false };
  }
}
