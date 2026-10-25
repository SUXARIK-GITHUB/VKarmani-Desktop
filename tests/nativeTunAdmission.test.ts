import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';

it('native TUN process admission precedes authorization, operation admission and prior-runtime teardown', () => {
  const commands = readFileSync(new URL('../src-tauri/src/commands.rs', import.meta.url), 'utf8');
  const connect = commands.slice(commands.indexOf('fn request_connect_blocking('));
  const gate = connect.indexOf('ensure_tun_process_enforcement(');
  expect(gate).toBeGreaterThan(0);
  for (const boundary of ['ensure_native_session_authorized(', 'acquire_operation_lock(', 'resolve_core_path(', 'stop_managed_or_starting_runtime(']) {
    expect(connect.indexOf(boundary), boundary).toBeGreaterThan(gate);
  }
});
