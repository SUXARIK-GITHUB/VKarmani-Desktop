import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';

it('local owner-test startup keeps native single-instance protection before storage and network setup', () => {
  const run=readFileSync(new URL('../src-tauri/src/app_run.rs',import.meta.url),'utf8');
  const policy=run.indexOf('if cfg!(not(debug_assertions)) || local_test_build()');
  const plugin=run.indexOf('tauri_plugin_single_instance::init(');
  expect(policy).toBeGreaterThan(run.indexOf('validate_local_test_config(context.config())'));
  expect(plugin).toBeGreaterThan(policy);
  expect(plugin).toBeLessThan(run.indexOf('.setup(|app|'));
});

it('native TUN process admission precedes authorization, operation admission and prior-runtime teardown', () => {
  const commands = readFileSync(new URL('../src-tauri/src/commands.rs', import.meta.url), 'utf8');
  const connect = commands.slice(commands.indexOf('fn request_connect_blocking('));
  const gate = connect.indexOf('ensure_tun_process_admission(');
  expect(gate).toBeGreaterThan(0);
  expect(connect).toContain('local_test_build() && app.config().identifier == LOCAL_TEST_ID');
  for (const boundary of ['ensure_native_session_authorized(', 'acquire_operation_lock(', 'resolve_core_path(', 'stop_managed_or_starting_runtime(']) {
    expect(connect.indexOf(boundary), boundary).toBeGreaterThan(gate);
  }
});

it('validates a TUN-free projection before stopping, with full TUN construction only after owned stop', () => {
  const commands = readFileSync(new URL('../src-tauri/src/commands.rs', import.meta.url), 'utf8');
  const connect = commands.slice(commands.indexOf('fn request_connect_blocking('));
  const validation = connect.indexOf('validate_xray_config_with_core(');
  const stop = connect.indexOf('stop_managed_or_starting_runtime(');
  expect(validation).toBeGreaterThan(0);
  expect(validation).toBeLessThan(stop);
  expect(connect.indexOf('validate_xray_config_with_core(&core_path, &config_path')).toBeGreaterThan(stop);
  expect(connect.indexOf('config_preflight_projection(&config)')).toBeLessThan(validation);
  expect(connect.indexOf('PreparedRuntimeConfig::write(')).toBeLessThan(validation);
  expect(connect.indexOf('prepared_config.commit()')).toBeGreaterThan(stop);
});
