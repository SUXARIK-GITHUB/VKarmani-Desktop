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
  expect(connect.slice(gate, connect.indexOf('let state = app.state'))).not.toContain('local_test_build');
  for (const boundary of ['ensure_native_session_authorized(', 'acquire_operation_lock(', 'resolve_core_path(', 'stop_managed_or_starting_runtime(']) {
    expect(connect.indexOf(boundary), boundary).toBeGreaterThan(gate);
  }
});

it('release-binary policy probe returns before Builder, storage and WebView startup', () => {
  const run=readFileSync(new URL('../src-tauri/src/app_run.rs',import.meta.url),'utf8');
  const probe=run.indexOf('value == "--verify-production-tun"');
  expect(probe).toBeGreaterThan(run.indexOf('validate_local_test_config(context.config())'));
  expect(probe).toBeLessThan(run.indexOf('let builder = tauri::Builder::default()'));
  expect(run.slice(probe,run.indexOf('let builder = tauri::Builder::default()'))).toContain('return;');
});

it('checks both TUN configurations before stopping and only the owned child constructs the adapter', () => {
  const commands = readFileSync(new URL('../src-tauri/src/commands.rs', import.meta.url), 'utf8');
  const connect = commands.slice(commands.indexOf('fn request_connect_blocking('));
  const validation = connect.indexOf('validate_xray_config_with_core(');
  const stop = connect.indexOf('stop_managed_or_starting_runtime(');
  expect(validation).toBeGreaterThan(0);
  expect(validation).toBeLessThan(stop);
  const compile = connect.indexOf('compile_xray_tun_config_with_core(&core_path, &config_path');
  const available = connect.indexOf('prepare_owned_tun_adapter(&app)');
  const spawn = connect.indexOf('spawn_xray_runtime_child(');
  expect(compile).toBeGreaterThan(validation);
  expect(compile).toBeLessThan(stop);
  const adapterPreflight = connect.indexOf('preflight_owned_tun_adapter(&app)');
  expect(adapterPreflight).toBeGreaterThan(compile);
  expect(adapterPreflight).toBeLessThan(stop);
  expect(available).toBeGreaterThan(stop);
  expect(spawn).toBeGreaterThan(available);
  expect(connect.indexOf('confirm_tun_routes_ready(&app, interface, &adapter)')).toBeLessThan(
    connect.indexOf('record_owned_tun_adapter(&app, adapter, &mut child)'),
  );
  const restart = readFileSync(new URL('../src-tauri/src/runtime_lifecycle.rs', import.meta.url), 'utf8');
  const readmit = restart.indexOf('prepare_owned_tun_adapter(app)');
  const replacement = restart.indexOf('spawn_xray_runtime_child(', readmit);
  const confirm = restart.indexOf('confirm_tun_routes_ready(app, interface, &adapter)', replacement);
  const record = restart.indexOf('record_owned_tun_adapter(app, adapter, &mut child)', confirm);
  expect(readmit).toBeGreaterThan(0);
  expect(replacement).toBeGreaterThan(readmit);
  expect(confirm).toBeGreaterThan(replacement);
  expect(record).toBeGreaterThan(confirm);
  expect(restart.indexOf('runtime.child = child;', record)).toBeGreaterThan(record);
  expect(connect).toMatch(/if tun_interface_plan\.is_none\(\) \{\s*validate_xray_config_with_core\(&core_path, &config_path/);
  expect(connect.indexOf('config_preflight_projection(&config)')).toBeLessThan(validation);
  expect(connect.indexOf('PreparedRuntimeConfig::write(')).toBeLessThan(validation);
  expect(connect.indexOf('prepared_config.commit()')).toBeGreaterThan(stop);
});
