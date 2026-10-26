import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
it('service inventory uses only local read-only SCM queries, without the timed-out shell provider or service controls', () => {
  const policy = readFileSync('src-tauri/src/app_policy.rs', 'utf8');
  const inventory = policy.split('pub(crate) fn service_inventory()')[1].split('#[tauri::command]')[0];
  expect(inventory).toContain('native_services::enumerate()');
  expect(inventory).not.toMatch(/run_powershell|Get-CimInstance|Command::/);
  const native = readFileSync('src-tauri/src/app_policy/native_services.rs', 'utf8');
  expect(native).toContain('SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE');
  expect(native).toContain('SERVICE_QUERY_CONFIG');
  expect(native).not.toMatch(/\b(StartServiceW|ControlService|ChangeServiceConfigW|CreateServiceW|DeleteService)\s*\(/);
  expect(native).not.toContain('SERVICE_ALL_ACCESS');
});
