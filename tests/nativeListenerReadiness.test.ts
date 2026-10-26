import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (file: string) => readFileSync(`src-tauri/src/${file}`, 'utf8');
describe('native readiness uses the retained child, never any reachable port', () => {
  it.each([
    ['commands.rs', 'pub(crate) fn wait_for_xray_runtime_ready', 'pub(crate) fn'],
    ['runtime_lifecycle.rs', 'fn wait_for_restarted_xray_ready', 'struct PreparedNetworkConfig'],
  ])('checks exact owner in %s', (file, start, end) => {
    const source = read(file).split(start)[1].split(end)[0];
    expect(source).toContain('runtime_listeners_ready(child)?');
    expect(source).not.toContain('tcp_port_open(');
  });
  it('checks the child handle after the owner snapshot and after restart setup', () => {
    const source = read('runtime_lifecycle.rs');
    const helper = source.split('pub(crate) fn runtime_listeners_ready')[1].split('fn wait_for_restarted')[0];
    expect(helper).toContain('child_listeners_ready(');
    const owner = read('listener_owner.rs').split('pub(crate) fn child_listeners_ready')[1].split('#[cfg(test)]')[0];
    expect(owner).toContain('child.id()');
    const compact = owner.replace(/\s+/g, '');
    expect(compact.indexOf('owned_loopback_listeners_ready')).toBeLessThan(compact.indexOf('retained_child_alive(child)'));
    expect(read('listener_owner.rs').split('fn retained_child_alive')[1].split('#[cfg(test)]')[0].replace(/\s+/g, '')).toContain('child.try_wait()');
    const publish = source.split('runtime.child = child;')[0];
    expect(publish).toContain('match runtime_listeners_ready(&mut child)');
    expect(publish.lastIndexOf('current_physical_binding()')).toBeLessThan(publish.lastIndexOf('match runtime_listeners_ready(&mut child)'));
    expect(publish.slice(publish.lastIndexOf('match runtime_listeners_ready(&mut child)'))).toContain('return Err(Box::new((runtime, error)))');
  });
  it('rechecks listeners after initial route setup before publishing, including a still-live child that lost its binds', () => {
    const source = read('commands.rs');
    const final = source.split('Xray остановился до завершения подключения.')[1].split('_operation_guard.stage("publishing")')[0];
    expect(final).toContain('runtime_listeners_ready(&mut child)?');
  });
  it('requires exact listener ownership under the operation lease before enabling system Proxy', () => {
    const command = read('commands.rs').split('pub(crate) fn set_system_proxy_blocking')[1].split('#[tauri::command]')[0];
    const check = command.indexOf('require_proxy_runtime_ready(');
    expect(check).toBeGreaterThan(command.indexOf('acquire_operation_lock('));
    expect(check).toBeLessThan(command.indexOf('enable_owned_windows_proxy('));
    const admission = command.slice(command.lastIndexOf('if enabled {', check), command.indexOf('let status ='));
    expect(admission.replace(/\s+/g, '')).toContain('runtime.as_mut()');
    expect(admission).toContain('&[HTTP_PORT, SOCKS_PORT, XRAY_API_PORT]');
    expect(admission).toContain(')?;');
    expect(admission.indexOf('_operation_guard.stage("configuring-proxy")?')).toBeGreaterThan(admission.indexOf('require_proxy_runtime_ready('));
  });
});
