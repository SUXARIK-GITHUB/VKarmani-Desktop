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
    expect(helper).toContain('child.id()');
    const compact = helper.replace(/\s+/g, '');
    expect(compact.indexOf('owned_loopback_listeners_ready')).toBeLessThan(compact.indexOf('child.try_wait()'));
    const publish = source.split('runtime.child = child;')[0];
    expect(publish).toContain('match runtime_listeners_ready(&mut child)');
    expect(publish.lastIndexOf('current_physical_binding()')).toBeLessThan(publish.lastIndexOf('match runtime_listeners_ready(&mut child)'));
    expect(publish.slice(publish.lastIndexOf('match runtime_listeners_ready(&mut child)'))).toContain('return Err(Box::new((runtime, error)))');
  });
});
