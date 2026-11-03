import { expect, it } from 'vitest';
import fixture from './fixtures/xray/fragment-compat.json';
import { parseXrayJsonSubscriptionToServers } from '../src/services/remnawave/subscriptionParser';
import { normalizeStoredSettings, defaultSettings } from '../src/services/storage';

it('keeps structured FinalMask and exact per-server REALITY paths without changing transport paths', () => {
  const host = (n: number) => ({ protocol: 'vless', transport: 'xhttp', security: 'reality',
    host: `fixture-${n}.example.invalid`, uuid: '00000000-0000-4000-8000-000000000001', name: `Fixture ${n}` });
  const mask = { tcp: [{ type: 'fragment', settings: { lengths: ['3-5', '12-17'], delays: [0, '2-3'], packets: 'tlshello', maxSplit: 3 } }], udp: [], quicParams: {} };
  const path = '/synthetic path?a=x%26y&b=%3D+%25 ';
  const rawHosts = [
    host(0), { ...host(1), transportOptions: { finalmask: mask } },
    { ...host(2), securityOptions: { spx: path }, transportOptions: { path: '/xhttp-only' } },
    { ...host(3), finalmask: mask, realitySettings: { spiderX: '', password: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } },
    { ...host(4), spx: '/not-reality', security: 'tls' }
  ];
  const input = JSON.stringify({ response: { rawHosts } });
  const servers = parseXrayJsonSubscriptionToServers(input);
  expect(new Set(servers.map(s => s.id)).size).toBe(5);
  const streams = servers.map(s => s.runtimeTemplate?.outbound.streamSettings);
  expect(streams[0]).not.toHaveProperty('finalmask');
  expect(streams[0]).not.toHaveProperty('realitySettings.spiderX');
  expect(streams[1]).toHaveProperty('finalmask', mask);
  expect(streams[2]).toHaveProperty('realitySettings.spiderX', path);
  expect(streams[2]).toHaveProperty('xhttpSettings.path', '/xhttp-only');
  expect(streams[3]).toHaveProperty('finalmask', mask);
  expect(streams[3]).toHaveProperty('realitySettings.spiderX', '');
  expect(streams[3]).toHaveProperty('realitySettings.password', rawHosts[3].realitySettings?.password);
  expect(streams[4]).not.toHaveProperty('realitySettings');
  expect(parseXrayJsonSubscriptionToServers(input)).toEqual(servers);
});

it.each([false, true])('preserves the complete fragment/transport/Auto graph in single and multiple profiles: %s', multiple => {
  const second=structuredClone(fixture); second.remarks='Synthetic second';
  second.outbounds[0].tag='pool-other';
  const input=multiple ? [fixture,second] : fixture;
  const before=structuredClone(input);
  const servers=parseXrayJsonSubscriptionToServers(JSON.stringify(input));
  expect(servers).toHaveLength(multiple ? 2 : 1);
  for(const [i,server] of servers.entries()) {
    const expected=multiple ? [fixture,second][i] : fixture;
    expect(server.runtimeTemplate?.fullConfig).toEqual(expected);
    expect(server.runtimeTemplate?.profileKind).toBe('auto');
    expect(server.runtimeTemplate?.memberTags).toEqual(expected.outbounds.slice(0,3).map(o=>o.tag));
  }
  expect(input).toEqual(before);
});

it('defaults fresh/absent-mode state to selected and retains every explicit choice', () => {
  expect(defaultSettings.tunRoutingMode).toBe('selected');
  for(const value of [null,undefined,{}, {language:'en'}])
    for(const hasRules of [false,true]) expect(normalizeStoredSettings(value,hasRules).tunRoutingMode).toBe('selected');
  for(const tunRoutingMode of ['all','exclude','selected'] as const)
    expect(normalizeStoredSettings({tunRoutingMode},true).tunRoutingMode).toBe(tunRoutingMode);
});

it('keeps independent RAW/REALITY, XHTTP and WebSocket nodes distinct without losing the graph', () => {
  const input=structuredClone(fixture) as any;
  delete input.routing;
  const servers=parseXrayJsonSubscriptionToServers(JSON.stringify(input));
  expect(servers).toHaveLength(3);
  expect(new Set(servers.map(s=>s.id)).size).toBe(3);
  expect(servers.map(s=>s.runtimeTemplate?.primaryOutboundTag)).toEqual(['pool-raw','pool-xhttp','pool-ws']);
  for(const server of servers) {
    expect(server.runtimeTemplate?.profileKind).toBe('node');
    expect(server.runtimeTemplate?.fullConfig).toEqual(input);
    expect(server.runtimeTemplate?.outbound).toEqual(input.outbounds.find((o:any)=>o.tag===server.runtimeTemplate?.primaryOutboundTag));
  }
});
