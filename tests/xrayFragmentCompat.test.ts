import { expect, it } from 'vitest';
import fixture from './fixtures/xray/fragment-compat.json';
import { parseXrayJsonSubscriptionToServers } from '../src/services/remnawave/subscriptionParser';
import { normalizeStoredSettings, defaultSettings } from '../src/services/storage';

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
