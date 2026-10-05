import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { OverviewTab } from '../src/components/OverviewTab';
import { appendTrafficSample, buildTrafficBars, formatTrafficBytes, validTrafficSnapshot, type TrafficSample } from '../src/utils/traffic';
import { activeSettingsSection } from '../src/utils/settingsNavigation';
import type { TrafficSnapshot } from '../src/types/vpn';

const server = { id:'synthetic', country:'Synthetic', city:'', flag:'', protocol:'Xray', load:0, host:'private-endpoint.example.test', port:443, transportLabel:'PRIVATE-TRANSPORT' };
const noop = () => {};
function render(connectionState: 'connected' | 'idle', language: 'ru' | 'en', selectedServer = server as import('../src/types/vpn').VpnServer) {
  return renderToStaticMarkup(<OverviewTab connectionState={connectionState} language={language} connectLabel="Connect" selectedServer={selectedServer} selectedServerId={server.id} servers={[]} allServerCount={1} searchValue="" sessionDurationText="00:00:30" showDiagnostics tunnelMode="proxy" onToggleConnection={noop} onTunnelModeChange={noop} onSelectServer={noop} onSearchChange={noop} onRefreshServers={noop} onRefreshPing={noop} onToggleFavoriteServer={noop} favoriteServerIds={[]} trafficReceivedText="—" trafficSentText="—" trafficChartBars={[]} vpnExternalIp="—" packetLossText="—" canConnect activeSplitTunnelCount={0} onOpenSplitTunnel={noop} />);
}
describe('truthful telemetry and connected hero regressions', () => {
  it.each([NaN, Infinity, -1])('shows unavailable bytes as no data: %s', value => expect(formatTrafficBytes(value)).toBe('—'));
  it('keeps measured zero distinct from unavailable', () => expect(formatTrafficBytes(0)).toBe('0 Б'));
  it.each(['ru','en'] as const)('hides secondary endpoint/protocol in connected hero only (%s)', language => {
    const markup=render('connected',language), hero=markup.slice(0,markup.indexOf('</section>'));
    expect(hero).not.toContain('PRIVATE-TRANSPORT');
    expect(hero).not.toContain('private-endpoint.example.test');
    expect(markup).toContain('PRIVATE-TRANSPORT'); // Retained in session diagnostics.
  });
  it('retains secondary information before connection', () => expect(render('idle','en')).toContain('PRIVATE-TRANSPORT'));
  it('does not display a stale numeric RTT after a failed measurement', () => expect(render('connected','en',{...server,latency:1,latencyStatus:'failed'})).toContain('No response'));
});

const snapshot = (receivedBytes: number, sentBytes = 0): TrafficSnapshot => ({receivedBytes,sentBytes,source:'xray-stats',checkedAt:'synthetic'});
describe('measured traffic history', () => {
  it('uses actual byte deltas and elapsed time, with no decorative idle activity', () => {
    let h=appendTrafficSample([],snapshot(100,10),1000);
    h=appendTrafficSample(h,snapshot(300,110),11000);
    h=appendTrafficSample(h,snapshot(300,110),21000);
    expect(h.map(s=>s.bytesPerSecond)).toEqual([null,30,0]);
    expect(buildTrafficBars(h)).toEqual([0,100,0]);expect(buildTrafficBars([])).toEqual([]);
  });
  it('does not invent rates through resets, source gaps or stale completions', () => {
    const initial=appendTrafficSample([],snapshot(100,100),1000);
    expect(appendTrafficSample(initial,snapshot(90,110),2000)[1].bytesPerSecond).toBeNull();
    expect(appendTrafficSample(initial,snapshot(9000),70000)[1].bytesPerSecond).toBeNull();
    expect(appendTrafficSample(initial,snapshot(9000),0)).toBe(initial);
    expect(appendTrafficSample(initial,{...snapshot(0),source:'unavailable'},2000)).toBe(initial);
  });
  it('marks a native rebaseline or runtime/source switch as unknown rate even when cumulative totals are unchanged', () => {
    const h=appendTrafficSample([],{...snapshot(100),runtimeId:'A'},1000);
    expect(appendTrafficSample(h,{...snapshot(100),runtimeId:'A',baselineChanged:true},31000)[1].bytesPerSecond).toBeNull();
    expect(appendTrafficSample(h,{...snapshot(100),runtimeId:'B'},31000)[1].bytesPerSecond).toBeNull();
    expect(appendTrafficSample(h,{...snapshot(100),runtimeId:'A',source:'windows-tun-adapter'},31000)[1].bytesPerSecond).toBeNull();
  });
  it.each([NaN,Infinity,-1,Number.MAX_SAFE_INTEGER+1])('rejects invalid or inexact native counters: %s', value => expect(validTrafficSnapshot(snapshot(value))).toBe(false));
  it('bounds a simulated 24-hour session to 60 measured samples and 30 rendered bars', () => {
    let history: TrafficSample[]=[];
    for(let i=0;i<2880;i++) history=appendTrafficSample(history,snapshot(i*70000,i*10000),i*30000);
    expect(history).toHaveLength(60);expect(buildTrafficBars(history)).toHaveLength(30);
    expect(history.every(s=>s.bytesPerSecond===80000/30)).toBe(true);
  });
  it.each(['ru','en'] as const)('keeps complete human-readable counters (%s)',language => {
    expect(formatTrafficBytes(162*1024*1024,language)).toBe(language==='ru'?'162 МБ':'162 MB');
    expect(formatTrafficBytes(Math.round(3.32*1024*1024),language)).toBe(language==='ru'?'3.32 МБ':'3.32 MB');
    expect(formatTrafficBytes(1.25*1024**3,language)).toBe(language==='ru'?'1.25 ГБ':'1.25 GB');
  });
});
describe('Settings without a viewport-sized blank tail', () => {
  it('selects the last section at the physical bottom even if it cannot reach sticky top', () => {
    const sections=[{id:'first',top:100},{id:'last',top:1500}];
    expect(activeSettingsSection(sections,1199,150,1200)).toBe('last');
    expect(activeSettingsSection(sections,600,150,1200)).toBe('first');
  });
});
