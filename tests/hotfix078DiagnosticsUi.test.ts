import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {describe,expect,it,vi} from 'vitest';
vi.mock('react',async()=>{const actual=await vi.importActual<typeof import('react')>('react');return {...actual,useState:(initial:unknown)=>[initial==='overview'?'network':initial,()=>{}]};});
import {DiagnosticsTab} from '../src/components/DiagnosticsTab';
import type {AppSettings,RuntimeStatus} from '../src/types/vpn';
const noop=()=>{};
function markup(state:'owned'|'foreign'|'unavailable',language:'ru'|'en',probeKind:'server-direct'|'xray-http'='server-direct') {
 const runtime:RuntimeStatus={bridge:'tauri',coreInstalled:true,tunnelActive:true,xrayPid:17,networkMode:'tun',launchMode:'xray-sidecar',message:'synthetic',routeOwnership:'confirmed',systemProxyEnabled:false,
 diagnosticFacts:{checkedAtUnixMs:1,tunInterface:'ready',resourceIntegrity:'verified',storageMetadata:'present',logsMetadata:'present',elevation:'elevated',repairHistory:[],repairHistoryStatus:'available',ports:[{port:10808,state},{port:10809,state},{port:10810,state}]}};
 return renderToStaticMarkup(React.createElement(DiagnosticsTab,{diagnostics:null,runtimeStatus:runtime,proxyStatus:{enabled:false,method:'wininet-api',scope:'current-user',checkedAt:'synthetic'},connectivityProbe:{success:true,checkedAt:'synthetic',kind:probeKind,httpPortOpen:false,socksPortOpen:false,message:'direct TCP'},connectionError:'TUN_ADDRESS_NOT_READY <img src=x>',profileSyncInfo:{status:'idle',source:'remnawave',sourceLabel:'synthetic',configCount:0},integrationMeta:{panelUrl:'',subscriptionUrl:'',isConfigured:false,modeLabel:''},sessionHistory:[],updateInfo:{status:'idle',currentVersion:'synthetic',available:false},settings:{language,tunnelMode:'tun'} as AppSettings,language,onEnableSystemProxy:noop,onDisableSystemProxy:noop,onRunConnectivityProbe:noop,onSyncProfile:noop,onCheckUpdates:noop,onClearAccessKey:noop,onReleaseChannelChange:noop,onProtocolStrategyChange:noop,onTunnelModeChange:noop,onLanguageChange:noop}));
}
describe('0.13.78 actual Diagnostics network section markup',()=>{
 it.each(['ru','en'] as const)('renders current listener facts separately from direct ping and truthful DNS/TUN status %s',language=>{
  const text=markup('owned',language);
  expect(text).toContain('HTTP listener 10809');expect(text).toContain('SOCKS listener 10808');
  expect(text).toContain(language==='ru'?'Доступен, собственный':'Available, owned');
  expect(text).toContain('<strong>VPN / TUN egress</strong><span>NOT_TESTED</span>');
  expect(text).toContain('<strong>DNS leak status</strong><span>NOT_TESTED</span>');
  expect(text).toContain('SERVER_DIRECT');expect(text).not.toContain('false / false');
  expect(text).toContain('TUN_ADDRESS_NOT_READY');expect(text).not.toContain('<img src=x>');
 });
 it('does not label foreign listeners as owned even if an unrelated HTTP request succeeded',()=>{
  const text=markup('foreign','en','xray-http');expect(text).toContain('Available, foreign owner');
  expect(text).not.toContain('Available, owned');expect(text).toContain('<strong>VPN / TUN egress</strong><span>NOT_TESTED</span>');
 });
 it('shows unavailable observations as unconfirmed rather than closed',()=>{
  const text=markup('unavailable','en');expect(text).toContain('Unconfirmed');expect(text).not.toContain('Not listening');
 });
});
