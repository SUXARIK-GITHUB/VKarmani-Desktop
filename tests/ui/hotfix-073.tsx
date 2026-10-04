// Synthetic browser acceptance: never imports App or invokes native networking.
import React, { useCallback, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { flushSync } from 'react-dom';
import { SettingsTab } from '../../src/components/SettingsTab';
import { usePingManager } from '../../src/hooks/usePingManager';
import { rankServersForDisplay } from '../../src/utils/serverSorting';
import { defaultSettings, loadSettings, saveSettings } from '../../src/services/storage';
import type { VpnServer, RuntimeStatus, ConnectionState } from '../../src/types/vpn';
import '../../src/styles.css';

const makeServers=(count=11, prefix='S'):VpnServer[]=>Array.from({length:count},(_,sourceOrder)=>({id:`${prefix}${sourceOrder}`,sourceOrder,country:`${prefix}${sourceOrder}`,city:'',flag:'',load:0,protocol:'Xray',host:'synthetic.example.test',port:443,latency:count-sourceOrder,latencyStatus:'ok'}));
const runtime:RuntimeStatus={bridge:'web-preview',coreInstalled:false,tunnelActive:false,message:'synthetic'};
const idleRefresh=async()=>runtime;
const ignore=()=>{};
type PanelApi={ping:()=>Promise<void>;replace:()=>void;context:(state:ConnectionState)=>void;count:()=>number;busy:()=>boolean};
function PingPanel({api}:{api:React.MutableRefObject<PanelApi|null>}){
 const [servers,setServers]=useState(()=>makeServers());const [state,setState]=useState<ConnectionState>('idle');const commits=useRef(0);
 const commit=useCallback<React.Dispatch<React.SetStateAction<VpnServer[]>>>(value=>{commits.current++;setServers(value);},[]);
 const ping=usePingManager({servers,setServers:commit,connectionState:state,selectedServerId:'S0',connectedServerId:state==='connected'?'S0':'',runtimeStatus:runtime,language:'ru',setConnectivityProbe:ignore,pushToast:ignore,refreshDiagnosticsAndRuntime:idleRefresh});
 api.current={ping:()=>ping.refreshPing({silent:true}),replace:()=>setServers(makeServers(11,'R')),context:setState,count:()=>commits.current,busy:()=>ping.isCheckingPing};
 return <section><strong>REAL_HOOK / WEB_PREVIEW</strong><pre data-testid="ping-state">{JSON.stringify({commits:commits.current,checking:ping.checkingPingServerIds.length,busy:ping.isCheckingPing,first:servers[0]?.id,total:ping.pingProgress.total})}</pre></section>;
}
function Harness(){
 const [settings,setSettings]=useState(()=>({...defaultSettings,...loadSettings()}));const [mounted,setMounted]=useState(true);const [results,setResults]=useState<string[]>([]);const api=useRef<PanelApi|null>(null);
 const nextRender=()=>new Promise<void>(resolve=>setTimeout(resolve,0));
 async function run(){
  const outcomes:string[]=[];
  async function reset(){flushSync(()=>setMounted(false));await nextRender();flushSync(()=>setMounted(true));await nextRender();}
  await reset();const one=api.current!.ping();await api.current!.ping();await one;await nextRender();outcomes.push(`double-click=${api.current!.count()===1?'PASS':'FAIL'}`);
  for(const scenario of ['refresh','connect','switch','disconnect'] as const){await reset();const pending=api.current!.ping();await nextRender();if(scenario==='refresh')flushSync(()=>api.current!.replace());else flushSync(()=>api.current!.context(scenario==='connect'?'connecting':scenario==='disconnect'?'disconnecting':'connected'));await pending;await nextRender();outcomes.push(`${scenario}-during-ping=${api.current!.count()===0?'PASS':'FAIL'}`);}
  await reset();const pending=api.current!.ping();await nextRender();flushSync(()=>setMounted(false));await pending;outcomes.push('unmount-during-ping=PASS');
  await reset();flushSync(()=>api.current!.replace());await nextRender();await api.current!.ping();await nextRender();outcomes.push(`refresh-then-ping=${api.current!.count()===1?'PASS':'FAIL'}`);
  setResults(outcomes);
 }
 return <main className="shell app-shell" style={{display:'block',padding:12,height:'100vh',overflow:'auto'}}>
  <div><button onClick={()=>void run()}>Run hook regression</button><button onClick={()=>setSettings(s=>({...s,language:s.language==='ru'?'en':'ru'}))}>RU / EN</button><button onClick={()=>setSettings(loadSettings())}>Reload settings</button></div>
  <pre data-testid="results">{results.join('\n')}</pre>{mounted&&<PingPanel api={api}/>}
  <pre data-testid="order">sort={String(settings.sortServersByPing)}; order={rankServersForDisplay(makeServers(4),'auto',[],settings.sortServersByPing).map(s=>s.id).join(',')}</pre>
  <SettingsTab settings={settings} language={settings.language} onToggleSetting={key=>setSettings(s=>{const next={...s,[key]:!s[key]};saveSettings(next);return next;})} onTunnelModeChange={tunnelMode=>setSettings(s=>({...s,tunnelMode}))} onTunRoutingModeChange={tunRoutingMode=>setSettings(s=>({...s,tunRoutingMode}))} onIpStackChange={ipStack=>setSettings(s=>({...s,ipStack}))} onLanguageChange={language=>setSettings(s=>({...s,language}))} onRoutingExclusionsChange={routingExclusions=>setSettings(s=>({...s,routingExclusions}))}/>
 </main>;
}
createRoot(document.getElementById('root')!).render(<Harness/>);
