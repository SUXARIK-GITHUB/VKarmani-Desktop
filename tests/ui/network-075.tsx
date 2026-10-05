// Browser-only synthetic acceptance of actual components/hooks; no App/native session.
import React, { useCallback, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { flushSync } from 'react-dom';
import { SettingsTab } from '../../src/components/SettingsTab';
import { SidebarNav } from '../../src/components/SidebarNav';
import { WindowHeader } from '../../src/components/WindowHeader';
import { OverviewTab } from '../../src/components/OverviewTab';
import { SplitTunnelModal } from '../../src/components/SplitTunnelModal';
import { AppInfoModal } from '../../src/components/AppInfoModal';
import { ToastViewport } from '../../src/components/ToastViewport';
import { useToastManager } from '../../src/hooks/useToastManager';
import { usePingManager } from '../../src/hooks/usePingManager';
import { defaultSettings } from '../../src/services/storage';
import { normalizeStoredRules } from '../../src/utils/appPolicies';
import { rankServersForDisplay } from '../../src/utils/serverSorting';
import { parseXrayJsonSubscriptionToServers as parse } from '../../src/services/remnawave/subscriptionParser';
import auto from '../fixtures/xray/auto.json';
import legacy from '../fixtures/policies/legacy-upgrade.json';
import type { AppTab, ConnectionState, RemnawaveSession, RuntimeStatus, VpnServer } from '../../src/types/vpn';
import packageJson from '../../package.json';
import '../../src/styles.css';

const query=new URLSearchParams(location.search);
const ignore=()=>{};
const runtime:RuntimeStatus={bridge:'web-preview',coreInstalled:false,tunnelActive:false,message:'synthetic'};
const refresh=async()=>runtime;
const session={} as RemnawaveSession;
const updateInfo={currentVersion:packageJson.version,status:'idle' as const,available:false,message:''};
const makeServers=()=>[...parse(JSON.stringify({...auto,remarks:'EU Auto'})).map(s=>({...s,country:'EU Auto',countryCode:'EU',flag:'EU',latency:28,latencyStatus:'ok' as const,latencyCheckedAt:query.get('fresh')==='1'?new Date().toISOString():undefined})),...Array.from({length:10},(_,i):VpnServer=>({id:`S${i}`,sourceOrder:i+1,country:i%2?'Netherlands':'Germany',countryCode:i%2?'NL':'DE',city:'',flag:i%2?'NL':'DE',load:0,protocol:'Xray',host:'synthetic.example.test',port:443,latency:40+i,latencyStatus:'ok'}))];
function Harness(){
 const [settings,setSettings]=useState({...defaultSettings,language:query.get('lang')==='en'?'en' as const:'ru' as const});
 const [tab,setTab]=useState<AppTab>(query.get('view')==='overview'?'overview':'settings');
 const [modal,setModal]=useState(query.get('modal')||'');
 const [entries,setEntries]=useState(()=>normalizeStoredRules([...legacy.splitTunnelEntries,{id:'long',kind:'app',value:'C:/Program Files/Very Long Application Folder/Рабочие инструменты/Example Application.exe',enabled:true,policy:'DIRECT',schemaVersion:2},{id:'quarantine',kind:'app',value:'<invalid stored policy>',enabled:false,schemaVersion:2}]));
 const [servers,setServers]=useState(makeServers);const [state,setState]=useState<ConnectionState>(query.get('connected')==='1'?'connected':'idle');
 const [testRuntime,setTestRuntime]=useState<RuntimeStatus>({...runtime,runtimeId:query.get('epoch')==='1'?'epoch-A':undefined});
 const [selected,setSelected]=useState(servers[0].id);const [favorites,setFavorites]=useState<string[]>([]);
 const [search,setSearch]=useState('');const commits=useRef(0);const [testResults,setTestResults]=useState<string[]>([]);
 const {toasts,pushToast}=useToastManager(false); // Explicit clipboard feedback still appears with global notifications OFF.
 const commit=useCallback<React.Dispatch<React.SetStateAction<VpnServer[]>>>(value=>{commits.current++;setServers(value);},[]);
 const ping=usePingManager({servers,setServers:commit,connectionState:state,selectedServerId:selected,connectedServerId:state==='connected'?selected:'',runtimeStatus:testRuntime,language:settings.language,setConnectivityProbe:ignore,pushToast,refreshDiagnosticsAndRuntime:refresh});
 const nextRender=()=>new Promise<void>(resolve=>requestAnimationFrame(()=>resolve()));
 async function hookRegression(){
  const results:string[]=[];let before=commits.current;
  const one=ping.refreshPing({silent:true});await ping.refreshPing({silent:true});await one;await nextRender();results.push(`double-click=${commits.current===before+1?'PASS':'FAIL'}`);
  for(const scenario of ['refresh','connect','switch','disconnect'] as const){before=commits.current;const pending=ping.refreshPing({silent:true});await nextRender();flushSync(()=>{if(scenario==='refresh')setServers(makeServers());else if(scenario==='switch')setSelected('S1');else setState(scenario==='connect'?'connecting':'disconnecting');});await pending;await nextRender();results.push(`${scenario}-during-ping=${commits.current===before?'PASS':'FAIL'}`);flushSync(()=>setState('idle'));await nextRender();}
  before=commits.current;await ping.refreshPing({silent:true});await nextRender();results.push(`refresh-then-ping=${commits.current===before+1?'PASS':'FAIL'}`);setTestResults(results);
 }
 const language=settings.language;const sorted=rankServersForDisplay(servers,'auto',favorites,settings.sortServersByPing).filter(s=>s.country.toLowerCase().includes(search.toLowerCase()));
 return <>
  <div className={`shell app-shell ${settings.themeGlow?'glow-enabled':'glow-disabled'}`}>
   <div className="window-frame desktop-frame">
    <WindowHeader session={session} currentVersion={packageJson.version} updateInfo={updateInfo} language={language} minimizeToTray onToggleLanguage={ignore} onCheckUpdates={ignore} onRequestHideToTray={ignore}/>
    <main className="workspace-grid"><SidebarNav activeTab={tab} onChange={setTab} onShowInfo={()=>setModal('info')} onExit={ignore} connectionState="idle" session={session} devices={[]} language={language} showDiagnostics={query.get('diagnostics')==='1'}/>
     <section className={`content-area ${tab==='overview'?'overview-content-area':''}`}>
      {tab==='overview'?<OverviewTab connectionState={state} connectLabel={language==='ru'?'Подключиться':'Connect'} selectedServer={servers.find(s=>s.id===selected)!} selectedServerId={selected} servers={sorted} allServerCount={servers.length} searchValue={search} sessionDurationText="00:00:00" language={language} showDiagnostics={query.get('diagnostics')==='1'} tunnelMode="tun" onToggleConnection={ignore} onTunnelModeChange={ignore} onSelectServer={setSelected} onSearchChange={setSearch} onRefreshServers={()=>setServers(makeServers())} onRefreshPing={()=>void ping.refreshPing({silent:true})} onToggleFavoriteServer={id=>setFavorites(values=>values.includes(id)?values.filter(v=>v!==id):[...values,id])} favoriteServerIds={favorites} trafficReceivedText={language==='ru'?'162 МБ':'162 MB'} trafficSentText={language==='ru'?'3.32 МБ':'3.32 MB'} trafficChartBars={[]} vpnExternalIp="—" packetLossText="—" isCheckingPing={ping.isCheckingPing} checkingPingServerIds={ping.checkingPingServerIds} canConnect activeSplitTunnelCount={3} onOpenSplitTunnel={()=>setModal('apps')}/>
       :<SettingsTab settings={settings} language={language} onToggleSetting={key=>setSettings(s=>({...s,[key]:!s[key]}))} onTunnelModeChange={tunnelMode=>setSettings(s=>({...s,tunnelMode}))} onIpStackChange={ipStack=>setSettings(s=>({...s,ipStack}))} onTunRoutingModeChange={tunRoutingMode=>setSettings(s=>({...s,tunRoutingMode}))} onLanguageChange={language=>setSettings(s=>({...s,language}))} onRoutingExclusionsChange={routingExclusions=>setSettings(s=>({...s,routingExclusions}))}/>}
     </section>
    </main>
   </div>
  </div>
  <SplitTunnelModal open={modal==='apps'} language={language} entries={entries} runningApps={[{pid:1234,name:'Example.exe',path:'C:/Apps/Example.exe'}]} isLoadingApps={false} onClose={()=>setModal('')} onAddEntry={(kind,value,policy)=>{setEntries(values=>normalizeStoredRules([...values,{id:`added-${values.length}`,kind,value,policy,enabled:true,schemaVersion:2}]));return true;}} onChangePolicy={(id,policy)=>setEntries(values=>values.map(e=>e.id===id?{...e,policy}:e))} tunnelMode="tun" tunRoutingMode={settings.tunRoutingMode} onToggleEntry={id=>setEntries(values=>values.map(e=>e.id===id?{...e,enabled:!e.enabled}:e))} onRemoveEntry={id=>setEntries(values=>values.filter(e=>e.id!==id))} onPickExecutable={ignore} onRefreshRunningApps={ignore}/>
  <AppInfoModal open={modal==='info'} language={language} info={{appVersion:packageJson.version,xrayVersion:'26.4.25',hwid:'SYNTHETIC-DEVICE',deviceName:'Synthetic workstation',osName:'Windows',osVersion:'11',osBuild:'synthetic',osArchitecture:'x64',corePath:'C:/Synthetic/VKarmani/xray.exe'}} updateInfo={updateInfo} onCheckUpdates={ignore} onClose={()=>setModal('')} onCopyFeedback={success=>pushToast(success?(language==='ru'?'Информация скопирована':'Information copied'):(language==='ru'?'Не удалось скопировать информацию':'Could not copy information'),success?'success':'error',{key:'copy-info',force:true})}/>
  <ToastViewport items={toasts}/>
  <div style={{position:'fixed',left:-10000,top:0}}><button onClick={()=>void hookRegression()}>Run hook regression</button><button data-testid="runtime-clear" onClick={()=>setTestRuntime({...runtime,runtimeId:undefined})}>Clear synthetic runtime</button><button data-testid="runtime-change" onClick={()=>setTestRuntime({...runtime,runtimeId:'epoch-B'})}>Change synthetic runtime</button><pre data-testid="hook-results">{testResults.join('\n')}</pre><pre data-testid="ping-state">{JSON.stringify({commits:commits.current,checking:ping.checkingPingServerIds,busy:ping.isCheckingPing,total:ping.pingProgress.total,profiles:servers.length,firstLatency:servers[0]?.latency,runtimeId:testRuntime.runtimeId})}</pre></div>
 </>;
}
createRoot(document.getElementById('root')!).render(<React.StrictMode><Harness/></React.StrictMode>);
