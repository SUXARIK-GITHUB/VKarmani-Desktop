import {describe,expect,it,vi} from 'vitest';
const callbacks=vi.hoisted(()=>({publish:vi.fn(),commit:vi.fn(),refresh:vi.fn().mockResolvedValue(null),ping:vi.fn()}));
vi.mock('react',()=>({useCallback:(fn:unknown)=>fn,useEffect:()=>{},useRef:(value:unknown)=>({current:value}),useState:(value:unknown)=>[value,vi.fn()]}));
vi.mock('../src/services/runtime',()=>({getServerPingEndpoint:()=>({host:'192.0.2.1',port:443}),pingNativeServer:callbacks.ping,writeNativeInterfaceLog:vi.fn(),writeNativeRoutingLog:vi.fn()}));
import {usePingManager} from '../src/hooks/usePingManager';
import type {RuntimeStatus,VpnServer} from '../src/types/vpn';
describe('0.13.78 actual ping batch callback',()=>{
 it('commits measured RTT but never overwrites the independent VPN connectivity result',async()=>{
  const server={id:'synthetic',host:'192.0.2.1',port:443,sourceOrder:0} as VpnServer;
  callbacks.ping.mockResolvedValue({success:true,checkedAt:'synthetic',kind:'server-direct',httpPortOpen:false,socksPortOpen:false,latencyMs:5,message:'direct TCP'});
  const hook=usePingManager({servers:[server],setServers:callbacks.commit,connectionState:'connected',selectedServerId:server.id,connectedServerId:server.id,runtimeStatus:{runtimeId:'owned',lastPreparedServerId:server.id} as RuntimeStatus,language:'en',setConnectivityProbe:callbacks.publish,pushToast:vi.fn(),refreshDiagnosticsAndRuntime:callbacks.refresh});
  await hook.refreshPing({silent:true});
  expect(callbacks.commit).toHaveBeenCalledTimes(1);expect(callbacks.publish).not.toHaveBeenCalled();
  expect(callbacks.refresh).toHaveBeenCalledTimes(1);
 });
});
