import {describe,it,expect,vi} from 'vitest';
import {NativeMutationTracker} from '../src/services/nativeTransport';
describe('Actual native invocation ownership outlives renderer timeout',()=>{
  it('keeps actual mutation pending after a caller deadline; late completion releases exactly once',async()=>{
    const settled=vi.fn();const tracker=new NativeMutationTracker(settled);let finish!:(v:string)=>void;
    const actual=tracker.invoke('request_connect',()=>new Promise<string>(resolve=>{finish=resolve;}));
    await expect(Promise.race([actual,Promise.reject(Error('client timeout'))])).rejects.toThrow('client timeout');
    expect(tracker.pending()).toBe(true);expect(tracker.commands()).toEqual(['request_connect']);expect(settled).not.toHaveBeenCalled();
    finish('late');expect(await actual).toBe('late');expect(tracker.pending()).toBe(false);expect(settled).toHaveBeenCalledOnce();
  });
  it('handles concurrent commands, sync throw and late rejection without releasing another owner',async()=>{
    const tracker=new NativeMutationTracker();let a!:()=>void;let reject!:(e:Error)=>void;
    const first=tracker.invoke('request_connect',()=>new Promise<void>(resolve=>{a=resolve;}));
    const second=tracker.invoke('request_disconnect',()=>new Promise<void>((_,no)=>{reject=no;}));
    await expect(tracker.invoke('set_system_proxy',()=>{throw Error('sync');})).rejects.toThrow('sync');
    a();await first;expect(tracker.commands()).toEqual(['request_disconnect']);reject(Error('late'));
    await expect(second).rejects.toThrow('late');expect(tracker.pending()).toBe(false);
  });
  it('readonly observations neither acquire mutation ownership nor publish results',async()=>{
    const settled=vi.fn();const tracker=new NativeMutationTracker(settled);
    expect(await tracker.invoke('diagnostics_snapshot',async()=>({private:'not stored'}))).toEqual({private:'not stored'});
    expect(tracker.commands()).toEqual([]);expect(settled).not.toHaveBeenCalled();
  });
});
