import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {describe,expect,it,vi} from 'vitest';
import {StartupRecoveryPanel} from '../src/components/StartupGate';
import {createStartupClient,safeStartupStatus,startupErrorCode,validateStartupStatus,type StartupStatus} from '../src/services/startup';
import packageJson from '../package.json';

const normal:StartupStatus={schemaVersion:1,mode:'normal',code:'STARTUP_NORMAL',appVersion:packageJson.version,failures:0,attemptId:'a'.repeat(48),retryAllowed:false,readyAfterMs:30000};
describe('R17/R18 startup admission and preservation boundary',()=>{
  it('accepts only exact versioned native DTOs with consistent admission fields',()=>{
    expect(validateStartupStatus(normal)).toEqual(normal);
    expect(validateStartupStatus(safeStartupStatus())).toEqual(safeStartupStatus());
    expect(validateStartupStatus({...normal,mode:'safe',code:'STARTUP_CRASH_LOOP',failures:3,retryAllowed:true})).toMatchObject({mode:'safe',failures:3});
  });
  it('rejects a well-formed release version which differs from the current manifest',()=>{
    const [major,minor,patch]=packageJson.version.split('.');
    expect(()=>validateStartupStatus({...normal,appVersion:`${major}.${minor}.${Number(patch)+1}`})).toThrow('STARTUP_STATUS_UNAVAILABLE');
  });
  it.each([{schemaVersion:2},{mode:'other'},{code:'<script>'},{appVersion:'old'},{failures:4},{failures:-1},{failures:1.5},{attemptId:'bad'},{attemptId:null},{retryAllowed:true},{readyAfterMs:30001},{readyAfterMs:-1},{privatePayload:'not-exportable'}])('rejects malformed/future/oversized status %j',mutation=>{
    expect(()=>validateStartupStatus({...normal,...mutation})).toThrow('STARTUP_STATUS_UNAVAILABLE');
  });
  it.each([null,[],{},'secret',42])('rejects missing status %j',value=>{expect(()=>validateStartupStatus(value)).toThrow();});
  it('keeps invalid-journal recovery read-only and never fabricates an attempt token',()=>{
    const status=safeStartupStatus('STARTUP_GUARD_INVALID');expect(status.retryAllowed).toBe(false);expect(status.attemptId).toBeNull();
    expect(()=>validateStartupStatus({...status,retryAllowed:true})).toThrow();
  });
  it('uses only dedicated startup IPC; retry does not restart/admit/read user state',async()=>{
    const calls:Array<{command:string,args:unknown}>=[];
    const invoke=async<T,>(command:string,args?:Record<string,unknown>)=>{calls.push({command,args});return (command==='startup_status'?normal:undefined) as T;};
    const client=createStartupClient(invoke);
    expect(await client.read()).toEqual(normal);await client.admit(normal.attemptId);await client.ready(normal.attemptId);await client.retry(normal.attemptId);await client.exit();
    expect(calls.map(c=>c.command)).toEqual(['startup_status','startup_admit_app','startup_acknowledge_ready','startup_retry_next_launch','startup_exit']);
    expect(calls[3].args).toEqual({attemptId:normal.attemptId});
    expect(()=>client.admit('wrong')).toThrow();expect(calls).toHaveLength(5);
  });
  it('preserves transport failure and does not fall back to loading or migrating state',async()=>{
    const invoke=vi.fn().mockRejectedValue({code:'STARTUP_GUARD_WRITE_FAILED',message:'sensitive raw payload'});
    const client=createStartupClient(invoke);await expect(client.read()).rejects.toMatchObject({code:'STARTUP_GUARD_WRITE_FAILED'});expect(invoke).toHaveBeenCalledOnce();
    expect(startupErrorCode({code:'STARTUP_GUARD_WRITE_FAILED',message:'sensitive'})).toBe('STARTUP_GUARD_WRITE_FAILED');
    expect(startupErrorCode({code:'sensitive'})).toBe('STARTUP_OPERATION_FAILED');
    expect(startupErrorCode(Object.defineProperty({},'code',{get(){throw Error('secret');}}))).toBe('STARTUP_OPERATION_FAILED');
  });
  it('bounds a stalled status read; a late response never admits or hydrates the app',async()=>{
    vi.useFakeTimers();
    try{
      let resolve!:(value:unknown)=>void;
      const invoke=vi.fn(()=>new Promise<unknown>(done=>{resolve=done;}));
      const client=createStartupClient(invoke as Parameters<typeof createStartupClient>[0]);
      const read=expect(client.read()).rejects.toMatchObject({code:'STARTUP_STATUS_UNAVAILABLE'});
      await vi.advanceTimersByTimeAsync(5000);await read;resolve(normal);await Promise.resolve();
      expect(invoke.mock.calls).toEqual([['startup_status']]);expect(vi.getTimerCount()).toBe(0);
    }finally{vi.useRealTimers();}
  });
  it('clears the read deadline after success and leaves write completion truthful',async()=>{
    vi.useFakeTimers();
    try{
      let complete!:(value:void)=>void;
      const invoke=async<T,>(command:string)=>command==='startup_status'?normal as T:await new Promise<void>(done=>{complete=done;}) as T;
      const client=createStartupClient(invoke);expect(await client.read()).toEqual(normal);expect(vi.getTimerCount()).toBe(0);
      let completed=false;const write=client.admit(normal.attemptId).then(()=>{completed=true;});
      await vi.advanceTimersByTimeAsync(6000);expect(completed).toBe(false);complete();await write;expect(completed).toBe(true);
    }finally{vi.useRealTimers();}
  });
  it.each(['ru','en'] as const)('shows recovery controls and honest preservation/AV scope in %s',language=>{
    const markup=renderToStaticMarkup(<StartupRecoveryPanel status={safeStartupStatus('STARTUP_GUARD_INVALID')} language={language} onLanguage={()=>{}} onRetry={()=>{}} onExit={()=>{}}/>);
    expect(markup).toContain('STARTUP_GUARD_INVALID');expect(markup).toContain('disabled=""');expect(markup).toContain('AV/heap');
    expect(markup).toContain(language==='ru'?'не сбрасывались и не мигрировались':'were not reset or migrated');
    expect(markup).not.toContain('accessKey');expect(markup).not.toContain('client-state-v2');
  });
  it.each(['ru','en'] as const)('does not attest native startup actions when only the frontend fallback is available in %s',language=>{
    const markup=renderToStaticMarkup(<StartupRecoveryPanel status={safeStartupStatus()} language={language} onLanguage={()=>{}} onRetry={()=>{}} onExit={()=>{}}/>);
    expect(markup).toContain(language==='ru'?'Действия нативного запуска до получения статуса неизвестны':'Earlier native startup actions are unknown');
    expect(markup).not.toContain(language==='ru'?'не запускались в этом режиме':'were not started in this mode');
    expect(markup).not.toContain(language==='ru'?'не сбрасывались и не мигрировались':'were not reset or migrated');
  });
});
