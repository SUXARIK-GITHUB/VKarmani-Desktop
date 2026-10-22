import {describe,expect,it,vi} from 'vitest';
import {autostartStatusLabel,NativeOperationError,structuredNativeError} from '../src/utils/nativeErrors';
import {normalizeNativeError} from '../src/services/runtime';

describe('R12/R43 confirmed autostart and structured native failures',()=>{
  it.each(['ru','en'] as const)('keeps partial repair truthful and localized without raw backend data in %s',language=>{
    const error=structuredNativeError({code:'REPAIR_PARTIAL_ROUTES_UNCONFIRMED',category:'network',retryable:false,details:'private PAC'},'fallback',language)!;
    expect(error.code).toBe('REPAIR_PARTIAL_ROUTES_UNCONFIRMED');expect(error.retryable).toBe(false);expect(error.message).not.toContain('private');expect(error.message).toContain(language==='ru'?'не подтверждена':'not confirmed');
  });
  it.each(['ru','en'] as const)('uses a fixed localized code message instead of native private payload in %s',language=>{
    const error=structuredNativeError({code:'AUTOSTART_DELETE_FAILED',category:'startup',retryable:true,message:'raw private account path'},'fallback',language)!;
    expect(error).toBeInstanceOf(NativeOperationError);expect(error.code).toBe('AUTOSTART_DELETE_FAILED');expect(error.category).toBe('startup');expect(error.retryable).toBe(true);
    expect(error.message).toContain(language==='ru'?'не подтвердил':'did not confirm');expect(error.message).not.toContain('private');
  });
  it('preserves a valid unknown machine code with caller fallback, never arbitrary details',()=>{
    const error=structuredNativeError({code:'STATE_FUTURE_FAILURE',category:'storage',recoverable:true,secret:'not-for-ui'},'safe fallback','en')!;
    expect(error.message).toBe('STATE_FUTURE_FAILURE: safe fallback');expect(error.retryable).toBe(true);
    expect(structuredNativeError({code:'../../secret'},'fallback','en')).toBeNull();
    expect(structuredNativeError(Object.defineProperty({},'code',{get(){throw Error('private');}}),'fallback','en')).toBeNull();
  });
  it('opaque payload/toJSON and throwing accessors do not cross the runtime UI boundary',()=>{
    const toJSON=vi.fn(()=>({private:'not-for-ui'}));
    expect(normalizeNativeError({private:'not-for-ui',toJSON},'fallback').message).toBe('fallback');expect(toJSON).not.toHaveBeenCalled();
    expect(normalizeNativeError(Object.defineProperty({},'message',{get(){throw Error('private');}}),'fallback').message).toBe('fallback');
  });
  it('retains legacy explicit messages with redaction and a bounded traversal/size',()=>{
    expect(normalizeNativeError({cause:{message:'HTTP 503'}},'fallback').message).toBe('HTTP 503');
    expect(normalizeNativeError('x'.repeat(100000),'fallback').message).toBe('[redacted-token]');
    expect(normalizeNativeError('word '.repeat(20000),'fallback').message.length).toBeLessThanOrEqual(4096);
    let reads=0;const cycle:Record<string,unknown>={};Object.defineProperty(cycle,'message',{get(){reads++;return '';}});cycle.error=cycle;cycle.cause=cycle;cycle.errors=Array(100000).fill(cycle);
    expect(normalizeNativeError(cycle,'fallback').message).toBe('fallback');expect(reads).toBeLessThanOrEqual(128);
  });
  it.each(['ru','en'] as const)('does not describe pending/unconfirmed startup preference as enabled Windows truth in %s',language=>{
    expect(autostartStatusLabel('unconfirmed',language)).toContain(language==='ru'?'не подтверждено':'not confirmed');
    expect(autostartStatusLabel('pending',language)).not.toBe(autostartStatusLabel('enabled',language));
    expect(autostartStatusLabel('not-managed',language)).not.toBe(autostartStatusLabel('disabled',language));
  });
});


describe('TUN observation errors remain structured and private',()=>{
  it.each(['RUNTIME_CLEANUP_INCOMPLETE','NETWORK_BINDING_CHANGED','NETWORK_BINDING_UNCONFIRMED','ROUTE_INTERFACE_CHANGED','ROUTE_INTERFACE_UNAVAILABLE','ROUTE_JOURNAL_UNAVAILABLE','TUN_INTERFACE_NOT_READY','TUN_ROUTES_UNCONFIRMED','TUN_PROCESS_ENFORCEMENT_UNAVAILABLE'])('localizes %s without paths or system details',code=>{
    for(const language of ['ru','en'] as const){
      const error=structuredNativeError({code,category:'network',retryable:false,message:'PRIVATE-PATH',details:'PID123'},'fallback',language)!;
      expect(error.code).toBe(code);expect(error.message).not.toContain('fallback');expect(error.message).not.toContain('PRIVATE');expect(error.message).not.toContain('PID123');expect(error.retryable).toBe(false);
    }
  });
});
