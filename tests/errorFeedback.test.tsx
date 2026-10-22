import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { createToast, mergeToastItems, toastDetails,redactToastTitle } from '../src/utils/toast';
import { confirmLogout } from '../src/utils/logoutConsent';
import { ToastViewport } from '../src/components/ToastViewport';
import type { ToastItem } from '../src/types/vpn';

describe('R43/R44 persistent bounded error feedback',()=>{
  it('preserves a fixed public long machine code through hook and copy redaction while arbitrary tokens stay private',()=>{
    const code='REPAIR_PARTIAL_ROUTES_UNCONFIRMED';
    const item=createToast(redactToastTitle(`${code}: https://sub.vkarmani.com/qa-synthetic-private-path`),'error');
    expect(item.code).toBe(code);expect(JSON.parse(toastDetails(item)).message).toContain(code);
    expect(toastDetails(item)).not.toContain('qa-synthetic-private-path');
    expect(redactToastTitle('Z'.repeat(48)+': private')).not.toContain('Z'.repeat(48));
    expect(redactToastTitle('REPAIR_FUTURE_'+ 'Z'.repeat(35)+': private')).not.toContain('Z'.repeat(35));
  });
  it('captures a machine code and timestamp while redacting messages before copy',()=>{
    const item=createToast('STATE_CONFLICT: https://sub.vkarmani.com/qa-synthetic-private-path','error');
    expect(item.code).toBe('STATE_CONFLICT');expect(Number.isFinite(Date.parse(item.createdAt!))).toBe(true);
    expect(toastDetails(item)).not.toContain('qa-synthetic-private-path');
    expect(toastDetails(item)).toContain('[redacted-key]');
  });
  it('routine notices cannot evict unresolved errors and repeated errors coalesce',()=>{
    const failure=createToast('Failed to save','error');let list=[failure];
    for(let i=0;i<100;i++)list=mergeToastItems(list,createToast('ok '+i,'success'));
    expect(list).toHaveLength(5);expect(list[0]).toBe(failure);
    list=mergeToastItems(list,createToast('Failed to save','error'));
    expect(list.filter(item=>item.tone==='error')).toHaveLength(1);
  });
  it('bounds adversarial distinct errors with an explicit omitted-count notice',()=>{
    let list:ToastItem[]=[];
    for(let i=0;i<100;i++)list=mergeToastItems(list,createToast('Failure '+i,'error'));
    expect(list).toHaveLength(16);expect(list[15]).toMatchObject({code:'ERROR_HISTORY_LIMIT',overflowCount:85});
    expect(JSON.parse(toastDetails(list[15])).omittedCount).toBe(85);
  });
  it.each(['ru','en'] as const)('renders escaped persistent error details/copy/dismiss in %s',language=>{
    const markup=renderToStaticMarkup(<ToastViewport items={[createToast('<img onerror=alert(1)>','error')]} language={language} onDismiss={()=>{}}/>);
    expect(markup).toContain('role="alert"');expect(markup).not.toContain('<img');
    expect(markup).toContain(language==='ru'?'Копировать подробности':'Copy details');expect(markup).toContain(language==='ru'?'Закрыть':'Dismiss');
    expect(markup).toContain('OPERATION_FAILED');
  });
});
describe('R45 explicit sign-out consent',()=>{
  it.each(['ru','en'] as const)('returns cancellation without invoking a destructive callback in %s',language=>{
    let prompts=0;
    expect(confirmLogout(language,message=>{prompts++;expect(message).toContain(language==='ru'?'VPN-подключение':'VPN connection');return false;})).toBe(false);
    expect(prompts).toBe(1);expect(confirmLogout(language,()=>true)).toBe(true);
  });
});
