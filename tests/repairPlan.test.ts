import {describe,it,expect,vi} from 'vitest';
import {confirmRepairPlan,validateRepairPlan} from '../src/utils/repairPlan';
const plan={id:'a'.repeat(48),expiresAfterMs:30000,restoreProxy:true,removeRouteCount:4};
describe('Explicit repair preview and consent boundary',()=>{
  it('executes only the exact prepared plan after explicit confirmation',async()=>{
    const calls:string[]=[];
    expect(await confirmRepairPlan(async()=>{calls.push('prepare');return plan;},value=>{calls.push('confirm');expect(value).toEqual(plan);return true;},async id=>{calls.push(id);return true;})).toBe('completed');
    expect(calls).toEqual(['prepare','confirm',plan.id]);
  });
  it('cancelled or superseded consent cannot mutate anything',async()=>{
    const execute=vi.fn();const confirm=vi.fn(()=>true);
    expect(await confirmRepairPlan(async()=>plan,()=>false,execute)).toBe('cancelled');
    expect(await confirmRepairPlan(async()=>plan,confirm,execute,()=>false)).toBe('cancelled');
    let mounted=true;expect(await confirmRepairPlan(async()=>plan,()=>{mounted=false;return true;},execute,()=>mounted)).toBe('cancelled');
    expect(execute).not.toHaveBeenCalled();expect(confirm).not.toHaveBeenCalled();
  });
  it.each([null,[],{}, {...plan,id:'foreign'}, {...plan,removeRouteCount:5}, {...plan,removeRouteCount:-1}, {...plan,removeRouteCount:1.5},{...plan,expiresAfterMs:0},{...plan,expiresAfterMs:30001},{...plan,privateData:'not-exportable'}])('rejects malformed native plans before confirmation or mutation %j',async raw=>{
    expect(()=>validateRepairPlan(raw)).toThrow('REPAIR_PLAN_INVALID');const confirm=vi.fn();const execute=vi.fn();
    await expect(confirmRepairPlan(async()=>raw as typeof plan,confirm,execute)).rejects.toThrow();expect(confirm).not.toHaveBeenCalled();expect(execute).not.toHaveBeenCalled();
  });
  it('does not claim success or retry a rejected/partially completed write',async()=>{
    expect(await confirmRepairPlan(async()=>plan,()=>true,async()=>false)).toBe('unconfirmed');
    const execute=vi.fn().mockRejectedValue(Error('REPAIR_PARTIAL_ROUTES_UNCONFIRMED'));
    await expect(confirmRepairPlan(async()=>plan,()=>true,execute)).rejects.toThrow('REPAIR_PARTIAL');expect(execute).toHaveBeenCalledOnce();
  });
});
