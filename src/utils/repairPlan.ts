export interface RuntimeRepairPlan { id:string; expiresAfterMs:number; restoreProxy:boolean; removeRouteCount:number }
export function validateRepairPlan(raw:unknown):RuntimeRepairPlan {
  if(!raw||typeof raw!=='object'||Array.isArray(raw))throw Error('REPAIR_PLAN_INVALID');
  const value=raw as Record<string,unknown>;
  if(Object.keys(value).sort().join(',')!=='expiresAfterMs,id,removeRouteCount,restoreProxy'
    ||typeof value.id!=='string'||!/^[a-f0-9]{48}$/i.test(value.id)
    ||typeof value.restoreProxy!=='boolean'||!Number.isInteger(value.removeRouteCount)||Number(value.removeRouteCount)<0||Number(value.removeRouteCount)>4
    ||!Number.isInteger(value.expiresAfterMs)||Number(value.expiresAfterMs)<=0||Number(value.expiresAfterMs)>30000)throw Error('REPAIR_PLAN_INVALID');
  return {id:value.id,expiresAfterMs:Number(value.expiresAfterMs),restoreProxy:value.restoreProxy,removeRouteCount:Number(value.removeRouteCount)};
}
/** Preparation is read-only. User cancellation or a late/stale preview never executes a repair. */
export async function confirmRepairPlan(
  prepare:()=>Promise<RuntimeRepairPlan>, confirm:(plan:RuntimeRepairPlan)=>boolean,
  execute:(id:string)=>Promise<boolean>, stillCurrent:()=>boolean=()=>true
):Promise<'cancelled'|'completed'|'unconfirmed'> {
  const plan=validateRepairPlan(await prepare());
  if(!stillCurrent()||!confirm(plan))return 'cancelled';
  if(!stillCurrent())return 'cancelled';
  return await execute(plan.id)?'completed':'unconfirmed';
}
