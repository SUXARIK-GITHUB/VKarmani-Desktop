import type { SessionRecord, TunnelMode } from '../types/vpn';

export const MAX_SESSION_HISTORY = 128;
export interface SessionHistoryEntry {
  id: string;
  startedAtMs: string;
  durationSeconds: number;
  mode: TunnelMode;
  status: SessionRecord['status'];
}
const fields=['id','startedAtMs','durationSeconds','mode','status'];
export function validateSessionHistory(value: unknown): SessionHistoryEntry[] {
  if (value === null || value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_SESSION_HISTORY) throw Error('SESSION_HISTORY_INVALID');
  const ids=new Set<string>();
  return value.map(item=>{
    if (!item || typeof item!=='object' || Object.keys(item).some(key=>!fields.includes(key))
      || typeof item.id!=='string' || !/^[a-f0-9]{32}$/.test(item.id) || ids.has(item.id)
      || typeof item.startedAtMs!=='string' || !/^(0|[1-9]\d{0,15})$/.test(item.startedAtMs) || BigInt(item.startedAtMs)>8640000000000000n
      || !Number.isInteger(item.durationSeconds) || item.durationSeconds<0 || item.durationSeconds>315360000
      || !['proxy','tun'].includes(item.mode) || !['current','completed','interrupted'].includes(item.status)) throw Error('SESSION_HISTORY_INVALID');
    ids.add(item.id);
    return {...item} as SessionHistoryEntry;
  });
}
export function recoverSessionHistory(value: unknown): SessionHistoryEntry[] {
  return validateSessionHistory(value).map(entry=>entry.status==='current'?{...entry,status:'interrupted'}:entry);
}
export function historyRecords(entries: SessionHistoryEntry[]): SessionRecord[] {
  return entries.map(entry=>({id:entry.id,startedAt:new Date(Number(entry.startedAtMs)).toISOString(),
    serverLabel:entry.mode==='tun'?'TUN':'Proxy',durationLabel:`${Math.floor(entry.durationSeconds/3600)}:${String(Math.floor(entry.durationSeconds%3600/60)).padStart(2,'0')}:${String(entry.durationSeconds%60).padStart(2,'0')}`,
    transferredGb:null,status:entry.status}));
}
