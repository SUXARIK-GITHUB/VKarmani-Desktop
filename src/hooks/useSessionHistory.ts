import {useEffect,useRef,useState} from 'react';
import {loadSessionHistory,saveSessionHistory} from '../services/storage';
import {historyRecords,MAX_SESSION_HISTORY,recoverSessionHistory,type SessionHistoryEntry} from '../utils/sessionHistory';
import type {ConnectionState,TunnelMode} from '../types/vpn';

export function useSessionHistory(ready:boolean,connection:ConnectionState,mode:TunnelMode,onError:(error:unknown)=>void){
  const [entries,setEntries]=useState<SessionHistoryEntry[]>([]);
  const [loaded,setLoaded]=useState(false);
  const current=useRef<SessionHistoryEntry[]>([]);
  const active=useRef<{id:string;started:number}|null>(null);
  const previousConnection=useRef(connection);
  const errorHandler=useRef(onError);errorHandler.current=onError;
  useEffect(()=>{
    if(!ready){setLoaded(false);return;}
    let cancelled=false;
    void loadSessionHistory().then(value=>{
      if(cancelled)return;
      const owned=active.current ? current.current.find(entry=>entry.id===active.current?.id) : undefined;
      const recovered=recoverSessionHistory(value).filter(entry=>entry.id!==owned?.id);
      current.current=(owned?[owned,...recovered]:recovered).slice(0,MAX_SESSION_HISTORY);setEntries(current.current);setLoaded(true);
      if(value.some(entry=>entry.status==='current'))void saveSessionHistory(current.current).catch(error=>errorHandler.current(error));
    }).catch(error=>{if(!cancelled)errorHandler.current(error);});
    return()=>{cancelled=true;};
  },[ready]);
  useEffect(()=>{
    const priorConnection=previousConnection.current;previousConnection.current=connection;
    if(!loaded||!ready)return;
    const commit=(next:SessionHistoryEntry[])=>{
      current.current=next;setEntries(next);void saveSessionHistory(next).catch(error=>errorHandler.current(error));
    };
    if(connection==='connected'&&active.current&&current.current.find(entry=>entry.id===active.current?.id)?.mode!==mode){
      const {id,started}=active.current;active.current=null;
      commit(current.current.map(entry=>entry.id===id?{...entry,durationSeconds:Math.min(315360000,Math.max(0,Math.floor((performance.now()-started)/1000))),status:'completed'}:entry));
    }
    if(connection==='connected'&&!active.current){
      const bytes=crypto.getRandomValues(new Uint8Array(16));
      const id=Array.from(bytes,value=>value.toString(16).padStart(2,'0')).join('');
      active.current={id,started:performance.now()};
      commit([{id,startedAtMs:String(Date.now()),durationSeconds:0,mode,status:'current' as const},...current.current].slice(0,MAX_SESSION_HISTORY));
    }
    if(connection==='idle'&&active.current){
      const {id,started}=active.current;active.current=null;
      commit(current.current.map(entry=>entry.id===id?{...entry,durationSeconds:Math.min(315360000,Math.max(0,Math.floor((performance.now()-started)/1000))),status:priorConnection==='disconnecting'?'completed':'interrupted'}:entry));
    }
    if(!active.current)return;
    let ticks=0;
    const timer=window.setInterval(()=>{
      const record=active.current;if(!record)return;
      const next=current.current.map(entry=>entry.id===record.id?{...entry,durationSeconds:Math.min(315360000,Math.max(0,Math.floor((performance.now()-record.started)/1000)))}:entry);
      current.current=next;setEntries(next);
      // At most two periodic CAS writes/minute; start/stop writes remain immediate.
      if(++ticks%30===0)void saveSessionHistory(next).catch(error=>errorHandler.current(error));
    },1000);
    return()=>window.clearInterval(timer);
  },[ready,loaded,connection,mode]);
  return {records:historyRecords(entries),loaded};
}
