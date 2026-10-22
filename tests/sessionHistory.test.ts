import {describe,expect,it} from 'vitest';
import {historyRecords,MAX_SESSION_HISTORY,recoverSessionHistory,validateSessionHistory,type SessionHistoryEntry} from '../src/utils/sessionHistory';
const entry:SessionHistoryEntry={id:'a'.repeat(32),startedAtMs:'0',durationSeconds:3661,mode:'tun',status:'current'};
describe('R35 bounded credential-free history schema',()=>{
  it('roundtrips only fixed fields and human-readable values without fabricating traffic',()=>{
    expect(validateSessionHistory([entry])).toEqual([entry]);
    expect(historyRecords([entry])[0]).toMatchObject({serverLabel:'TUN',durationLabel:'1:01:01',transferredGb:null,startedAt:'1970-01-01T00:00:00.000Z'});
  });
  it('keeps an unconfirmed previous end distinct from successful completion',()=>{
    expect(recoverSessionHistory([entry])[0].status).toBe('interrupted');
    expect(recoverSessionHistory([{...entry,status:'completed'}])[0].status).toBe('completed');
    expect(entry.status).toBe('current');
  });
  it.each(['accessKey','subscriptionUrl','host','serverLabel','runtimeTemplate','error','extra'])('rejects %s rather than persisting untrusted data',key=>{
    expect(()=>validateSessionHistory([{...entry,[key]:'synthetic-sensitive'}])).toThrow('SESSION_HISTORY_INVALID');
  });
  it.each([{durationSeconds:-1},{durationSeconds:0.5},{durationSeconds:315360001},{startedAtMs:'01'},{startedAtMs:'8640000000000001'},{mode:'unknown'},{status:'failed'},{id:'secret'}])('rejects malformed entry %j',patch=>{
    expect(()=>validateSessionHistory([{...entry,...patch}])).toThrow('SESSION_HISTORY_INVALID');
  });
  it('enforces unique IDs and exact 128-row bounds',()=>{
    const rows=Array.from({length:MAX_SESSION_HISTORY},(_,i)=>({...entry,id:i.toString(16).padStart(32,'0')}));
    expect(validateSessionHistory(rows)).toHaveLength(128);
    expect(()=>validateSessionHistory([...rows,{...entry}])).toThrow();
    expect(()=>validateSessionHistory([entry,entry])).toThrow();
  });
});
