import {it,expect} from 'vitest';
import {restoreConnectionPreferences} from '../src/utils/connectionPreferences';
import type {AppSettings} from '../src/types/vpn';
it('rolls back the applied requested mode despite an earlier stale ref',()=>{
  const old={tunnelMode:'proxy',ipStack:'ipv4'} as AppSettings;
  const requested={...old,tunnelMode:'tun'} as AppSettings;
  expect(restoreConnectionPreferences(requested,requested,{tunnelMode:'proxy'}).tunnelMode).toBe('proxy');
});
it('preserves newer mode/IP and unrelated preferences rather than replaying a captured object',()=>{
  const requested={tunnelMode:'tun',ipStack:'ipv6',language:'en'} as AppSettings;
  const current={...requested,tunnelMode:'proxy',language:'ru'} as AppSettings;
  expect(restoreConnectionPreferences(current,requested,{tunnelMode:'tun',ipStack:'ipv4'})).toMatchObject({tunnelMode:'proxy',ipStack:'ipv4',language:'ru'});
});
