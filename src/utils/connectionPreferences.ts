import type {AppSettings} from '../types/vpn';
/** Run against React's actual queued state, not a ref from a previous effect.
 * Preserve preferences changed after this request was captured. */
export function restoreConnectionPreferences(current:AppSettings,requested:AppSettings,rollback:Partial<AppSettings>):AppSettings{
  const patch=Object.fromEntries(Object.entries(rollback).filter(([key])=>current[key as keyof AppSettings]===requested[key as keyof AppSettings]));
  return {...current,...patch};
}
