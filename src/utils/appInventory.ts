import type { RunningAppInfo, WindowsServiceInfo } from '../types/vpn';
import { normalizeRuleValue } from './appPolicies';

export interface ApplicationChoice extends RunningAppInfo {
  identity: string;
  executable: string | null;
  processIds: number[];
}

export function applicationChoices(processes: RunningAppInfo[]): ApplicationChoice[] {
  const choices = new Map<string, ApplicationChoice>();
  for (const process of processes) {
    let executable: string | null = null;
    try {
      const value = normalizeRuleValue('app', process.path ?? '');
      if (/^[a-z]:\//i.test(value)) executable = value;
    } catch { /* Unreadable/unsupported paths must never become basename rules. */ }
    const identity = executable ? `path:${executable.toLowerCase()}` : `unavailable:${process.pid}:${process.name.toLowerCase()}`;
    const existing = choices.get(identity);
    if (existing) {
      if (!existing.processIds.includes(process.pid)) existing.processIds.push(process.pid);
      if (!existing.title && process.title) existing.title = process.title;
    } else choices.set(identity, { ...process, identity, executable, processIds: [process.pid] });
  }
  return [...choices.values()];
}

export function serviceChoices(services: WindowsServiceInfo[]): WindowsServiceInfo[] {
  const choices = new Map<string, WindowsServiceInfo>();
  for (const service of services) {
    const identity = service.name.trim().toLowerCase();
    if (!identity) continue;
    const previous = choices.get(identity);
    if (!previous) choices.set(identity, { ...service, name: service.name.trim() });
    else if (!service.supported || previous.exePath.replace(/\\/g, '/').toLowerCase() !== service.exePath.replace(/\\/g, '/').toLowerCase()) {
      choices.set(identity, { ...previous, supported: false, reason: 'SERVICE_IDENTITY_AMBIGUOUS' });
    }
  }
  return [...choices.values()];
}
