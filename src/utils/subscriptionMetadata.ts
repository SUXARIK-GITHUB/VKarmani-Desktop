import type { RemnawaveSession } from '../types/vpn';
import type { RemoteSubscriptionResponse } from '../services/runtime';

type Userinfo = RemoteSubscriptionResponse['userinfo'];
const keys = ['upload','download','total','expire'] as const;
const decimal = (value: unknown): value is string => typeof value === 'string' && /^\d{1,20}$/.test(value) && BigInt(value) <= 18446744073709551615n;

export function parseSubscriptionUserinfo(header: string | null): Userinfo {
  const result: Userinfo = {upload:null,download:null,total:null,expire:null};
  if (header === null) return result;
  if (header.length > 2048) throw Error('SUBSCRIPTION_USERINFO_INVALID');
  for (const part of header.split(';').map(value=>value.trim()).filter(Boolean)) {
    const separator = part.indexOf('=');
    if (separator < 0) throw Error('SUBSCRIPTION_USERINFO_INVALID');
    const name = part.slice(0,separator).trim();
    if (!keys.includes(name as typeof keys[number])) continue;
    const key = name as typeof keys[number], value = part.slice(separator+1).trim();
    if (!decimal(value) || result[key] !== null) throw Error('SUBSCRIPTION_USERINFO_INVALID');
    result[key] = BigInt(value).toString();
  }
  return result;
}

export function withSubscriptionUserinfo(session: RemnawaveSession, userinfo: Userinfo, now = Date.now()): RemnawaveSession {
  if (!userinfo || keys.some(key=>userinfo[key] !== null && !decimal(userinfo[key]))) throw Error('SUBSCRIPTION_USERINFO_INVALID');
  const {upload,download,total,expire} = userinfo;
  if (expire !== null && expire !== '0' && BigInt(expire)*1000n <= BigInt(Math.floor(now))) throw Error('SUBSCRIPTION_EXPIRED');
  const milliseconds = expire !== null && BigInt(expire) <= 8640000000000n ? Number(expire)*1000 : null;
  const used = upload !== null && download !== null ? BigInt(upload)+BigInt(download) : null;
  return {...session,plan:{...session.plan,
    uploadBytes:upload, downloadBytes:download, totalBytes:total, expiresAtUnix:expire,
    trafficUsedGb:used === null ? null : Number(used)/1073741824,
    trafficLimitGb:total === null ? null : Number(total)/1073741824,
    expiresAt:milliseconds && expire !== '0' ? new Date(milliseconds).toISOString() : '—'
  }};
}
