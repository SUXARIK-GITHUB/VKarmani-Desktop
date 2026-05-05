import { describe, expect, it } from 'vitest';
import { __remnawaveTest } from '../src/services/remnawave';
import { rankServersForDisplay } from '../src/utils/serverSorting';
import { normalizeRoutingDomainInput, normalizeRoutingIpInput, sanitizeRoutingExclusions } from '../src/utils/routingExclusions';
import type { VpnServer } from '../src/types/vpn';

const uuid = '123e4567-e89b-12d3-a456-426614174000';

describe('Remnawave Xray JSON profile parser', () => {
  it('builds only Xray JSON profile endpoint candidates', () => {
    const candidates = __remnawaveTest.buildXrayJsonUrlCandidates('https://sub.vkarmani.com/1NJDc37GHnsdRnvX', '1NJDc37GHnsdRnvX');

    expect(candidates).toEqual([
      'https://sub.vkarmani.com/api/sub/1NJDc37GHnsdRnvX/json',
      'https://sub.vkarmani.com/api/subscriptions/by-short-uuid/1NJDc37GHnsdRnvX/json',
      'https://sub.vkarmani.com/1NJDc37GHnsdRnvX/json'
    ]);
    expect(candidates.every((url) => url.endsWith('/json'))).toBe(true);
  });

  it('uses a single Xray JSON profile identity during production sync', () => {
    expect(__remnawaveTest.XRAY_JSON_SUBSCRIPTION_PROFILE.name).toBe('Xray JSON');
    expect(__remnawaveTest.XRAY_JSON_SUBSCRIPTION_PROFILE.accept).toContain('application/json');
    expect(__remnawaveTest.XRAY_JSON_SUBSCRIPTION_PROFILE.userAgent).toContain('Xray/');
    expect(__remnawaveTest.XRAY_JSON_SUBSCRIPTION_PROFILE.userAgent).toContain('VKarmani-Desktop');
  });

  it('parses standard Xray JSON config arrays', () => {
    const payload = [
      {
        remarks: 'VKarmani Smart / RU Moscow',
        outbounds: [
          {
            tag: 'proxy',
            protocol: 'vless',
            settings: {
              vnext: [{ address: 'smart-ru.example.com', port: 443, users: [{ id: uuid, encryption: 'none' }] }]
            },
            streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: 'smart-ru.example.com' } }
          },
          { tag: 'direct', protocol: 'freedom' }
        ]
      },
      {
        remarks: 'Netherland | All',
        outbounds: [
          {
            tag: 'proxy',
            protocol: 'trojan',
            settings: { servers: [{ address: 'nl.example.com', port: 443, password: 'secret' }] },
            streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: 'nl.example.com' } }
          }
        ]
      }
    ];

    const servers = __remnawaveTest.parseXrayJsonSubscriptionToServers(JSON.stringify(payload));

    expect(servers.map((server) => server.rawLabel)).toEqual(['VKarmani Smart / RU Moscow', 'Netherland | All']);
    expect(servers[0].runtimeTemplate?.protocol).toBe('vless');
    expect(servers[1].runtimeTemplate?.protocol).toBe('trojan');
  });

  it('rejects non-JSON profile bodies in the production parser', () => {
    expect(__remnawaveTest.parseXrayJsonSubscriptionToServers('vless://id@example.com:443#OldTextFormat')).toHaveLength(0);
    expect(__remnawaveTest.parseXrayJsonSubscriptionToServers('not a json document')).toHaveLength(0);
  });

  it('does not collapse a top-level Xray JSON profile with multiple proxy outbounds to one server', () => {
    const payload = {
      remarks: 'VKarmani Xray JSON full profile',
      outbounds: [
        {
          tag: 'RU Moscow',
          protocol: 'vless',
          settings: {
            vnext: [{ address: 'ru.example.com', port: 443, users: [{ id: uuid, encryption: 'none' }] }]
          },
          streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: 'ru.example.com' } }
        },
        {
          tag: 'NL Amsterdam',
          protocol: 'vless',
          settings: {
            vnext: [{ address: 'nl.example.com', port: 443, users: [{ id: uuid, encryption: 'none' }] }]
          },
          streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: 'nl.example.com' } }
        },
        { tag: 'direct', protocol: 'freedom' },
        { tag: 'block', protocol: 'blackhole' }
      ]
    };

    const servers = __remnawaveTest.parseXrayJsonSubscriptionToServers(JSON.stringify(payload));

    expect(servers).toHaveLength(2);
    expect(servers.map((server) => server.host)).toEqual(['ru.example.com', 'nl.example.com']);
    expect(servers.map((server) => server.rawLabel)).toEqual(['RU Moscow', 'NL Amsterdam']);
  });

  it('keeps top-level Xray JSON config remarks instead of showing generic proxy labels', () => {
    const payload = {
      remarks: 'Single Xray JSON Node',
      outbounds: [
        {
          tag: 'proxy',
          protocol: 'vless',
          settings: {
            vnext: [{ address: 'single-xray.example.com', port: 443, users: [{ id: uuid, encryption: 'none' }] }]
          },
          streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: 'single-xray.example.com' } }
        },
        { tag: 'direct', protocol: 'freedom' }
      ]
    };

    const [server] = __remnawaveTest.parseXrayJsonSubscriptionToServers(JSON.stringify(payload));

    expect(server?.rawLabel).toBe('Single Xray JSON Node');
    expect(server?.host).toBe('single-xray.example.com');
    expect(server?.runtimeTemplate?.protocol).toBe('vless');
  });


  it('keeps full Xray JSON config on single cascade profiles so native can preserve routing rules', () => {
    const payload = {
      remarks: 'Cascade With Rules',
      dns: { servers: ['https+local://1.1.1.1/dns-query'] },
      routing: {
        rules: [
          { domain: ['domain:example.org'], outboundTag: 'direct', type: 'field' }
        ]
      },
      outbounds: [
        {
          tag: 'cascade-proxy',
          protocol: 'vless',
          settings: {
            vnext: [{ address: 'cascade.example.com', port: 443, users: [{ id: uuid, encryption: 'none' }] }]
          },
          streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: 'cascade.example.com' } }
        },
        { tag: 'direct', protocol: 'freedom' }
      ]
    };

    const [server] = __remnawaveTest.parseXrayJsonSubscriptionToServers(JSON.stringify(payload));

    expect(server?.runtimeTemplate?.primaryOutboundTag).toBe('cascade-proxy');
    expect(server?.runtimeTemplate?.fullConfig?.routing).toEqual(payload.routing);
    expect(server?.runtimeTemplate?.fullConfig?.dns).toEqual(payload.dns);
  });

  it('uses Remnawave structured display names inside Xray JSON payloads', () => {
    const payload = {
      response: {
        rawHosts: [
          {
            protocol: 'vless',
            host: 'smart-ru.example.com',
            port: 443,
            uuid,
            security: 'tls',
            serverDescription: 'VKarmani Smart / RU Moscow',
            rawInbound: { remark: 'Poland | No ADS' }
          },
          {
            protocol: 'vless',
            host: 'nl.example.com',
            port: 443,
            uuid,
            security: 'tls',
            name: 'Netherland | All'
          }
        ]
      }
    };

    const servers = __remnawaveTest.parseXrayJsonSubscriptionToServers(JSON.stringify(payload));

    expect(servers.map((server) => server.rawLabel)).toEqual(['VKarmani Smart / RU Moscow', 'Netherland | All']);
    expect(servers[0].country).toBe('VKarmani Smart / RU Moscow');
    expect(servers[0].countryCode).toBe('PL');
  });

  it('hides backend cascade members when a public aggregate is present in Xray JSON', () => {
    const host = (name: string, label: string) => ({
      protocol: 'vless',
      host: `${name}.example.com`,
      port: 443,
      uuid,
      security: 'tls',
      serverDescription: label
    });
    const payload = {
      response: {
        rawHosts: [
          host('pl-public', 'Poland | No ADS'),
          host('pl-s1', 'Poland S1 | mallard'),
          host('pl-s2', 'Poland S2 | badger'),
          host('se-public', 'Sweden S1 | All')
        ]
      }
    };

    const servers = __remnawaveTest.parseXrayJsonSubscriptionToServers(JSON.stringify(payload));

    expect(servers.map((server) => server.rawLabel)).toEqual(['Poland | No ADS', 'Sweden S1 | All']);
    expect(servers.some((server) => /mallard|badger/i.test(server.rawLabel ?? ''))).toBe(false);
  });


  it('hides raw backend codenames BADGER and MALLARD when user-facing cascade servers exist', () => {
    const host = (name: string, label: string) => ({
      protocol: 'vless',
      host: `${name}.pl.example.com`,
      port: 443,
      uuid,
      security: 'tls',
      serverDescription: label
    });
    const payload = {
      response: {
        rawHosts: [
          host('pl-public', 'Poland | No ADS'),
          host('pl-badger', 'BADGER'),
          host('pl-mallard', 'MALLARD'),
          host('se-public', 'Sweden S1 | All')
        ]
      }
    };

    const servers = __remnawaveTest.parseXrayJsonSubscriptionToServers(JSON.stringify(payload));

    expect(servers.map((server) => server.rawLabel)).toEqual(['Poland | No ADS', 'Sweden S1 | All']);
    expect(servers.some((server) => /badger|mallard/i.test(server.rawLabel ?? ''))).toBe(false);
  });


  it('hides BADGER and MALLARD composite Xray JSON configs from the user-facing server list', () => {
    const outbound = (tag: string, host: string) => ({
      tag,
      protocol: 'vless',
      settings: {
        vnext: [{ address: host, port: 443, users: [{ id: uuid, encryption: 'none' }] }]
      },
      streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: host } }
    });
    const singleConfig = (remarks: string, host: string) => ({
      remarks,
      outbounds: [outbound('proxy', host), { tag: 'direct', protocol: 'freedom' }]
    });
    const payload = [
      singleConfig('🇵🇱 VKarmani Smart | MSK', 'smart.pl.example.com'),
      singleConfig('Germany | All', 'de.example.com'),
      singleConfig('Netherland | All', 'nl.example.com'),
      singleConfig('France | All', 'fr.example.com'),
      singleConfig('Sweden | All', 'se.example.com'),
      singleConfig('United States | All', 'us.example.com'),
      singleConfig('United Kingdom | All', 'uk.example.com'),
      singleConfig('BADGER | VLESS | RAW', 'badger.pl.example.com'),
      singleConfig('MALLARD | VLESS | RAW', 'mallard.pl.example.com')
    ];

    const servers = __remnawaveTest.parseXrayJsonSubscriptionToServers(JSON.stringify(payload));

    expect(servers).toHaveLength(7);
    expect(servers.map((server) => server.rawLabel)).toEqual([
      '🇵🇱 VKarmani Smart | MSK',
      'Germany | All',
      'Netherland | All',
      'France | All',
      'Sweden | All',
      'United States | All',
      'United Kingdom | All'
    ]);
    expect(servers.some((server) => /badger|mallard/i.test(`${server.rawLabel ?? ''} ${server.country} ${server.host ?? ''}`))).toBe(false);
  });


  it('prefers a user-facing Smart cascade full config over raw BADGER/MALLARD backend members', () => {
    const backendHost = (name: string, label: string) => ({
      protocol: 'vless',
      host: `${name}.pl.example.com`,
      port: 443,
      uuid,
      security: 'tls',
      serverDescription: label
    });
    const outbound = (tag: string, host: string) => ({
      tag,
      protocol: 'vless',
      settings: {
        vnext: [{ address: host, port: 443, users: [{ id: uuid, encryption: 'none' }] }]
      },
      streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: host } }
    });
    const payload = {
      response: {
        rawHosts: [
          backendHost('badger', 'BADGER'),
          backendHost('mallard', 'MALLARD')
        ],
        config: {
          remarks: '🇵🇱 VKarmani Smart | MSK',
          dns: { servers: ['1.1.1.1'] },
          routing: {
            domainStrategy: 'AsIs',
            rules: [
              { type: 'field', domain: ['domain:vk.com'], outboundTag: 'BADGER' },
              { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' }
            ]
          },
          outbounds: [
            outbound('BADGER', 'badger.pl.example.com'),
            outbound('MALLARD', 'mallard.pl.example.com'),
            { tag: 'direct', protocol: 'freedom' }
          ]
        }
      }
    };

    const servers = __remnawaveTest.parseXrayJsonSubscriptionToServers(JSON.stringify(payload));

    expect(servers.map((server) => server.rawLabel)).toEqual(['🇵🇱 VKarmani Smart | MSK']);
    expect(servers.some((server) => /badger|mallard/i.test(server.rawLabel ?? ''))).toBe(false);
    expect(servers[0]?.runtimeTemplate?.primaryOutboundTag).toBe('BADGER');
    expect(servers[0]?.runtimeTemplate?.fullConfig?.routing).toEqual(payload.response.config.routing);
    expect(servers[0]?.runtimeTemplate?.fullConfig?.dns).toEqual(payload.response.config.dns);
  });


  it('keeps previous full profile when Remnawave temporarily returns only one ready config', () => {
    const makeServer = (id: string): VpnServer => ({
      id,
      country: id,
      city: 'Node',
      flag: '🌐',
      load: 0,
      protocol: 'Xray',
      runtimeTemplate: {
        family: 'xray',
        protocol: 'vless',
        outbound: { protocol: 'vless', settings: {} }
      }
    });

    expect(__remnawaveTest.shouldKeepPreviousFullProfile([makeServer('a'), makeServer('b')], [makeServer('a')])).toBe(true);
    expect(__remnawaveTest.shouldKeepPreviousFullProfile([makeServer('a'), makeServer('b')], [makeServer('a'), makeServer('c')])).toBe(false);
  });

  it('keeps server ids stable when Xray JSON config order changes', () => {
    const config = (label: string, host: string) => ({
      remarks: label,
      outbounds: [
        {
          tag: 'proxy',
          protocol: 'vless',
          settings: {
            vnext: [{ address: host, port: 443, users: [{ id: uuid, encryption: 'none' }] }]
          },
          streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: host } }
        }
      ]
    });

    const original = __remnawaveTest.parseXrayJsonSubscriptionToServers(JSON.stringify([
      config('First', 'first.example.com'),
      config('Second', 'second.example.com')
    ]));
    const reordered = __remnawaveTest.parseXrayJsonSubscriptionToServers(JSON.stringify([
      config('Second', 'second.example.com'),
      config('First', 'first.example.com')
    ]));

    expect(original.find((server) => server.host === 'first.example.com')?.id)
      .toBe(reordered.find((server) => server.host === 'first.example.com')?.id);
    expect(original.find((server) => server.host === 'second.example.com')?.id)
      .toBe(reordered.find((server) => server.host === 'second.example.com')?.id);
  });
});


describe('Server display ranking', () => {
  function server(id: string, latency: number | null, latencyStatus: VpnServer['latencyStatus'] = 'ok'): VpnServer {
    return {
      id,
      country: id.toUpperCase(),
      city: 'Node',
      flag: '🌐',
      latency,
      latencyStatus,
      load: 0,
      protocol: 'Xray',
      runtimeTemplate: {
        family: 'xray',
        protocol: 'vless',
        transport: 'tcp',
        outbound: {}
      }
    };
  }

  it('keeps favorite servers first and sorts the rest by best successful ping', () => {
    const ranked = rankServersForDisplay([
      server('slow', 180),
      server('favorite', 500),
      server('failed', null, 'failed'),
      server('fast', 25),
      server('unchecked', null, 'unchecked')
    ], 'auto', ['favorite']);

    expect(ranked.map((item) => item.id)).toEqual(['favorite', 'fast', 'slow', 'unchecked', 'failed']);
  });

  it('sorts all servers by best successful ping when there is no favorite server', () => {
    const ranked = rankServersForDisplay([
      server('middle', 80),
      server('fast', 15),
      server('slow', 140)
    ], 'auto');

    expect(ranked.map((item) => item.id)).toEqual(['fast', 'middle', 'slow']);
  });
});


describe('Routing exclusions settings', () => {
  it('normalizes user domains and IPv4 CIDR rules safely', () => {
    expect(normalizeRoutingDomainInput('https://Example.RU/path')).toBe('example.ru');
    expect(normalizeRoutingDomainInput('*.bank.ru')).toBe('.bank.ru');
    expect(normalizeRoutingDomainInput('домен.рф')).toBe('xn--d1acufc.xn--p1ai');
    expect(normalizeRoutingDomainInput('bad_domain.local')).toBeNull();
    expect(normalizeRoutingIpInput('1.2.3.4')).toBe('1.2.3.4');
    expect(normalizeRoutingIpInput('5.6.7.0/24')).toBe('5.6.7.0/24');
    expect(normalizeRoutingIpInput('5.6.7.0/33')).toBeNull();
  });

  it('deduplicates and keeps stored routing exclusions backward-compatible', () => {
    const normalized = sanitizeRoutingExclusions({
      enabled: true,
      bypassRuDomains: true,
      domains: ['Example.ru', 'example.ru', 'https://ya.ru/search'],
      ips: ['1.2.3.4', '1.2.3.4', 'bad']
    });

    expect(normalized.enabled).toBe(true);
    expect(normalized.bypassSuDomains).toBe(true);
    expect(normalized.domains).toEqual(['example.ru', 'ya.ru']);
    expect(normalized.ips).toEqual(['1.2.3.4']);
  });
});
