import { describe, expect, it } from 'vitest';
import { __remnawaveTest } from '../src/services/remnawave';
import { rankServersForDisplay } from '../src/utils/serverSorting';
import { normalizeRoutingDomainInput, normalizeRoutingIpInput, sanitizeRoutingExclusions } from '../src/utils/routingExclusions';
import type { VpnServer } from '../src/types/vpn';

const uuid = '123e4567-e89b-12d3-a456-426614174000';

function base64Url(value: string) {
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

describe('Remnawave subscription parser', () => {
  it('parses VLESS Reality links', () => {
    const [server] = __remnawaveTest.parseSubscriptionToServers(
      `vless://${uuid}@reality.example.com:443?security=reality&sni=reality.example.com&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp#NL%20Reality`
    );

    expect(server?.runtimeTemplate?.protocol).toBe('vless');
    expect(server?.host).toBe('reality.example.com');
    expect(server?.port).toBe(443);
    expect(JSON.stringify(server?.runtimeTemplate?.outbound)).toContain('realitySettings');
  });

  it('parses VLESS WebSocket TLS links', () => {
    const [server] = __remnawaveTest.parseSubscriptionToServers(
      `vless://${uuid}@ws.example.com:8443?security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws#US%20WS`
    );

    expect(server?.runtimeTemplate?.protocol).toBe('vless');
    expect(server?.runtimeTemplate?.transport).toBe('ws');
    expect(JSON.stringify(server?.runtimeTemplate?.outbound)).toContain('/ws');
  });

  it('parses UUIDv7 VLESS links from base64 Remnawave subscriptions', () => {
    const uuidV7 = '01890f3a-a123-7abc-b456-426614174000';
    const raw = `vless://${uuidV7}@uuid7.example.com:443?security=reality&sni=uuid7.example.com&fp=chrome&pbk=PUBKEY&sid=abcd&type=tcp#FI%20UUIDv7`;
    const [server] = __remnawaveTest.parseSubscriptionToServers(btoa(raw));

    expect(server?.runtimeTemplate?.protocol).toBe('vless');
    expect(server?.host).toBe('uuid7.example.com');
    expect(JSON.stringify(server?.runtimeTemplate?.outbound)).toContain('realitySettings');
  });

  it('parses base64 encoded Xray JSON template without confusing it with raw URI base64', () => {
    const raw = JSON.stringify({
      outbounds: [
        {
          tag: 'FI Xray JSON Base64',
          protocol: 'vless',
          settings: {
            vnext: [
              {
                address: 'xray-json-base64.example.com',
                port: 443,
                users: [{ id: uuid, encryption: 'none' }]
              }
            ]
          },
          streamSettings: {
            network: 'grpc',
            security: 'reality',
            realitySettings: { serverName: 'xray-json-base64.example.com', publicKey: 'PUBKEY', shortId: 'abcd' },
            grpcSettings: { serviceName: 'grpc' }
          }
        }
      ]
    });

    const [server] = __remnawaveTest.parseSubscriptionToServers(btoa(raw));

    expect(server?.runtimeTemplate?.protocol).toBe('vless');
    expect(server?.runtimeTemplate?.transport).toBe('grpc');
    expect(server?.host).toBe('xray-json-base64.example.com');
    expect(JSON.stringify(server?.runtimeTemplate?.outbound)).toContain('realitySettings');
  });

  it('parses Xray JSON template outbounds from Remnawave templates', () => {
    const raw = JSON.stringify({
      outbounds: [
        {
          tag: 'DE Xray JSON',
          protocol: 'vless',
          settings: {
            vnext: [
              {
                address: 'xray-json.example.com',
                port: 443,
                users: [{ id: uuid, encryption: 'none' }]
              }
            ]
          },
          streamSettings: {
            network: 'ws',
            security: 'tls',
            tlsSettings: { serverName: 'xray-json.example.com' },
            wsSettings: { path: '/ws' }
          }
        }
      ]
    });

    const [server] = __remnawaveTest.parseSubscriptionToServers(raw);

    expect(server?.runtimeTemplate?.protocol).toBe('vless');
    expect(server?.runtimeTemplate?.transport).toBe('ws');
    expect(server?.host).toBe('xray-json.example.com');
  });

  it('parses Sing-box JSON template outbounds from Remnawave templates', () => {
    const raw = JSON.stringify({
      outbounds: [
        {
          type: 'vless',
          tag: 'NL Singbox',
          server: 'singbox-template.example.com',
          server_port: 443,
          uuid,
          tls: { enabled: true, server_name: 'singbox-template.example.com', utls: { fingerprint: 'chrome' } },
          transport: { type: 'ws', path: '/ws', headers: { Host: 'singbox-template.example.com' } }
        }
      ]
    });

    const [server] = __remnawaveTest.parseSubscriptionToServers(raw);

    expect(server?.runtimeTemplate?.protocol).toBe('vless');
    expect(server?.runtimeTemplate?.transport).toBe('ws');
    expect(server?.host).toBe('singbox-template.example.com');
  });

  it('parses Mihomo/Clash YAML template proxies from Remnawave templates', () => {
    const raw = `proxies:
  - name: US Clash
    type: vless
    server: clash-template.example.com
    port: 443
    uuid: ${uuid}
    tls: true
    servername: clash-template.example.com
    client-fingerprint: chrome
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: clash-template.example.com
`;

    const [server] = __remnawaveTest.parseSubscriptionToServers(raw);

    expect(server?.runtimeTemplate?.protocol).toBe('vless');
    expect(server?.runtimeTemplate?.transport).toBe('ws');
    expect(server?.host).toBe('clash-template.example.com');
  });

  it('keeps subscription server labels after pipe separators', () => {
    const [server] = __remnawaveTest.parseSubscriptionToServers(
      `vless://${uuid}@pl-adguard.example.com:443?security=tls&sni=pl-adguard.example.com&type=tcp#Poland%20%7C%20AdGuard`
    );

    expect(server?.rawLabel).toBe('Poland | AdGuard');
    expect(server?.country).toBe('Poland | AdGuard');
    expect(server?.city).toBe('');
    expect(server?.countryCode).toBe('PL');
  });

  it('parses VMess links from base64url subscriptions', () => {
    const vmessPayload = btoa(JSON.stringify({
      v: '2',
      ps: 'DE VMess',
      add: 'vmess.example.com',
      port: 443,
      id: uuid,
      aid: 0,
      net: 'ws',
      type: 'none',
      host: 'vmess.example.com',
      path: '/ray',
      tls: 'tls',
      sni: 'vmess.example.com'
    }));

    const subscription = base64Url(`vmess://${vmessPayload}`);
    const [server] = __remnawaveTest.parseSubscriptionToServers(subscription);

    expect(server?.runtimeTemplate?.protocol).toBe('vmess');
    expect(server?.host).toBe('vmess.example.com');
    expect(server?.port).toBe(443);
  });


  it('parses VMess payload encoded as base64url without padding', () => {
    const vmessPayload = base64Url(JSON.stringify({
      v: '2',
      ps: 'NL VMess URL-safe',
      add: 'vmess-ipv6.example.com',
      port: '8443',
      id: uuid,
      aid: '0',
      net: 'tcp',
      type: 'none',
      tls: 'tls',
      sni: 'vmess-ipv6.example.com'
    }));

    const [server] = __remnawaveTest.parseSubscriptionToServers(`vmess://${vmessPayload}`);

    expect(server?.runtimeTemplate?.protocol).toBe('vmess');
    expect(server?.host).toBe('vmess-ipv6.example.com');
    expect(server?.port).toBe(8443);
  });

  it('parses Trojan links', () => {
    const [server] = __remnawaveTest.parseSubscriptionToServers(
      'trojan://secret@example.net:443?security=tls&sni=example.net&type=tcp#Trojan'
    );

    expect(server?.runtimeTemplate?.protocol).toBe('trojan');
    expect(server?.host).toBe('example.net');
    expect(server?.port).toBe(443);
  });

  it('parses Shadowsocks IPv4 and IPv6 endpoints', () => {
    const ipv4 = 'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzQDEuMi4zLjQ6ODM4OA#SS%20IPv4';
    const ipv6 = 'ss://chacha20-ietf-poly1305:pass@[2001:4860:4860::8888]:8388#SS%20IPv6';
    const servers = __remnawaveTest.parseSubscriptionToServers(`${ipv4}\n${ipv6}`);

    expect(servers).toHaveLength(2);
    expect(servers[0].host).toBe('1.2.3.4');
    expect(servers[0].port).toBe(8388);
    expect(servers[1].host).toBe('2001:4860:4860::8888');
    expect(servers[1].port).toBe(8388);
  });

  it('parses VLESS XHTTP links', () => {
    const [server] = __remnawaveTest.parseSubscriptionToServers(
      `vless://${uuid}@xhttp.example.com:443?security=tls&sni=xhttp.example.com&type=xhttp&host=cdn.example.com&path=%2Fxhttp&mode=auto#US%20XHTTP`
    );

    expect(server?.runtimeTemplate?.protocol).toBe('vless');
    expect(server?.runtimeTemplate?.transport).toBe('xhttp');
    expect(JSON.stringify(server?.runtimeTemplate?.outbound)).toContain('xhttpSettings');
  });

  it('parses VLESS XHTTP aliases and extra JSON', () => {
    const extra = encodeURIComponent(JSON.stringify({ scMaxEachPostBytes: 65536 }));
    const [server] = __remnawaveTest.parseSubscriptionToServers(
      `vless://${uuid}@xhttp-extra.example.com:443?security=tls&sni=xhttp-extra.example.com&type=splithttp&authority=cdn.example.com&pathPrefix=%2Fxhttp&mode=packet-up&extra=${extra}#US%20XHTTP%20Extra`
    );

    const outbound = JSON.stringify(server?.runtimeTemplate?.outbound);
    expect(server?.runtimeTemplate?.transport).toBe('xhttp');
    expect(outbound).toContain('xhttpSettings');
    expect(outbound).toContain('scMaxEachPostBytes');
  });

  it('parses Hysteria2 links', () => {
    const [server] = __remnawaveTest.parseSubscriptionToServers(
      'hy2://secret@hy2.example.com:443?sni=hy2.example.com&obfs=salamander&obfs-password=obfs-pass#NL%20HY2'
    );

    expect(server?.protocol).toBe('Hysteria2');
    expect(server?.runtimeTemplate?.protocol).toBe('hysteria2');
    expect(server?.host).toBe('hy2.example.com');
    expect(server?.port).toBe(443);
    const outbound = server?.runtimeTemplate?.outbound as Record<string, unknown>;
    expect(outbound.protocol).toBe('hysteria');
    expect(JSON.stringify(outbound)).toContain('"version":2');
    expect(JSON.stringify(outbound)).toContain('hysteriaSettings');
    expect(JSON.stringify(outbound)).toContain('udpmasks');
  });

  it('parses Hysteria2 aliases and IPv6 hosts', () => {
    const [server] = __remnawaveTest.parseSubscriptionToServers(
      'hysteria2://secret@[2001:4860:4860::8888]:8443?peer=hy2.example.com&obfs_type=salamander&obfsPassword=obfs-pass#HY2%20IPv6'
    );

    expect(server?.runtimeTemplate?.protocol).toBe('hysteria2');
    expect(server?.host).toBe('2001:4860:4860::8888');
    expect(JSON.stringify(server?.runtimeTemplate?.outbound)).toContain('obfs-pass');
    expect(JSON.stringify(server?.runtimeTemplate?.outbound)).toContain('"network":"hysteria"');
  });

  it('rejects malformed and invalid-port links', () => {
    expect(__remnawaveTest.parseSubscriptionToServers('not-a-link')).toHaveLength(0);
    expect(__remnawaveTest.parsePort('70000', 443)).toBe(443);
  });

  it('keeps server ids stable when subscription order changes', () => {
    const first = `vless://${uuid}@first.example.com:443?security=tls&sni=first.example.com&type=tcp#NL%20First`;
    const second = `trojan://secret@second.example.com:443?security=tls&sni=second.example.com&type=tcp#US%20Second`;

    const original = __remnawaveTest.parseSubscriptionToServers(`${first}\n${second}`);
    const reordered = __remnawaveTest.parseSubscriptionToServers(`${second}\n${first}`);

    expect(original.find((server) => server.host === 'first.example.com')?.id)
      .toBe(reordered.find((server) => server.host === 'first.example.com')?.id);
    expect(original.find((server) => server.host === 'second.example.com')?.id)
      .toBe(reordered.find((server) => server.host === 'second.example.com')?.id);
  });


  it('adds hidden unique suffixes only when subscription ids collide', () => {
    const base = `vless://${uuid}@same.example.com:443?security=tls&sni=same.example.com&type=tcp`;
    const servers = __remnawaveTest.parseSubscriptionToServers(`${base}#US%20One\n${base}#NL%20Two`);

    expect(servers).toHaveLength(2);
    expect(new Set(servers.map((server) => server.id)).size).toBe(2);
    expect(servers[0].id.startsWith('subscription-')).toBe(true);
    expect(servers[1].id.startsWith('subscription-')).toBe(true);
  });

  it('rejects incomplete VLESS, Reality, VMess, Trojan, Shadowsocks and Hysteria2 links', () => {
    const invalidLinks = [
      'vless://not-a-uuid@broken.example.com:443?security=tls#Broken',
      `vless://${uuid}@reality-broken.example.com:443?security=reality&sni=reality-broken.example.com#RealityNoPublicKey`,
      `vless://${uuid}@bad-port.example.com:70000?security=tls#BadPort`,
      `vmess://${base64Url(JSON.stringify({ v: '2', ps: 'No host', port: 443, id: uuid, net: 'tcp' }))}`,
      `vmess://${base64Url(JSON.stringify({ v: '2', ps: 'Bad UUID', add: 'vmess.example.com', port: 443, id: 'bad', net: 'tcp' }))}`,
      'trojan://@trojan.example.com:443?security=tls#NoPassword',
      'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ@ss.example.com:8388#NoPassword',
      'hy2://@hy2.example.com:443?sni=hy2.example.com#NoPassword'
    ];

    expect(__remnawaveTest.parseSubscriptionToServers(invalidLinks.join('\n'))).toHaveLength(0);
  });

  it('decodes UTF-8 base64 subscription labels without mojibake', () => {
    const utf8Subscription = `vless://${uuid}@utf8.example.com:443?security=tls&sni=utf8.example.com&type=tcp#🇫🇮%20Хельсинки`;
    const encoded = btoa(unescape(encodeURIComponent(utf8Subscription)));

    const [server] = __remnawaveTest.parseSubscriptionToServers(encoded);

    expect(server?.host).toBe('utf8.example.com');
    expect(server?.rawLabel).toContain('Хельсинки');
  });

  it('caps imported subscription servers and ignores oversized URIs', () => {
    const manyServers = Array.from({ length: 1105 }, (_, index) =>
      `vless://${uuid}@node-${index}.example.com:443?security=tls&sni=node-${index}.example.com&type=tcp#Node-${index}`
    );
    const oversized = `vless://${uuid}@oversized.example.com:443?security=tls&sni=oversized.example.com&type=tcp#${'x'.repeat(9000)}`;
    const servers = __remnawaveTest.parseSubscriptionToServers([...manyServers, oversized].join('\n'));

    expect(servers).toHaveLength(1000);
    expect(servers.some((server) => server.host === 'oversized.example.com')).toBe(false);
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
