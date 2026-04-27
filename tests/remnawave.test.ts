import { describe, expect, it } from 'vitest';
import { __remnawaveTest } from '../src/services/remnawave';

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
  });

  it('parses Hysteria2 aliases and IPv6 hosts', () => {
    const [server] = __remnawaveTest.parseSubscriptionToServers(
      'hysteria2://secret@[2001:4860:4860::8888]:8443?peer=hy2.example.com&obfs_type=salamander&obfsPassword=obfs-pass#HY2%20IPv6'
    );

    expect(server?.runtimeTemplate?.protocol).toBe('hysteria2');
    expect(server?.host).toBe('2001:4860:4860::8888');
    expect(JSON.stringify(server?.runtimeTemplate?.outbound)).toContain('obfs-pass');
  });

  it('rejects malformed and invalid-port links', () => {
    expect(__remnawaveTest.parseSubscriptionToServers('not-a-link')).toHaveLength(0);
    expect(__remnawaveTest.parsePort('70000', 443)).toBe(443);
  });
});
