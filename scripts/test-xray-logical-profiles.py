"""Bounded loopback-only Xray profile integration; never changes Windows proxy/routes.

Input is the synthetic auto-proxy.json emitted by Rust tests with
VKARMANI_CONFIG_CORPUS_OUTPUT. Only processes launched by this script are stopped.
"""
import argparse
import copy
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def http_target(label):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = label.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def wait_port(child, port):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("owned Xray exited before ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.025)
    raise TimeoutError("owned Xray port did not become ready")


def stop_owned(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()  # Popen handle belongs to this harness, never name-wide.
            child.wait(timeout=3)


def run(core, corpus, report):
    core = core.resolve(strict=True)
    manifest = json.loads((core.parent / "core-manifest.json").read_text(encoding="utf-8-sig"))
    record = next(item for item in manifest["files"] if item["file"] == core.name)
    digest = hashlib.sha256(core.read_bytes()).hexdigest()
    if core.stat().st_size != record["size"] or digest != record["sha256"]:
        raise RuntimeError("bundled core manifest mismatch")
    template = json.loads(corpus.read_text(encoding="utf-8"))
    if any(item.get("protocol") == "tun" for item in template.get("inbounds", [])):
        raise RuntimeError("TUN corpus is forbidden in loopback-only harness")
    if [item.get("tag") for item in template.get("outbounds", [])[:3]] != ["pool-a", "pool-b", "direct"] or "observatory" in template:
        raise RuntimeError("expected the synthetic Rust Auto corpus, never production config")
    directory = Path(tempfile.mkdtemp(prefix="vkarmani-logical-profiles-"))
    children, logs, targets, cases = [], [], [], []
    started = time.monotonic()
    result = {"status": "FAIL", "scope": "owned loopback Xray processes only; no native app/Windows network lifecycle", "core_sha256": digest, "artifacts": str(directory), "cases": cases}

    def launch(config, name, ready_port):
        path = directory / f"{name}.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        # Reject accidental external listeners before launching any process.
        if any(item.get("listen") != "127.0.0.1" for item in config["inbounds"]):
            raise RuntimeError("non-loopback listener")
        log = (directory / f"{name}.log").open("wb")
        logs.append(log)
        child = subprocess.Popen([str(core), "run", "-c", str(path)], cwd=core.parent, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        children.append(child)
        wait_port(child, ready_port)
        return child

    def request(port):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            connection.request("GET", "http://127.0.0.1:9/synthetic-test", headers={"Connection": "close"})
            response = connection.getresponse()
            body = response.read(1024).decode()
            if response.status != 200:
                raise RuntimeError(f"test proxy HTTP status {response.status}")
            return body
        finally:
            connection.close()

    try:
        ports, nodes = {}, {}
        credential = "123e4567-e89b-12d3-a456-426614174000"
        for label in ["A", "B"]:
            server, thread = http_target(label)
            targets.append((server, thread))
            port = free_port()
            ports[label] = port
            # Xray's default VLESS server private-IP block is deliberately
            # relaxed only inside this loopback fixture with a fixed owned
            # destination. No application/provider security setting changes.
            config = {"log": {"loglevel": "debug"}, "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": {"clients": [{"id": credential}], "decryption": "none"}}], "outbounds": [{"protocol": "freedom", "settings": {"redirect": f"127.0.0.1:{server.server_port}", "ipsBlocked": []}}]}
            nodes[label] = launch(config, f"member-{label}", port)
        for index, label in enumerate(["A", "B"]):
            outbound = template["outbounds"][index]
            outbound.update({"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": ports[label], "users": [{"id": credential, "encryption": "none"}]}]}, "streamSettings": {"network": "tcp", "security": "none"}})
        template["dns"] = {"servers": ["localhost"]}
        template["burstObservatory"]["pingConfig"] = {"destination": "http://127.0.0.1:9/probe", "connectivity": "http://127.0.0.1:9/probe", "interval": "1s", "sampling": 1, "timeout": "1s"}
        # Synthetic request/probe destination is port 9; member servers redirect
        # it exclusively to owned loopback HTTP responders above.
        main_port = None
        for inbound in template["inbounds"]:
            inbound["port"] = free_port()
            if inbound["protocol"] == "http": main_port = inbound["port"]
        if main_port is None: raise RuntimeError("missing HTTP client adapter")
        template["log"] = {"loglevel": "debug", "access": "none"}
        fallback = copy.deepcopy(template)
        fallback["routing"]["balancers"][0]["selector"] = ["no-such-member-"]
        fallback_port = None
        for inbound in fallback["inbounds"]:
            inbound["port"] = free_port()
            if inbound["protocol"] == "http": fallback_port = inbound["port"]
        fallback_child = launch(fallback, "fallback", fallback_port)
        if request(fallback_port) != "B": raise RuntimeError("fallbackTag did not select B")
        cases.append({"case": "empty selected pool uses fallbackTag", "status": "PASS"})
        stop_owned(fallback_child)
        auto_child = launch(template, "auto", main_port)
        seen = {request(main_port) for _ in range(5)}
        if not seen <= {"A", "B"}: raise RuntimeError("Auto did not use an owned member")
        cases.append({"case": "Auto Proxy full graph", "status": "PASS", "members_observed": sorted(seen)})
        stop_owned(nodes["B"])
        deadline = time.monotonic() + 8
        while True:
            try:
                if request(main_port) == "A": break
            except (OSError, http.client.HTTPException, RuntimeError): pass
            if time.monotonic() >= deadline: raise RuntimeError("Auto did not recover with unavailable B")
            time.sleep(0.05)
        cases.append({"case": "Auto with unavailable member", "status": "PASS"})
        stop_owned(auto_child)
        normal = copy.deepcopy(template)
        normal.pop("burstObservatory", None)
        normal["routing"].pop("balancers", None)
        for rule in normal["routing"]["rules"]:
            if rule.pop("balancerTag", None) is not None: rule["outboundTag"] = "pool-a"
        normal_child = launch(normal, "normal", main_port)
        if request(main_port) != "A": raise RuntimeError("Auto -> normal wrong target")
        cases.append({"case": "Auto -> normal exact target", "status": "PASS"})
        stop_owned(normal_child)
        replacement = launch(template, "auto-reconnect", main_port)
        if request(main_port) != "A": raise RuntimeError("normal -> Auto wrong target")
        cases.append({"case": "normal -> Auto / reconnect", "status": "PASS"})
        replacement.kill()  # Deliberate exact owned-child crash injection.
        replacement.wait(timeout=3)
        replacement = launch(template, "auto-after-crash", main_port)
        # A ready listener is not a ready leastLoad health observation. B is
        # deliberately offline, so cold-start fallback may fail before A's
        # first burst observation. Measure bounded recovery, not instant success.
        recovery_started = time.monotonic()
        deadline = recovery_started + 8
        initial_failures = 0
        while True:
            try:
                if request(main_port) == "A": break
            except (OSError, http.client.HTTPException, RuntimeError): initial_failures += 1
            if time.monotonic() >= deadline: raise RuntimeError("Auto after crash did not recover within bound")
            time.sleep(0.025)
        cases.append({"case": "Auto after owned Xray crash", "status": "PASS", "initial_request_failures": initial_failures, "recovery_seconds": round(time.monotonic() - recovery_started, 3)})
        result["status"] = "PASS"
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        for child in reversed(children): stop_owned(child)
        for log in logs: log.close()
        for server, thread in targets:
            server.shutdown(); server.server_close(); thread.join(timeout=2)
        result.update({"duration_seconds": round(time.monotonic() - started, 3), "owned_pids": [child.pid for child in children], "cleanup": "PASS" if all(child.poll() is not None for child in children) and all(not thread.is_alive() for _, thread in targets) else "FAIL"})
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))
    return 0 if result["status"] == "PASS" and result["cleanup"] == "PASS" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    raise SystemExit(run(args.core, args.corpus, args.report))
