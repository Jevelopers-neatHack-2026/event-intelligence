import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { request as namedRequest } from "node:http";
import { installPngNetworkGuard } from "../../../src/extraction/png/network-guard.mjs";

const require = createRequire(import.meta.url);
const guard = installPngNetworkGuard();
const exercised = [];
function deny(name, operation, code) {
  let caught;
  try { operation(); } catch (error) { caught = error; }
  assert.equal(caught?.code, code, name + " must reject before an operation can occur.");
  assert.equal(String(caught).includes("private-png-marker"), false);
  exercised.push({ name, code: caught.code });
}
// Invalid destinations/arguments ensure a broken guard cannot make a real request.
for (const [name, operation] of [
  ["http.request", () => require("node:http").request("not a URL")],
  ["http.get", () => require("node:http").get("not a URL")],
  ["http.ClientRequest", () => new (require("node:http").ClientRequest)("not a URL")],
  ["named ESM http.request", () => namedRequest("not a URL")],
  ["https.request", () => require("node:https").request("not a URL")],
  ["https.get", () => require("node:https").get("not a URL")],
  ["http2.connect", () => require("node:http2").connect("not a URL")],
  ["net.connect", () => require("node:net").connect({ port: -1 })],
  ["net.createConnection", () => require("node:net").createConnection({ port: -1 })],
  ["net.Socket.connect", () => require("node:net").Socket.prototype.connect.call({}, { port: -1 })],
  ["net.Server.listen", () => require("node:net").Server.prototype.listen.call({}, -1)],
  ["tls.connect", () => require("node:tls").connect({ port: -1 })],
  ["dgram.createSocket", () => require("node:dgram").createSocket("invalid socket type")],
  ["dgram.Socket.send", () => require("node:dgram").Socket.prototype.send.call({})],
  ["dgram.Socket.bind", () => require("node:dgram").Socket.prototype.bind.call({})],
  ["dns.lookup", () => require("node:dns").lookup({})],
  ["dns.resolve4", () => require("node:dns").resolve4({})],
  ["dns.Resolver.resolveTxt", () => require("node:dns").Resolver.prototype.resolveTxt.call({}, {})],
  ["dns.promises.lookup", () => require("node:dns/promises").lookup({})],
  ["dns.promises.Resolver.resolveAny", () => require("node:dns/promises").Resolver.prototype.resolveAny.call({}, {})],
  ["fetch", () => globalThis.fetch("not a URL")],
  ["WebSocket", () => new globalThis.WebSocket("not a URL")],
]) deny(name, operation, "PNG_NETWORK_API_DENIED");
assert.equal(guard.attemptCount, 22);

deny("read outside worker/fixture allowlist",
  () => require("node:fs").readFileSync("/no-such-private-png-marker"), "ERR_ACCESS_DENIED");
deny("write file", () => require("node:fs").writeFileSync("/tmp/private-png-marker-" + process.pid, "synthetic"), "ERR_ACCESS_DENIED");
deny("spawn child", () => require("node:child_process").spawnSync(process.execPath, ["-e", "0"]), "ERR_ACCESS_DENIED");
deny("start worker thread", () => new (require("node:worker_threads").Worker)("0", { eval: true }), "ERR_ACCESS_DENIED");
deny("load native addon", () => process.dlopen({ exports: {} }, "/no-such-private-png-marker.node"), "ERR_DLOPEN_DISABLED");
process.stdout.write(JSON.stringify({
  mode: "synthetic invalid-argument API denial and actual Node permission operations",
  networkApiAttemptCount: guard.attemptCount, exercised,
  nativeEgressOrHostContainmentAttested: false,
}) + "\n");
