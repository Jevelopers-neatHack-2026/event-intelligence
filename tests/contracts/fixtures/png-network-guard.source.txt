// API interposition for this fixed child, not an OS firewall or hostile-code sandbox.
import { createRequire, syncBuiltinESMExports } from "node:module";

const require = createRequire(import.meta.url);

export function installPngNetworkGuard() {
  let attempts = 0;
  function deny() {
    attempts += 1;
    const error = new Error("PNG network API disabled");
    error.code = "PNG_NETWORK_API_DENIED";
    throw error;
  }
  function patch(target, keys) {
    for (const key of keys) {
      if (typeof target[key] === "function") target[key] = deny;
    }
  }
  const dnsMethods = ["lookup", "lookupService", "resolve", "resolve4", "resolve6",
    "resolveAny", "resolveCaa", "resolveCname", "resolveMx", "resolveNaptr",
    "resolveNs", "resolvePtr", "resolveSoa", "resolveSrv", "resolveTxt", "reverse"];
  for (const [name, methods] of [
    ["node:http", ["request", "get", "ClientRequest"]],
    ["node:https", ["request", "get"]],
    ["node:http2", ["connect"]],
    ["node:net", ["connect", "createConnection"]],
    ["node:tls", ["connect"]],
    ["node:dgram", ["createSocket"]],
    ["node:dns", dnsMethods],
    ["node:dns/promises", dnsMethods],
  ]) patch(require(name), methods);
  patch(require("node:net").Socket.prototype, ["connect"]);
  patch(require("node:net").Server.prototype, ["listen"]);
  patch(require("node:dgram").Socket.prototype, ["connect", "send", "bind"]);
  patch(require("node:dns").Resolver.prototype, dnsMethods);
  patch(require("node:dns/promises").Resolver.prototype, dnsMethods);
  globalThis.fetch = deny;
  globalThis.WebSocket = deny;
  syncBuiltinESMExports();
  return Object.freeze({ get attemptCount() { return attempts; } });
}
