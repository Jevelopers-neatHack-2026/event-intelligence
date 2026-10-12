import test from "node:test";
import { scenario } from "./scenario.mjs";

for (const mode of ["active-cancel", "active-timeout", "queue-timeout", "queue-late", "saturation",
  "pre-spawn-timeout", "pre-spawn-cancel", "return-timeout", "return-cancel",
  "normalized-timeout", "normalized-cancel", "spawn-throw", "exit", "cpu", "memory", "fd", "abi"]) {
  test("real child lifecycle and fresh recovery: " + mode, (t) => scenario(mode, t));
}
