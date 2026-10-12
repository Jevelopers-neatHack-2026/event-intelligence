import test from "node:test";
import { scenario } from "./scenario.mjs";

for (const mode of ["network-current", "network-captured", "network-lookup", "network-url", "subprocess", "file-read", "file-read-swallowed", "file-write"]) {
  test("cooperative Python I/O guard and actual child recovery: " + mode, (t) => scenario(mode, t));
}
