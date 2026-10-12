import assert from "node:assert/strict";
import test from "node:test";
import { scenario } from "./scenario.mjs";

const modes = ["valid", "dimensions", "format", "mode", "frames", "source", "pixel-hash", "pixels",
  "runtime", "wheel", "python", "protocol", "extra", "duplicate", "invalid-utf8", "bom", "truncated", "tail",
  "header-cap", "output-cap", "stderr-cap", "stderr", "nonzero", "rejection-payload", "network"];
for (const mode of modes) {
  test("synthetic framed child response with actual process closure: " + mode, (t) => {
    const { result } = scenario("frame-" + mode, t);
    if (mode === "valid") assert.equal(result.kind, "decoded");
    else {
      assert.equal(result.kind, "rejected");
      const code = ["output-cap", "stderr-cap"].includes(mode) ? "OUTPUT_LIMIT" :
        ["stderr", "nonzero"].includes(mode) ? "DECODER_FAILURE" : mode === "network" ? "REMOTE_RESOURCE_ATTEMPT" : "PROTOCOL_ERROR";
      assert.equal(result.code, code);
      assert.equal(result.copyNormalizedBytes, undefined); assert.equal(result.rgbaSha256, undefined);
    }
  });
}
