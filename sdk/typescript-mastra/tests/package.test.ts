import { describe, expect, it } from "vitest";

import { __version__ } from "../src/index.js";

describe("@neuronedge/enclave-mastra package", () => {
  it("exports its version", () => {
    expect(__version__).toBe("0.1.0");
  });
});
