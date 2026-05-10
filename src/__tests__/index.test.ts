import { describe, it, expect } from "vitest";
import { VERSION } from "../index.js";

describe("ossguard-npm", () => {
  it("should export VERSION", () => {
    expect(VERSION).toBeDefined();
    expect(typeof VERSION).toBe("string");
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});
