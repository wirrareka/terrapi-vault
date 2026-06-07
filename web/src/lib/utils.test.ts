import { describe, expect, it } from "vitest";
import { untilExpiry, fmtUnix } from "./utils";

describe("untilExpiry", () => {
  it("reports expired when past", () => {
    expect(untilExpiry(100, 200)).toBe("expired");
    expect(untilExpiry(100, 100)).toBe("expired");
  });
  it("formats minutes-only under an hour", () => {
    expect(untilExpiry(1000 + 5 * 60, 1000)).toBe("in 5m");
  });
  it("formats hours and minutes", () => {
    expect(untilExpiry(1000 + 2 * 3600 + 5 * 60, 1000)).toBe("in 2h 5m");
  });
});

describe("fmtUnix", () => {
  it("renders a non-empty local datetime string", () => {
    expect(fmtUnix(1_700_000_000).length).toBeGreaterThan(0);
  });
});
