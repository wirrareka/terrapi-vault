import { describe, expect, it } from "vitest";
import { mockGet } from "./mock";
import type { Broker, LeasesResponse } from "./types";

describe("mockGet", () => {
  it("serves the broker list", () => {
    expect(mockGet<Broker[]>("/brokers").length).toBe(2);
  });
  it("serves broker-tagged observe data", () => {
    const r = mockGet<LeasesResponse>("/observe/leases");
    expect(r.leases.length).toBeGreaterThan(0);
    expect(r.leases.every((l) => typeof l.broker === "string")).toBe(true);
  });
  it("ignores the query string", () => {
    expect(mockGet("/observe/audit?since=0&limit=10")).toBeTruthy();
  });
  it("throws on an unknown route", () => {
    expect(() => mockGet("/nope")).toThrow();
  });
});
