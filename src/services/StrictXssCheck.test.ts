import { describe, it, expect } from "vitest";
import { isStrictXssReflection } from "@/services/StrictXssCheck";

describe("XSS reflection regression — must stay strict before enterprise launch", () => {
  it("does NOT flag benign q= search reflection (the historical false positive)", () => {
    const body = `<html><body><h1>Search results for: hello</h1></body></html>`;
    expect(isStrictXssReflection(body, "hello")).toBe(false);
  });

  it("does NOT flag HTML-entity-escaped reflection", () => {
    const payload = `<script>alert(1)</script>`;
    const body = `<p>You searched: &lt;script&gt;alert(1)&lt;/script&gt;</p>`;
    expect(isStrictXssReflection(body, payload)).toBe(false);
  });

  it("does NOT flag reflection inside a quoted attribute when payload has no quote-breaker", () => {
    const body = `<input value="hello-world" />`;
    expect(isStrictXssReflection(body, "hello-world")).toBe(false);
  });

  it("FLAGS an unescaped <svg/onload=> reflection", () => {
    const payload = `<svg/onload=cyberscope1>`;
    const body = `<div>${payload}</div>`;
    expect(isStrictXssReflection(body, payload)).toBe(true);
  });

  it("FLAGS attribute-break payload with embedded quote", () => {
    const payload = `"><img src=x onerror=cyberscope>`;
    const body = `<input value="${payload}">`;
    expect(isStrictXssReflection(body, payload)).toBe(true);
  });

  it("does NOT flag when payload is missing from body entirely", () => {
    expect(isStrictXssReflection(`<p>nothing here</p>`, `<script>x</script>`)).toBe(false);
  });
});
