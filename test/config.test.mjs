import assert from "node:assert/strict";
import { test } from "node:test";
import { accessPattern, grantOrigin, grantedHosts, parsePort } from "../extension/config.js";

test("access is asked per https origin, port included; anything else is refused", () => {
  assert.equal(accessPattern(new URL("https://ci.example.com/job/x?y=1")), "https://ci.example.com/*");
  assert.equal(accessPattern(new URL("https://ci.example.com:8443/x")), "https://ci.example.com:8443/*");
  assert.equal(accessPattern(new URL("http://ci.example.com/x")), null);
  assert.equal(accessPattern(new URL("ftp://ci.example.com/x")), null);
});

test("the grant page only accepts a bare https origin", () => {
  assert.equal(grantOrigin("?origin=https%3A%2F%2Fci.example.com"), "https://ci.example.com");
  assert.equal(grantOrigin("?origin=https%3A%2F%2Fci.example.com%3A8443"), "https://ci.example.com:8443");
  for (const bad of [
    "",
    "?origin=",
    "?origin=http%3A%2F%2Fci.example.com",
    "?origin=https%3A%2F%2Fci.example.com%2Fpath",
    "?origin=https%3A%2F%2Fuser%40ci.example.com",
    "?origin=javascript%3Aalert(1)",
    "?origin=https%3A%2F%2FCI.example.com",
  ]) {
    assert.equal(grantOrigin(bad), null, bad);
  }
});

test("granted hosts are listed without scheme or path, skipping non-https grants", () => {
  assert.deepEqual(
    grantedHosts(["https://zz.example.com/*", "http://127.0.0.1/*", "https://*.example.org/*", "https://a.example.com:8443/*"]),
    ["*.example.org", "a.example.com:8443", "zz.example.com"],
  );
});

test("port field: empty is the default, otherwise a high port", () => {
  assert.equal(parsePort(""), 8731);
  assert.equal(parsePort(" 9000 "), 9000);
  for (const bad of ["80", "70000", "abc", "1.5"]) assert.throws(() => parsePort(bad), /Port/);
});
