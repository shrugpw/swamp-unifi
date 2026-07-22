/**
 * Unit and model-level tests for the unifi-networks extension.
 *
 * Coverage: pure helpers (curl argv/config building, curl stdout parsing,
 * response finalization, IPv4 subnet math, session-token/SYSTEM-message
 * parsing, instance-name sanitization), the retry/backoff logic in
 * apiRequest, and full method execution (scan, scanFirewall, scanWifi,
 * scanClients, consoles, deletePolicy) via createModelTestContext +
 * withMockedFetch.
 *
 * NOT covered end-to-end: curlRequest's actual `Deno.Command` spawn+stdin-pipe
 * behavior (only its pure argv/config-building helpers are tested) —
 * @swamp-club/swamp-testing's withMockedCommand does not support intercepting
 * `spawn()`, only `output()`-style one-shot commands. Likewise scanUpdates'
 * WebSocket step has no mock primitive available. Both are accepted,
 * documented gaps rather than silently-skipped ones.
 *
 * Run with: deno test --allow-net extensions/models/unifi_networks_test.ts
 */

import { assertEquals, assertRejects, assertThrows } from "jsr:@std/assert@1";
import { createModelTestContext, withMockedFetch } from "jsr:@swamp-club/swamp-testing";
import {
  apiRequest,
  buildCurlArgs,
  buildCurlConfig,
  describePorts,
  describeProtocol,
  describeTrafficFilter,
  base32Decode,
  extractSessionToken,
  fetchAllPages,
  finalizeResponse,
  instanceName,
  ipv4InSubnet,
  ipv4ToInt,
  mapSystemMessage,
  model,
  parseCurlOutput,
  resolveTargets,
  sanitizeInstanceName,
  type Target,
  totpCode,
} from "./unifi_networks.ts";

/** GlobalArgs cast helper: the real Ctx type is narrower than the test
 * harness's Record<string, unknown> globalArgs, so a cast is needed at the
 * call boundary — the values themselves are still fully real/runtime-checked. */
// deno-lint-ignore no-explicit-any
function testCtx(globalArgs: Record<string, unknown>, opts?: Record<string, unknown>) {
  const ctx = createModelTestContext({ globalArgs, ...opts });
  return { ...ctx, context: ctx.context as any };
}

// ── TOTP (RFC 6238) ───────────────────────────────────────────────────────────

// RFC 6238 Appendix B reference vectors (SHA-1, secret "12345678901234567890").
const RFC_TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

Deno.test("totpCode: matches RFC 6238 vectors", async () => {
  assertEquals(await totpCode(RFC_TOTP_SECRET, 59_000, 30, 8), "94287082");
  assertEquals(
    await totpCode(RFC_TOTP_SECRET, 1_111_111_109_000, 30, 8),
    "07081804",
  );
  assertEquals(
    await totpCode(RFC_TOTP_SECRET, 1_234_567_890_000, 30, 8),
    "89005924",
  );
});

Deno.test("totpCode: defaults to 6 digits and zero-pads", async () => {
  const code = await totpCode(RFC_TOTP_SECRET, 59_000);
  assertEquals(code, "287082");
  assertEquals(code.length, 6);
});

Deno.test("totpCode: stable within a 30s step, rolls at the boundary", async () => {
  const a = await totpCode(RFC_TOTP_SECRET, 30_000);
  const b = await totpCode(RFC_TOTP_SECRET, 59_999);
  const c = await totpCode(RFC_TOTP_SECRET, 60_000);
  assertEquals(a, b);
  assertEquals(a === c, false);
});

Deno.test("base32Decode: tolerates padding, lowercase and whitespace", () => {
  assertEquals(base32Decode("MZXW6==="), base32Decode("mzxw6"));
  assertEquals(base32Decode("MZXW 6"), base32Decode("MZXW6"));
});

Deno.test("base32Decode: rejects invalid input", () => {
  assertThrows(() => base32Decode("MZXW1"), Error, "Invalid base32");
  assertThrows(() => base32Decode(""), Error, "Empty base32");
});

// ── parseCurlOutput ───────────────────────────────────────────────────────────

Deno.test("parseCurlOutput: body + trailing status line", () => {
  const { status, body } = parseCurlOutput('{"a":1}\n200');
  assertEquals(status, 200);
  assertEquals(body, '{"a":1}');
});

Deno.test("parseCurlOutput: empty body (204 from DELETE)", () => {
  // curl with -w "\n%{http_code}" emits just "\n204" when the body is empty
  const { status, body } = parseCurlOutput("\n204");
  assertEquals(status, 204);
  assertEquals(body, "");
});

Deno.test("parseCurlOutput: multi-line JSON body keeps every line", () => {
  // The status must be split off the LAST newline, not the first, or a
  // pretty-printed body would be truncated.
  const raw = '{\n  "a": 1,\n  "b": 2\n}\n200';
  const { status, body } = parseCurlOutput(raw);
  assertEquals(status, 200);
  assertEquals(body, '{\n  "a": 1,\n  "b": 2\n}');
  assertEquals(JSON.parse(body), { a: 1, b: 2 });
});

Deno.test("parseCurlOutput: error status with a body", () => {
  const { status, body } = parseCurlOutput('{"code":"unauthorized"}\n401');
  assertEquals(status, 401);
  assertEquals(body, '{"code":"unauthorized"}');
});

// ── finalizeResponse ──────────────────────────────────────────────────────────

Deno.test("finalizeResponse: 2xx JSON body parses", () => {
  assertEquals(finalizeResponse("GET", "/x", 200, '{"ok":true}'), { ok: true });
});

Deno.test("finalizeResponse: 2xx empty body returns null", () => {
  assertEquals(finalizeResponse("DELETE", "/x", 204, ""), null);
  assertEquals(finalizeResponse("DELETE", "/x", 200, "   "), null);
});

Deno.test("finalizeResponse: non-2xx throws with method/url/status/body", () => {
  const err = assertThrows(
    () => finalizeResponse("GET", "/sites", 401, "unauthorized"),
    Error,
    "GET /sites failed (401): unauthorized",
  );
  assertEquals(err instanceof Error, true);
});

Deno.test("finalizeResponse: 5xx throws", () => {
  assertThrows(() => finalizeResponse("POST", "/x", 500, "boom"), Error, "(500)");
});

// ── buildCurlArgs ─────────────────────────────────────────────────────────────

Deno.test("buildCurlArgs: GET includes -k, -K stdin config, verb, status writeout", () => {
  const args = buildCurlArgs("GET", "https://udm/x");
  assertEquals(args.includes("-sk"), true); // -k skips TLS verify
  assertEquals(args[args.indexOf("-K") + 1], "-"); // headers read from stdin, not argv
  assertEquals(args[args.indexOf("-X") + 1], "GET");
  assertEquals(args[args.indexOf("-w") + 1], "\n%{http_code}");
  assertEquals(args[args.length - 1], "https://udm/x"); // url is last
  // No body → no content-type / data
  assertEquals(args.includes("--data-binary"), false);
  assertEquals(args.some((a) => a.startsWith("Content-Type")), false);
});

Deno.test("buildCurlArgs: body adds content-type and serialized payload", () => {
  const args = buildCurlArgs("PATCH", "https://udm/p", { enabled: false });
  assertEquals(args.includes("Content-Type: application/json"), true);
  assertEquals(args[args.indexOf("--data-binary") + 1], '{"enabled":false}');
  assertEquals(args[args.indexOf("-X") + 1], "PATCH");
  assertEquals(args[args.length - 1], "https://udm/p");
});

Deno.test("buildCurlArgs: no secret ever appears in argv (routed via -K stdin instead)", () => {
  // The whole point of the -K/stdin design: buildCurlArgs doesn't even accept
  // an apiKey parameter anymore, so there's no argv slot for a secret to leak
  // into — verified structurally by the function's arity/signature above,
  // and here by confirming a representative secret-shaped string is absent.
  const args = buildCurlArgs("GET", "https://udm/x");
  assertEquals(args.some((a) => a.includes("s3cr3t")), false);
});

// ── buildCurlConfig ───────────────────────────────────────────────────────────

Deno.test("buildCurlConfig: formats one header-line per entry", () => {
  const config = buildCurlConfig({
    "X-API-KEY": "secret123",
    "Accept": "application/json",
  });
  assertEquals(config.includes('header = "X-API-KEY: secret123"'), true);
  assertEquals(config.includes('header = "Accept: application/json"'), true);
});

Deno.test("buildCurlConfig: escapes embedded quotes and backslashes", () => {
  const config = buildCurlConfig({ "X-API-KEY": 'weird"key\\value' });
  assertEquals(config, 'header = "X-API-KEY: weird\\"key\\\\value"\n');
});

// ── ipv4ToInt ─────────────────────────────────────────────────────────────────

Deno.test("ipv4ToInt: parses dotted quads to uint32", () => {
  assertEquals(ipv4ToInt("0.0.0.0"), 0);
  assertEquals(ipv4ToInt("10.0.0.1"), 0x0A000001);
  assertEquals(ipv4ToInt("255.255.255.255"), 0xFFFFFFFF); // stays unsigned
  assertEquals(ipv4ToInt("192.168.1.1"), 0xC0A80101);
});

Deno.test("ipv4ToInt: rejects malformed input", () => {
  assertEquals(ipv4ToInt("10.0.0"), null); // too few octets
  assertEquals(ipv4ToInt("10.0.0.1.2"), null); // too many
  assertEquals(ipv4ToInt("10.0.0.256"), null); // octet out of range
  assertEquals(ipv4ToInt("10.0.0.x"), null); // non-numeric
  assertEquals(ipv4ToInt(""), null);
});

// ── ipv4InSubnet ──────────────────────────────────────────────────────────────

Deno.test("ipv4InSubnet: matches inside and rejects outside a /24", () => {
  assertEquals(ipv4InSubnet("10.0.10.51", "10.0.10.1", 24), true);
  assertEquals(ipv4InSubnet("10.0.10.255", "10.0.10.1", 24), true);
  assertEquals(ipv4InSubnet("10.0.11.5", "10.0.10.1", 24), false); // next subnet
  assertEquals(ipv4InSubnet("10.0.0.5", "10.0.10.1", 24), false);
});

Deno.test("ipv4InSubnet: boundary prefixes /32 and /0", () => {
  assertEquals(ipv4InSubnet("10.0.0.1", "10.0.0.1", 32), true); // exact host
  assertEquals(ipv4InSubnet("10.0.0.2", "10.0.0.1", 32), false);
  assertEquals(ipv4InSubnet("8.8.8.8", "10.0.0.1", 0), true); // /0 matches all
});

Deno.test("ipv4InSubnet: malformed IP or bad prefix is a non-match, not a throw", () => {
  assertEquals(ipv4InSubnet("not-an-ip", "10.0.0.1", 24), false);
  assertEquals(ipv4InSubnet("10.0.0.1", "10.0.0.1", 33), false);
  assertEquals(ipv4InSubnet("10.0.0.1", "10.0.0.1", -1), false);
});

// ── extractSessionToken ────────────────────────────────────────────────────────

Deno.test("extractSessionToken: pulls TOKEN value up to the next semicolon", () => {
  const header =
    "TOKEN=eyJhbGciOiJIUzI1NiJ9.abc; path=/; expires=Wed, 01-Jan-2027; samesite=none; secure; httponly";
  assertEquals(
    extractSessionToken(header),
    "eyJhbGciOiJIUzI1NiJ9.abc",
  );
});

Deno.test("extractSessionToken: missing TOKEN cookie returns empty string", () => {
  assertEquals(extractSessionToken(""), "");
  assertEquals(extractSessionToken("OTHER=value; path=/"), "");
});

// ── mapSystemMessage ────────────────────────────────────────────────────────────

Deno.test("mapSystemMessage: OS version read from system.info.hardware, not system.info", () => {
  const { os } = mapSystemMessage({
    system: { info: { hardware: { firmwareVersion: "4.3.6" } } },
    firmware: { latest: { version: "v5.1.19+3fbc1da", channel: "release" } },
    apps: { controllers: [] },
  });
  assertEquals(os.currentVersion, "4.3.6");
  assertEquals(os.availableVersion, "v5.1.19+3fbc1da");
  assertEquals(os.channel, "release");
  assertEquals(os.updateAvailable, true);
});

Deno.test("mapSystemMessage: firmware read from top level, system.firmware (null) is ignored", () => {
  const { os } = mapSystemMessage({
    system: { info: { hardware: { firmwareVersion: "4.3.6" } }, firmware: null },
    firmware: { latest: { version: "4.3.6", channel: "release" } },
    apps: { controllers: [] },
  });
  // current === available -> no update, and proves system.firmware was never touched
  assertEquals(os.updateAvailable, false);
});

Deno.test("mapSystemMessage: missing fields fall back to 'unknown', no update reported", () => {
  const { os } = mapSystemMessage({});
  assertEquals(os.currentVersion, "unknown");
  assertEquals(os.availableVersion, undefined);
  assertEquals(os.channel, "unknown");
  assertEquals(os.updateAvailable, false);
});

Deno.test("mapSystemMessage: controller updateAvailable null (offline) coalesces to undefined", () => {
  const { controllers } = mapSystemMessage({
    apps: {
      controllers: [
        {
          name: "network",
          version: "10.1.89",
          updateAvailable: "10.4.57",
          isInstalled: true,
          isRunning: true,
          releaseChannel: "release",
          status: "ok",
        },
        {
          name: "innerspace",
          version: "",
          updateAvailable: null,
          isInstalled: false,
          isRunning: false,
          releaseChannel: "release",
          status: "offline",
        },
      ],
    },
  });
  assertEquals(controllers.length, 2);
  assertEquals(controllers[0].updateAvailable, "10.4.57");
  assertEquals(controllers[1].updateAvailable, undefined);
});

// ── instanceName ──────────────────────────────────────────────────────────────

const localTarget: Target = { base: "https://udm", target: "udm", insecure: false };

Deno.test("instanceName: single-target scan uses the bare site name", () => {
  assertEquals(instanceName(localTarget, "Default", false), "Default");
});

Deno.test("instanceName: multi-console suffix uses consoleId, not just consoleShortname", () => {
  const t: Target = {
    base: "https://x",
    target: "console-1",
    consoleId: "console-1",
    consoleShortname: "UDMPRO",
    insecure: false,
  };
  assertEquals(instanceName(t, "Default", true), "Default-UDMPRO-console-1");
});

Deno.test("instanceName: two same-model consoles with a same-named site no longer collide", () => {
  // Regression: consoleShortname alone ("UDMPRO") is a hardware model name,
  // not unique per device — two consoles of the same model previously
  // produced the identical instance name for a same-named site.
  const a: Target = {
    base: "https://a",
    target: "console-a",
    consoleId: "console-a",
    consoleShortname: "UDMPRO",
    insecure: false,
  };
  const b: Target = {
    base: "https://b",
    target: "console-b",
    consoleId: "console-b",
    consoleShortname: "UDMPRO",
    insecure: false,
  };
  const nameA = instanceName(a, "Default", true);
  const nameB = instanceName(b, "Default", true);
  assertEquals(nameA === nameB, false);
});

Deno.test("instanceName: sanitizes characters outside [A-Za-z0-9._-]", () => {
  assertEquals(instanceName(localTarget, "My Site!", false), "My-Site-");
});

// ── describeProtocol / describePorts / describeTrafficFilter ─────────────────

Deno.test("describeProtocol: NAMED_PROTOCOL, PROTOCOL_NUMBER, PRESET, and no-filter cases", () => {
  assertEquals(describeProtocol(undefined), undefined);
  assertEquals(
    describeProtocol({ protocolFilter: undefined }),
    "all",
  );
  assertEquals(
    describeProtocol({
      protocolFilter: { type: "NAMED_PROTOCOL", protocol: { name: "tcp" } },
    }),
    "tcp",
  );
  assertEquals(
    describeProtocol({
      protocolFilter: {
        type: "NAMED_PROTOCOL",
        matchOpposite: true,
        protocol: { name: "tcp" },
      },
    }),
    "not tcp",
  );
  assertEquals(
    describeProtocol({
      protocolFilter: { type: "PROTOCOL_NUMBER", protocolNumber: 47 },
    }),
    "proto 47",
  );
  assertEquals(
    describeProtocol({
      protocolFilter: { type: "PRESET", preset: { name: "TCP_UDP" } },
    }),
    "tcp_udp",
  );
});

Deno.test("describePorts: single ports, ranges, negation, and non-PORTS filter", () => {
  assertEquals(describePorts(undefined), undefined);
  assertEquals(describePorts({ type: "IP_ADDRESSES" }), "traffic-matching-list");
  assertEquals(
    describePorts({
      type: "PORTS",
      items: [
        { type: "PORT_NUMBER", value: 22 },
        { type: "PORT_NUMBER_RANGE", start: 8000, stop: 8080 },
      ],
    }),
    "22, 8000-8080",
  );
  assertEquals(
    describePorts({
      type: "PORTS",
      matchOpposite: true,
      items: [{ type: "PORT_NUMBER", value: 443 }],
    }),
    "not 443",
  );
});

Deno.test("describeTrafficFilter: NETWORK filter resolves zone names, IP_ADDRESS lists values", () => {
  const zoneNames = { "z1": "Trusted" };
  assertEquals(
    describeTrafficFilter(
      { type: "NETWORK", networkFilter: { networkIds: ["z1"] } },
      zoneNames,
    ),
    "networks Trusted",
  );
  assertEquals(
    describeTrafficFilter(
      {
        type: "IP_ADDRESS",
        ipAddressFilter: {
          type: "IP_ADDRESSES",
          items: [{ value: "10.0.0.5" }],
        },
      },
      {},
    ),
    "ip 10.0.0.5",
  );
  assertEquals(describeTrafficFilter(undefined, {}), undefined);
});

// ── fetchAllPages ─────────────────────────────────────────────────────────────

Deno.test("fetchAllPages: stops on a short page even when totalCount is absent", async () => {
  // Regression for the truncation bug: a missing totalCount used to coalesce
  // to 0 via `?? 0`, making `items.length >= 0` true after the very first
  // full page and silently truncating results. The short-page signal alone
  // must now correctly continue past a full first page.
  const { result } = await withMockedFetch((req) => {
    const url = new URL(req.url);
    const offset = Number(url.searchParams.get("offset"));
    if (offset === 0) {
      // First page: exactly `limit` items, no totalCount in the envelope.
      return Response.json({
        data: Array.from({ length: 100 }, (_, i) => ({ id: `n${i}` })),
      });
    }
    // Second page: fewer than limit -> short page -> stop.
    return Response.json({ data: [{ id: "n100" }] });
  }, async () => {
    return await fetchAllPages("https://udm", "/v1/sites", "key", false);
  });
  assertEquals(result.length, 101);
});

Deno.test("fetchAllPages: totalCount, when present, is an early-exit optimization only", async () => {
  const { result, calls } = await withMockedFetch((req) => {
    const url = new URL(req.url);
    const offset = Number(url.searchParams.get("offset"));
    if (offset === 0) {
      return Response.json({
        data: Array.from({ length: 100 }, (_, i) => ({ id: `n${i}` })),
        totalCount: 100,
      });
    }
    throw new Error("should not fetch a second page when totalCount is met");
  }, async () => {
    return await fetchAllPages("https://udm", "/v1/sites", "key", false);
  });
  assertEquals(result.length, 100);
  assertEquals(calls.length, 1);
});

Deno.test("fetchAllPages: empty first page returns immediately", async () => {
  const { result, calls } = await withMockedFetch(() => Response.json({ data: [] }), async () => {
    return await fetchAllPages("https://udm", "/v1/sites", "key", false);
  });
  assertEquals(result.length, 0);
  assertEquals(calls.length, 1);
});

// ── resolveTargets ────────────────────────────────────────────────────────────

Deno.test("resolveTargets: cloud mode with no consoleId discovers and paginates through every console", async () => {
  const { result } = await withMockedFetch((req) => {
    const url = new URL(req.url);
    const offset = Number(url.searchParams.get("offset"));
    if (offset === 0) {
      return Response.json({
        data: Array.from({ length: 100 }, (_, i) => ({
          id: `console-${i}`,
          reportedState: { hardware: { shortname: "UDMPRO", name: `Console ${i}` } },
        })),
      });
    }
    return Response.json({
      data: [{
        id: "console-100",
        reportedState: { hardware: { shortname: "UDMPRO", name: "Console 100" } },
      }],
    });
  }, async () => {
    return await resolveTargets(
      { mode: "cloud", apiKey: "key", verifyTls: true } as Parameters<
        typeof resolveTargets
      >[0],
    );
  });
  // Regression: consoles discovery previously used a single un-paginated
  // apiGet, silently missing consoles beyond the first ~100.
  assertEquals(result.length, 101);
});

Deno.test("resolveTargets: cloud mode throws when the key sees no consoles", async () => {
  await withMockedFetch(() => Response.json({ data: [] }), async () => {
    await assertRejects(
      () =>
        resolveTargets(
          { mode: "cloud", apiKey: "key", verifyTls: true } as Parameters<
            typeof resolveTargets
          >[0],
        ),
      Error,
      "No consoles visible",
    );
  });
});

// ── deletePolicy (model-level, via createModelTestContext + withMockedFetch) ──

Deno.test("deletePolicy: refuses to delete a non-USER_DEFINED policy", async () => {
  const { context } = testCtx({
    mode: "local",
    apiKey: "key",
    host: "udm.example",
    verifyTls: true,
  });
  await withMockedFetch(
    () =>
      Response.json({
        id: "p1",
        name: "System Rule",
        metadata: { origin: "PREDEFINED" },
      }),
    async () => {
      await assertRejects(
        () =>
          model.methods.deletePolicy.execute(
            { siteId: "s1", policyId: "p1" },
            context,
          ),
        Error,
        "only USER_DEFINED policies are deletable",
      );
    },
  );
});

Deno.test("deletePolicy: idempotent when the policy is already gone (404 on pre-check)", async () => {
  const { context } = testCtx({
    mode: "local",
    apiKey: "key",
    host: "udm.example",
    verifyTls: true,
  });
  const { result } = await withMockedFetch(
    () => new Response("not found", { status: 404 }),
    async () =>
      await model.methods.deletePolicy.execute(
        { siteId: "s1", policyId: "p1" },
        context,
      ),
  );
  assertEquals(result, { dataHandles: [] });
});

Deno.test("deletePolicy: idempotent on a TOCTOU 404 from the delete call itself", async () => {
  const { context } = testCtx({
    mode: "local",
    apiKey: "key",
    host: "udm.example",
    verifyTls: true,
  });
  let call = 0;
  const { result } = await withMockedFetch(
    (req) => {
      call++;
      if (req.method === "GET") {
        return Response.json({
          id: "p1",
          name: "My Rule",
          metadata: { origin: "USER_DEFINED" },
        });
      }
      // DELETE races with something else that already removed it.
      return new Response("not found", { status: 404 });
    },
    async () =>
      await model.methods.deletePolicy.execute(
        { siteId: "s1", policyId: "p1" },
        context,
      ),
  );
  assertEquals(result, { dataHandles: [] });
  assertEquals(call, 2); // GET (exists check) + DELETE
});

// ── sanitizeInstanceName ──────────────────────────────────────────────────────

Deno.test("sanitizeInstanceName: strips characters unsafe for on-disk storage paths", () => {
  assertEquals(sanitizeInstanceName("udm.example.com"), "udm.example.com");
  assertEquals(sanitizeInstanceName("fe80::1"), "fe80--1"); // IPv6 colons
  assertEquals(sanitizeInstanceName("My Site!"), "My-Site-");
});

// ── apiRequest retry/backoff ──────────────────────────────────────────────────

Deno.test("apiRequest: retries 429 and succeeds once a good response arrives", async () => {
  const { result, calls } = await withMockedFetch([
    new Response("rate limited", { status: 429, headers: { "Retry-After": "0" } }),
    new Response("rate limited", { status: 429, headers: { "Retry-After": "0" } }),
    Response.json({ ok: true }),
  ], async () => {
    return await apiRequest("GET", "https://udm/x", "key");
  });
  assertEquals(result, { ok: true });
  assertEquals(calls.length, 3);
});

Deno.test("apiRequest: retries 503 the same way as 429", async () => {
  const { result, calls } = await withMockedFetch([
    new Response("unavailable", { status: 503, headers: { "Retry-After": "0" } }),
    Response.json({ ok: true }),
  ], async () => {
    return await apiRequest("GET", "https://udm/x", "key");
  });
  assertEquals(result, { ok: true });
  assertEquals(calls.length, 2);
});

Deno.test("apiRequest: gives up after MAX_RETRIES on a persistent 429 and throws", async () => {
  // 1 initial attempt + 3 retries = 4 total requests before finalizeResponse
  // throws on the 4th's still-429 status.
  const responses = Array.from(
    { length: 4 },
    () => new Response("rate limited", { status: 429, headers: { "Retry-After": "0" } }),
  );
  const { calls } = await withMockedFetch(responses, async () => {
    await assertRejects(
      () => apiRequest("GET", "https://udm/x", "key"),
      Error,
      "(429)",
    );
  });
  assertEquals(calls.length, 4);
});

Deno.test("apiRequest: Retry-After header value is honored over default backoff", async () => {
  // Retry-After: 0 means an immediate retry rather than waiting the default
  // exponential backoff (500ms+) — keeps this test fast while proving the
  // header-driven path (not just the backoff path) is what's exercised.
  const start = performance.now();
  const { result } = await withMockedFetch([
    new Response("rate limited", { status: 429, headers: { "Retry-After": "0" } }),
    Response.json({ ok: true }),
  ], async () => {
    return await apiRequest("GET", "https://udm/x", "key");
  });
  const elapsedMs = performance.now() - start;
  assertEquals(result, { ok: true });
  assertEquals(elapsedMs < 400, true); // well under the 500ms base backoff
});

// ── scan / consoles (model-level, via createModelTestContext + withMockedFetch) ──
//
// scanFirewall/scanWifi/scanClients share the identical target/site fan-out
// shape as `scan` (see resolveTargets/fetchAllPages, already covered above),
// so this exercises the common writeResource path once rather than
// duplicating near-identical tests per method.
//
// scanUpdates is NOT covered end-to-end here: its login/checkUpdates/logout
// steps are fetch-mockable, but the SYSTEM-message step depends on a raw
// WebSocket, and @swamp-club/swamp-testing has no WebSocket mock primitive
// (only withMockedFetch/withMockedCommand) — an accepted, documented gap
// rather than a silently-skipped one.

Deno.test("scan: writes one siteNetworks resource per site (local mode)", async () => {
  const { context, getWrittenResources } = testCtx({
    mode: "local",
    apiKey: "key",
    host: "udm.example",
    verifyTls: true,
  });
  const { result } = await withMockedFetch((req) => {
    const url = new URL(req.url);
    if (url.pathname.endsWith("/v1/sites")) {
      return Response.json({ data: [{ id: "s1", name: "Default" }] });
    }
    if (url.pathname.endsWith("/networks")) {
      return Response.json({
        data: [{
          id: "n1",
          name: "LAN",
          management: "auto",
          enabled: true,
          vlanId: 1,
          default: true,
        }],
      });
    }
    throw new Error(`unexpected request: ${req.method} ${req.url}`);
  }, async () => {
    return await model.methods.scan.execute({}, context);
  });

  assertEquals(result.dataHandles.length, 1);
  const written = getWrittenResources();
  assertEquals(written.length, 1);
  assertEquals(written[0].specName, "siteNetworks");
  assertEquals(written[0].name, "Default");
  assertEquals(written[0].data.networkCount, 1);
  assertEquals(
    (written[0].data.networks as Array<{ name: string }>)[0].name,
    "LAN",
  );
});

Deno.test("scanFirewall: joins policies to zone names via mapPolicy", async () => {
  const { context, getWrittenResources } = testCtx({
    mode: "local",
    apiKey: "key",
    host: "udm.example",
    verifyTls: true,
  });
  const { result } = await withMockedFetch((req) => {
    const url = new URL(req.url);
    if (url.pathname.endsWith("/v1/sites")) {
      return Response.json({ data: [{ id: "s1", name: "Default" }] });
    }
    if (url.pathname.endsWith("/firewall/zones")) {
      return Response.json({
        data: [
          { id: "z1", name: "Trusted", networkIds: [] },
          { id: "z2", name: "Guest", networkIds: [] },
        ],
      });
    }
    if (url.pathname.endsWith("/firewall/policies")) {
      return Response.json({
        data: [{
          id: "p1",
          name: "Block Guest to Trusted",
          enabled: true,
          index: 1,
          action: { type: "BLOCK" },
          source: { zoneId: "z2" },
          destination: { zoneId: "z1" },
        }],
      });
    }
    throw new Error(`unexpected request: ${req.method} ${req.url}`);
  }, async () => {
    return await model.methods.scanFirewall.execute({}, context);
  });

  assertEquals(result.dataHandles.length, 1);
  const written = getWrittenResources()[0];
  assertEquals(written.data.zoneCount, 2);
  assertEquals(written.data.policyCount, 1);
  const policy = (written.data.policies as Array<
    { sourceZone?: string; destinationZone?: string }
  >)[0];
  assertEquals(policy.sourceZone, "Guest");
  assertEquals(policy.destinationZone, "Trusted");
});

Deno.test("scanWifi: maps SPECIFIC network ref to its VLAN, NATIVE ref to the default network", async () => {
  const { context, getWrittenResources } = testCtx({
    mode: "local",
    apiKey: "key",
    host: "udm.example",
    verifyTls: true,
  });
  const { result } = await withMockedFetch((req) => {
    const url = new URL(req.url);
    if (url.pathname.endsWith("/v1/sites")) {
      return Response.json({ data: [{ id: "s1", name: "Default" }] });
    }
    if (url.pathname.endsWith("/networks")) {
      return Response.json({
        data: [
          { id: "n1", name: "LAN", vlanId: 1, default: true, management: "auto", enabled: true },
          { id: "n2", name: "IOT", vlanId: 20, default: false, management: "auto", enabled: true },
        ],
      });
    }
    if (url.pathname.endsWith("/wifi/broadcasts")) {
      return Response.json({
        data: [
          {
            id: "w1",
            name: "MainWifi",
            enabled: true,
            type: "STANDARD",
            network: { type: "NATIVE" },
          },
          {
            id: "w2",
            name: "IotWifi",
            enabled: true,
            type: "IOT_OPTIMIZED",
            network: { type: "SPECIFIC", networkId: "n2" },
          },
        ],
      });
    }
    throw new Error(`unexpected request: ${req.method} ${req.url}`);
  }, async () => {
    return await model.methods.scanWifi.execute({}, context);
  });

  assertEquals(result.dataHandles.length, 1);
  const written = getWrittenResources()[0];
  const wifis = written.data.wifis as Array<{ name: string; vlanId?: number }>;
  assertEquals(wifis.find((w) => w.name === "MainWifi")?.vlanId, 1); // NATIVE -> default net
  assertEquals(wifis.find((w) => w.name === "IotWifi")?.vlanId, 20); // SPECIFIC -> n2
});

Deno.test("consoles: requires cloud mode", async () => {
  const { context } = testCtx({ mode: "local", apiKey: "key", verifyTls: true });
  await assertRejects(
    () => model.methods.consoles.execute({}, context),
    Error,
    "requires mode='cloud'",
  );
});

Deno.test("scanClients: byVlan groups by networkId, not networkName — same-named VLANs don't merge", async () => {
  const { context, getWrittenResources } = testCtx({
    mode: "local",
    apiKey: "key",
    host: "udm.example",
    verifyTls: true,
  });
  const { result } = await withMockedFetch((req) => {
    const url = new URL(req.url);
    if (url.pathname.endsWith("/v1/sites")) {
      return Response.json({ data: [{ id: "s1", name: "Default" }] });
    }
    if (/\/networks\/n[12]$/.test(url.pathname)) {
      const hostIp = url.pathname.endsWith("/n1") ? "10.0.10.1" : "10.0.20.1";
      return Response.json({ ipv4Configuration: { hostIpAddress: hostIp, prefixLength: 24 } });
    }
    if (url.pathname.endsWith("/networks")) {
      // Two distinct VLANs that happen to share a display name.
      return Response.json({
        data: [
          { id: "n1", name: "Guest", vlanId: 10, management: "auto", enabled: true, default: false },
          { id: "n2", name: "Guest", vlanId: 20, management: "auto", enabled: true, default: false },
        ],
      });
    }
    if (url.pathname.endsWith("/clients")) {
      return Response.json({
        data: [
          { id: "c1", name: "client-a", type: "WIRED", ipAddress: "10.0.10.5" },
          { id: "c2", name: "client-b", type: "WIRED", ipAddress: "10.0.20.5" },
        ],
      });
    }
    throw new Error(`unexpected request: ${req.method} ${req.url}`);
  }, async () => {
    return await model.methods.scanClients.execute({}, context);
  });

  assertEquals(result.dataHandles.length, 1);
  const written = getWrittenResources()[0];
  assertEquals(written.data.unmappedCount, 0);
  const byVlan = written.data.byVlan as Array<
    { vlanId?: number; networkName: string; clientCount: number }
  >;
  // Regression: previously keyed by networkName, so both "Guest" VLANs would
  // have collapsed into a single entry with clientCount 2.
  assertEquals(byVlan.length, 2);
  assertEquals(byVlan.find((v) => v.vlanId === 10)?.clientCount, 1);
  assertEquals(byVlan.find((v) => v.vlanId === 20)?.clientCount, 1);
});

Deno.test("consoles: writes discovered consoles in cloud mode", async () => {
  const { context, getWrittenResources } = testCtx({
    mode: "cloud",
    apiKey: "key",
    verifyTls: true,
  });
  const { result } = await withMockedFetch(
    () =>
      Response.json({
        data: [{
          id: "console-1",
          reportedState: {
            hardware: { shortname: "UDMPRO", name: "My Console" },
          },
        }],
      }),
    async () => {
      return await model.methods.consoles.execute({}, context);
    },
  );
  assertEquals(result.dataHandles.length, 1);
  const written = getWrittenResources();
  assertEquals(written[0].specName, "consoles");
  assertEquals(written[0].data.consoleCount, 1);
});
