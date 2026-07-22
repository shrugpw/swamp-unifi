import { z } from "npm:zod@4";

const CLOUD_BASE = "https://api.ui.com";

const GlobalArgsSchema = z.object({
  mode: z.enum(["local", "cloud"]).describe(
    "Connection mode. Determines which API key you must create: " +
      "'local' = key from the console (Network → Settings → Control Plane → Integrations) reached at https://<host>; " +
      "'cloud' = key from unifi.ui.com (Account → API Keys) reached via Ubiquiti's cloud proxy.",
  ),
  apiKey: z.string().meta({ sensitive: true }).describe(
    "UniFi API key matching the chosen mode",
  ),
  host: z.string().optional().describe(
    "Console hostname or IP — required when mode='local' (e.g. 192.0.2.1)",
  ),
  consoleId: z.string().optional().describe(
    "Cloud console ID to target. When mode='cloud' and omitted, all consoles " +
      "visible to the key are discovered and scanned.",
  ),
  verifyTls: z.boolean().default(true).describe(
    "Verify the console's TLS certificate in local mode. Set false for the " +
      "self-signed certificate on a factory UDM (routes calls through curl).",
  ),
  username: z.string().optional().describe(
    "UniFi OS local admin username — required for scanUpdates. " +
      "This is the management-plane account on the console itself, not the Integration API key.",
  ),
  password: z.string().meta({ sensitive: true }).optional().describe(
    "UniFi OS local admin password — required for scanUpdates. " +
      'Reference a vault secret, e.g. ${{ vault.get("udm", "password") }}.',
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const ConsoleSchema = z.object({
  id: z.string(),
  shortname: z.string().optional(),
  name: z.string().optional(),
});

const ConsolesSchema = z.object({
  fetchedAt: z.string(),
  consoleCount: z.number(),
  consoles: z.array(ConsoleSchema),
});

const NetworkSchema = z.object({
  id: z.string(),
  name: z.string(),
  management: z.string(),
  enabled: z.boolean(),
  vlanId: z.number(),
  default: z.boolean(),
  zoneId: z.string().optional(),
  deviceId: z.string().optional(),
  metadataOrigin: z.string().optional(),
});

const ZoneSchema = z.object({
  id: z.string(),
  name: z.string(),
  networkIds: z.array(z.string()),
  metadataOrigin: z.string().optional(),
});

const PolicySchema = z.object({
  id: z.string(),
  name: z.string(),
  enabled: z.boolean(),
  index: z.number(),
  action: z.string(),
  sourceZoneId: z.string().optional(),
  sourceZone: z.string().optional(),
  destinationZoneId: z.string().optional(),
  destinationZone: z.string().optional(),
  ipVersion: z.string().optional(),
  protocol: z.string().optional().describe(
    "Readable protocol match, e.g. 'tcp', 'udp', 'icmp', 'all'",
  ),
  sourceMatch: z.string().optional().describe(
    "Readable source traffic filter beyond zone",
  ),
  destinationMatch: z.string().optional().describe(
    "Readable destination traffic filter beyond zone",
  ),
  destinationPorts: z.string().optional().describe(
    "Readable destination port match",
  ),
  connectionStates: z.array(z.string()).optional(),
  ipsecFilter: z.string().optional(),
  loggingEnabled: z.boolean().optional(),
  metadataOrigin: z.string().optional(),
});

const SiteFirewallSchema = z.object({
  scannedAt: z.string(),
  mode: z.enum(["local", "cloud"]),
  target: z.string(),
  consoleId: z.string().optional(),
  consoleShortname: z.string().optional(),
  siteId: z.string(),
  siteName: z.string(),
  zoneCount: z.number(),
  policyCount: z.number(),
  zones: z.array(ZoneSchema),
  policies: z.array(PolicySchema),
});

const SiteNetworksSchema = z.object({
  scannedAt: z.string(),
  mode: z.enum(["local", "cloud"]),
  target: z.string().describe(
    "host (local) or consoleId (cloud) that was scanned",
  ),
  consoleId: z.string().optional(),
  consoleShortname: z.string().optional(),
  siteId: z.string(),
  siteName: z.string(),
  networkCount: z.number(),
  networks: z.array(NetworkSchema),
});

const WifiSchema = z.object({
  id: z.string(),
  name: z.string().describe("SSID"),
  enabled: z.boolean(),
  type: z.string().describe("STANDARD | IOT_OPTIMIZED"),
  security: z.string().optional().describe(
    "OPEN | WPA2_PERSONAL | WPA3_PERSONAL | ...",
  ),
  networkRef: z.string().describe("NATIVE (default/untagged) or SPECIFIC"),
  networkId: z.string().optional(),
  networkName: z.string().optional(),
  vlanId: z.number().optional(),
  metadataOrigin: z.string().optional(),
});

const SiteWifiSchema = z.object({
  scannedAt: z.string(),
  mode: z.enum(["local", "cloud"]),
  target: z.string(),
  consoleId: z.string().optional(),
  consoleShortname: z.string().optional(),
  siteId: z.string(),
  siteName: z.string(),
  wifiCount: z.number(),
  wifis: z.array(WifiSchema),
});

const OsUpdateSchema = z.object({
  currentVersion: z.string(),
  availableVersion: z.string().optional(),
  channel: z.string(),
  updateAvailable: z.boolean(),
});

const ControllerUpdateSchema = z.object({
  name: z.string(),
  version: z.string(),
  updateAvailable: z.string().optional(),
  isInstalled: z.boolean(),
  isRunning: z.boolean(),
  releaseChannel: z.string(),
  status: z.string(),
});

const ConsoleUpdatesSchema = z.object({
  scannedAt: z.string(),
  host: z.string(),
  os: OsUpdateSchema,
  controllers: z.array(ControllerUpdateSchema),
});

const ClientSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.string().describe("WIRED | WIRELESS | VPN | TELEPORT"),
  macAddress: z.string().optional(),
  ipAddress: z.string().optional(),
  connectedAt: z.string().optional(),
  accessType: z.string().optional().describe("DEFAULT | GUEST"),
  uplinkDeviceId: z.string().optional(),
  // Mapped from ipAddress → network subnet (clients carry no networkId/vlanId)
  vlanId: z.number().optional(),
  networkId: z.string().optional(),
  networkName: z.string().optional(),
});

const VlanClientCountSchema = z.object({
  vlanId: z.number().optional(),
  networkName: z.string(),
  clientCount: z.number(),
});

const SiteClientsSchema = z.object({
  scannedAt: z.string(),
  mode: z.enum(["local", "cloud"]),
  target: z.string(),
  consoleId: z.string().optional(),
  consoleShortname: z.string().optional(),
  siteId: z.string(),
  siteName: z.string(),
  clientCount: z.number(),
  unmappedCount: z.number().describe(
    "Clients whose IP matched no known subnet (e.g. VPN)",
  ),
  byVlan: z.array(VlanClientCountSchema),
  clients: z.array(ClientSchema),
});

// ── HTTP ──────────────────────────────────────────────────────────────────────

interface RequestOptions {
  /** Route through curl (-k) for a self-signed local cert instead of fetch. */
  insecure?: boolean;
  /** JSON request body for POST/PUT/PATCH. */
  body?: unknown;
}

// ── pure helpers (unit-tested in unifi_networks_test.ts) ──────────────────────

/**
 * Build the curl argv for a request. `-k` skips TLS verification (self-signed
 * UDM cert); `-w "\n%{http_code}"` appends the status on its own trailing line
 * so the caller can recover it from stdout. `-K -` reads header config from
 * stdin (see buildCurlConfig) instead of `-H`, so the API key never appears in
 * argv/the host process list. A body adds the JSON content type. Exported for
 * testing.
 */
export function buildCurlArgs(
  method: string,
  url: string,
  body?: unknown,
): string[] {
  const args = [
    "-sk",
    "-K",
    "-",
    "-X",
    method,
    "--connect-timeout",
    "10",
    // --connect-timeout only bounds the TCP handshake; --max-time bounds the
    // whole request (matching the fetch transport's AbortSignal.timeout), so
    // a UDM that connects fine but then stalls mid-response can't hang the
    // method indefinitely.
    "--max-time",
    String(FETCH_TIMEOUT_MS / 1000),
    "-w",
    "\n%{http_code}",
  ];
  if (body !== undefined) {
    args.push(
      "-H",
      "Content-Type: application/json",
      "--data-binary",
      JSON.stringify(body),
    );
  }
  args.push(url);
  return args;
}

/**
 * Build a curl config-file body (for `-K -` via stdin) carrying header
 * values that must not appear in argv (visible to other local users via `ps`
 * for the process's lifetime). Values are escaped for curl's config-file
 * quoting (backslash and double-quote) — safe for typical API key/token
 * content; a value containing other curl-config-significant characters is
 * not specifically hardened against. Exported for testing.
 */
export function buildCurlConfig(headers: Record<string, string>): string {
  return Object.entries(headers)
    .map(([k, v]) => `header = "${k}: ${escapeCurlConfigValue(v)}"`)
    .join("\n") + "\n";
}

function escapeCurlConfigValue(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/**
 * Split curl stdout (body followed by "\n%{http_code}") into status + body.
 * Uses the LAST newline so a JSON body containing newlines is preserved, and
 * tolerates an empty body (e.g. a 204). Exported for testing.
 */
export function parseCurlOutput(raw: string): { status: number; body: string } {
  const nl = raw.lastIndexOf("\n");
  if (nl < 0) return { status: parseInt(raw, 10), body: "" };
  return { status: parseInt(raw.slice(nl + 1), 10), body: raw.slice(0, nl) };
}

/**
 * Extract the UniFi OS session TOKEN value from a Set-Cookie response header.
 * Returns "" if the header is missing or carries no TOKEN cookie. Exported for testing.
 */
export function extractSessionToken(setCookieHeader: string): string {
  const match = setCookieHeader.match(/TOKEN=([^;]+)/);
  return match ? match[1] : "";
}

/**
 * Enforce a 2xx status and parse the JSON body, returning null for an empty
 * body (e.g. a 204 from DELETE). Shared by both transports so they behave
 * identically. Exported for testing.
 */
export function finalizeResponse(
  method: string,
  url: string,
  status: number,
  text: string,
): Record<string, unknown> | null {
  if (status < 200 || status >= 300) {
    throw new Error(`${method} ${url} failed (${status}): ${text}`);
  }
  return text.trim() ? (JSON.parse(text) as Record<string, unknown>) : null;
}

// ── transports ────────────────────────────────────────────────────────────────

/**
 * Issue an HTTP request via curl. Factory UDMs present a self-signed cert and
 * Deno's fetch cannot skip TLS verification, so the insecure local path shells
 * out to curl with -k. The API key and Accept header are passed via a `-K -`
 * config piped over stdin rather than `-H` argv, so the key is never visible
 * to other local users via `ps`/`/proc/<pid>/cmdline`. Returns the HTTP status
 * and raw body; status enforcement is left to apiRequest so both transports
 * behave identically.
 */
async function curlRequest(
  method: string,
  url: string,
  apiKey: string,
  body?: unknown,
): Promise<{ status: number; body: string }> {
  const config = buildCurlConfig({
    "X-API-KEY": apiKey,
    "Accept": "application/json",
  });
  const cmd = new Deno.Command("curl", {
    args: buildCurlArgs(method, url, body),
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  });
  const child = cmd.spawn();
  try {
    const writer = child.stdin.getWriter();
    await writer.write(new TextEncoder().encode(config));
    await writer.close();
  } catch (e) {
    // Reap the spawned process even if writing its stdin config failed,
    // then surface the original error — otherwise a write failure here
    // would leak a child process.
    await child.output().catch(() => {});
    throw e;
  }
  const out = await child.output();
  if (out.code !== 0) {
    throw new Error(
      `curl ${method} ${url} failed (exit ${out.code}): ${
        new TextDecoder().decode(out.stderr)
      }`,
    );
  }
  return parseCurlOutput(new TextDecoder().decode(out.stdout));
}

/** Requests time out after this many ms on the native fetch transport (curl uses --connect-timeout 10 instead). */
const FETCH_TIMEOUT_MS = 15_000;

/** How many extra attempts a 429/503 gets before apiRequest gives up. */
const MAX_RETRIES = 3;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Single request core shared by every verb (GET/POST/PUT/PATCH/DELETE) over
 * both transports (fetch when secure, curl when insecure). Retries on 429/503
 * with exponential backoff, honoring a numeric `Retry-After` header (in
 * seconds) from the fetch transport when present — curl's transport has no
 * header visibility here, so it always falls back to backoff. Verb helpers
 * below are thin wrappers over this.
 */
export async function apiRequest(
  method: string,
  url: string,
  apiKey: string,
  opts: RequestOptions = {},
): Promise<Record<string, unknown> | null> {
  const { insecure = false, body } = opts;

  for (let attempt = 0;; attempt++) {
    let status: number;
    let text: string;
    let retryAfterMs: number | undefined;

    if (insecure) {
      ({ status, body: text } = await curlRequest(method, url, apiKey, body));
    } else {
      const headers: Record<string, string> = {
        "X-API-KEY": apiKey,
        "Accept": "application/json",
      };
      if (body !== undefined) headers["Content-Type"] = "application/json";
      const resp = await fetch(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      status = resp.status;
      text = await resp.text();
      const retryAfter = resp.headers.get("retry-after");
      if (retryAfter && /^\d+$/.test(retryAfter)) {
        retryAfterMs = Number(retryAfter) * 1000;
      }
    }

    if ((status === 429 || status === 503) && attempt < MAX_RETRIES) {
      await sleep(retryAfterMs ?? 500 * 2 ** attempt);
      continue;
    }

    return finalizeResponse(method, url, status, text);
  }
}

// Verb helpers over the shared core. GET/DELETE are the verbs in use today;
// POST/PUT/PATCH writes are a one-line apiRequest(...) call away when a
// create/update method is added (the API supports them, e.g. PATCH policies).
const apiGet = (url: string, apiKey: string, insecure = false) =>
  apiRequest("GET", url, apiKey, { insecure }).then((r) => r ?? {});

const apiDelete = (url: string, apiKey: string, insecure: boolean) =>
  apiRequest("DELETE", url, apiKey, { insecure }).then(() => undefined);

/**
 * Page through a list endpoint until the last page. An empty or short
 * (< limit) page is the sole authoritative "no more data" signal — this is
 * what every offset/limit list endpoint here guarantees. `totalCount`, when
 * present, is used ONLY as a redundant early-exit optimization, never as the
 * primary stop condition: a naive `items.length >= (totalCount ?? 0)` check
 * would silently truncate to a single page the moment any response omits
 * `totalCount`, since `?? 0` makes that comparison trivially true. Guards
 * against a stale/wrong totalCount too, since it can never fire before the
 * short-page signal would have anyway.
 */
export async function fetchAllPages(
  base: string,
  path: string,
  apiKey: string,
  insecure: boolean,
): Promise<Array<Record<string, unknown>>> {
  const items: Array<Record<string, unknown>> = [];
  let offset = 0;
  const limit = 100;
  while (true) {
    const page = await apiGet(
      `${base}${path}?offset=${offset}&limit=${limit}`,
      apiKey,
      insecure,
    );
    const data = (page.data ?? []) as Array<Record<string, unknown>>;
    items.push(...data);
    const totalCount = page.totalCount as number | undefined;
    if (
      data.length === 0 ||
      data.length < limit ||
      (totalCount !== undefined && items.length >= totalCount)
    ) break;
    offset += limit;
  }
  return items;
}

// ── mapping ─────────────────────────────────────────────────────────────────

function mapNetwork(n: Record<string, unknown>): z.infer<typeof NetworkSchema> {
  return {
    id: n.id as string,
    name: n.name as string,
    management: n.management as string,
    enabled: n.enabled as boolean,
    vlanId: n.vlanId as number,
    default: n.default as boolean,
    zoneId: n.zoneId as string | undefined,
    deviceId: n.deviceId as string | undefined,
    metadataOrigin: (n.metadata as Record<string, unknown>)?.origin as
      | string
      | undefined,
  };
}

function mapZone(z_: Record<string, unknown>): z.infer<typeof ZoneSchema> {
  return {
    id: z_.id as string,
    name: z_.name as string,
    networkIds: (z_.networkIds as string[]) ?? [],
    metadataOrigin: (z_.metadata as Record<string, unknown>)?.origin as
      | string
      | undefined,
  };
}

type Obj = Record<string, unknown>;

/** Readable protocol from an ipProtocolScope, e.g. "tcp", "icmp", "proto 47", "all". */
export function describeProtocol(scope: Obj | undefined): string | undefined {
  if (!scope) return undefined;
  const pf = scope.protocolFilter as Obj | undefined;
  if (!pf) return "all";
  switch (pf.type) {
    case "NAMED_PROTOCOL": {
      const name = (pf.protocol as Obj)?.name as string | undefined;
      return pf.matchOpposite ? `not ${name}` : name;
    }
    case "PROTOCOL_NUMBER":
      return `proto ${pf.protocolNumber}`;
    case "PRESET":
      return String((pf.preset as Obj)?.name ?? pf.preset).toLowerCase();
    default:
      return "all";
  }
}

/** Readable port match, e.g. "22, 80, 8000-8080" or "not 443". */
export function describePorts(portFilter: Obj | undefined): string | undefined {
  if (!portFilter) return undefined;
  if (portFilter.type !== "PORTS") return "traffic-matching-list";
  const items = (portFilter.items as Obj[]) ?? [];
  const parts = items.map((it) =>
    it.type === "PORT_NUMBER_RANGE"
      ? `${it.start}-${it.stop}`
      : String(it.value)
  );
  const joined = parts.join(", ");
  return portFilter.matchOpposite ? `not ${joined}` : joined;
}

/** Readable source/destination traffic filter beyond the zone. */
export function describeTrafficFilter(
  filter: Obj | undefined,
  zoneNames: Record<string, string>,
): string | undefined {
  if (!filter) return undefined;
  const opp = filter.matchOpposite ? "not " : "";
  switch (filter.type) {
    case "PORT":
      return `ports ${describePorts(filter.portFilter as Obj)}`;
    case "NETWORK": {
      const ids = ((filter.networkFilter as Obj)?.networkIds as string[]) ?? [];
      const names = ids.map((id) => zoneNames[id] ?? id).join(", ");
      return `${opp}networks ${names}`;
    }
    case "IP_ADDRESS": {
      const ipf = filter.ipAddressFilter as Obj | undefined;
      if (ipf?.type !== "IP_ADDRESSES") return `${opp}ip traffic-matching-list`;
      const vals = ((ipf.items as Obj[]) ?? []).map((i) => i.value).join(", ");
      return `${opp}ip ${vals}`;
    }
    case "MAC_ADDRESS":
      return `${opp}mac addresses`;
    case "REGION":
      return `${opp}region`;
    case "DOMAIN":
      return `${opp}domain`;
    case "APPLICATION":
      return `${opp}application`;
    case "APPLICATION_CATEGORY":
      return `${opp}app category`;
    default:
      return filter.type
        ? `${opp}${String(filter.type).toLowerCase()}`
        : undefined;
  }
}

function mapPolicy(
  p: Record<string, unknown>,
  zoneNames: Record<string, string>,
): z.infer<typeof PolicySchema> {
  const source = p.source as Obj | undefined;
  const dest = p.destination as Obj | undefined;
  const srcZoneId = source?.zoneId as string | undefined;
  const dstZoneId = dest?.zoneId as string | undefined;
  const scope = p.ipProtocolScope as Obj | undefined;
  const destFilter = dest?.trafficFilter as Obj | undefined;
  return {
    id: p.id as string,
    name: (p.name as string) ?? "(unnamed)",
    enabled: p.enabled as boolean,
    index: p.index as number,
    action: (p.action as Obj)?.type as string,
    sourceZoneId: srcZoneId,
    sourceZone: srcZoneId ? zoneNames[srcZoneId] : undefined,
    destinationZoneId: dstZoneId,
    destinationZone: dstZoneId ? zoneNames[dstZoneId] : undefined,
    ipVersion: scope?.ipVersion as string | undefined,
    protocol: describeProtocol(scope),
    sourceMatch: describeTrafficFilter(source?.trafficFilter as Obj, zoneNames),
    destinationMatch: describeTrafficFilter(destFilter, zoneNames),
    // NETWORK/IP filters can carry an additional port match alongside the main filter
    destinationPorts: describePorts(destFilter?.portFilter as Obj),
    connectionStates: (p.connectionStateFilter as string[]) ?? undefined,
    ipsecFilter: p.ipsecFilter as string | undefined,
    loggingEnabled: p.loggingEnabled as boolean | undefined,
    metadataOrigin: (p.metadata as Obj)?.origin as string | undefined,
  };
}

// ── IPv4 subnet matching (pure, unit-tested) ──────────────────────────────────

/** Parse a dotted-quad IPv4 string to a uint32, or null if malformed. */
export function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const octet = Number(p);
    if (octet > 255) return null;
    n = (n << 8) | octet;
  }
  return n >>> 0;
}

/** True if an IPv4 address falls within hostIp/prefixLength. */
export function ipv4InSubnet(
  ip: string,
  hostIp: string,
  prefix: number,
): boolean {
  const a = ipv4ToInt(ip);
  const b = ipv4ToInt(hostIp);
  if (a === null || b === null || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  return (a & mask) === (b & mask);
}

/** A network's IPv4 subnet plus the identity we map clients onto. */
interface Subnet {
  networkId: string;
  networkName: string;
  vlanId?: number;
  hostIp: string;
  prefix: number;
}

/** Resolve the vlan/network a client IP belongs to, if any. */
function matchSubnet(
  ip: string | undefined,
  subnets: Subnet[],
): Subnet | undefined {
  if (!ip) return undefined;
  return subnets.find((s) => ipv4InSubnet(ip, s.hostIp, s.prefix));
}

function mapClient(
  c: Record<string, unknown>,
  subnets: Subnet[],
): z.infer<typeof ClientSchema> {
  const ip = c.ipAddress as string | undefined;
  const match = matchSubnet(ip, subnets);
  return {
    id: c.id as string,
    name: c.name as string,
    type: c.type as string,
    macAddress: c.macAddress as string | undefined,
    ipAddress: ip,
    connectedAt: c.connectedAt as string | undefined,
    accessType: (c.access as Record<string, unknown>)?.type as
      | string
      | undefined,
    uplinkDeviceId: c.uplinkDeviceId as string | undefined,
    vlanId: match?.vlanId,
    networkId: match?.networkId,
    networkName: match?.networkName,
  };
}

/** Network identity for VLAN lookups, keyed by network id. */
type NetworkLookup = Record<string, { name: string; vlanId?: number }>;

function mapWifi(
  w: Record<string, unknown>,
  networks: NetworkLookup,
  defaultNet: { id: string; name: string; vlanId?: number } | undefined,
): z.infer<typeof WifiSchema> {
  const netRef = w.network as Record<string, unknown> | undefined;
  const refType = (netRef?.type as string) ?? "NATIVE";
  // SPECIFIC binds an explicit networkId; NATIVE rides the default/untagged network.
  const specificId = netRef?.networkId as string | undefined;
  const match = specificId
    ? { id: specificId, ...networks[specificId] }
    : defaultNet;
  return {
    id: w.id as string,
    name: w.name as string,
    enabled: w.enabled as boolean,
    type: w.type as string,
    security: (w.securityConfiguration as Record<string, unknown>)?.type as
      | string
      | undefined,
    networkRef: refType,
    networkId: match?.id,
    networkName: match?.name,
    vlanId: match?.vlanId,
    metadataOrigin: (w.metadata as Record<string, unknown>)?.origin as
      | string
      | undefined,
  };
}

function mapConsole(h: Record<string, unknown>): z.infer<typeof ConsoleSchema> {
  const hardware = (h.reportedState as Record<string, unknown>)?.hardware as
    | Record<string, unknown>
    | undefined;
  return {
    id: h.id as string,
    shortname: hardware?.shortname as string | undefined,
    name: hardware?.name as string | undefined,
  };
}

/**
 * Map a UDM management-plane SYSTEM websocket message into OS + controller
 * update status. Current OS version lives at system.info.hardware.firmwareVersion
 * (NOT system.info.firmwareVersion); available-update data is the top-level
 * firmware.latest (NOT nested under system.firmware, which the UDM sends as
 * null) — neither path is documented by Ubiquiti. Controller updateAvailable
 * comes back null for offline controllers, coalesced to undefined for the
 * schema. Exported for testing.
 */
export function mapSystemMessage(systemData: Record<string, unknown>): {
  os: z.infer<typeof OsUpdateSchema>;
  controllers: z.infer<typeof ControllerUpdateSchema>[];
} {
  const apps = systemData.apps as Record<string, unknown> | undefined;
  const controllers = (apps?.controllers as Array<Record<string, unknown>>) ??
    [];
  const system = systemData.system as Record<string, unknown> | undefined;
  const info = system?.info as Record<string, unknown> | undefined;
  const hardware = info?.hardware as Record<string, unknown> | undefined;
  const firmware = systemData.firmware as Record<string, unknown> | undefined;
  const latest = firmware?.latest as Record<string, unknown> | undefined;

  const currentVersion = (hardware?.firmwareVersion as string) ?? "unknown";
  const availableVersion = latest?.version as string | undefined;
  const channel = (latest?.channel as string) ?? "unknown";

  return {
    os: {
      currentVersion,
      availableVersion,
      channel,
      updateAvailable: availableVersion !== undefined &&
        availableVersion !== currentVersion,
    },
    controllers: controllers.map((c) => ({
      name: c.name as string,
      version: c.version as string,
      updateAvailable: (c.updateAvailable as string | null) ?? undefined,
      isInstalled: c.isInstalled as boolean,
      isRunning: c.isRunning as boolean,
      releaseChannel: c.releaseChannel as string,
      status: c.status as string,
    })),
  };
}

/** A console to scan: its proxy base URL plus identity for labelling output. */
export interface Target {
  base: string;
  target: string;
  consoleId?: string;
  consoleShortname?: string;
  insecure: boolean;
}

function proxyBase(consoleId: string): string {
  return `${CLOUD_BASE}/v1/connector/consoles/${consoleId}/proxy/network/integration`;
}

/** Resolve the set of consoles to scan from the configured mode + args. */
export async function resolveTargets(g: GlobalArgs): Promise<Target[]> {
  if (g.mode === "local") {
    if (!g.host) {
      throw new Error("mode='local' requires 'host' (the console IP/hostname)");
    }
    return [{
      base: `https://${g.host}/proxy/network/integration`,
      target: g.host,
      insecure: !g.verifyTls,
    }];
  }

  // cloud
  if (g.consoleId) {
    return [{
      base: proxyBase(g.consoleId),
      target: g.consoleId,
      consoleId: g.consoleId,
      insecure: false,
    }];
  }

  // cloud, no consoleId → discover and fan out over every console
  const consoles =
    (await fetchAllPages(CLOUD_BASE, "/v1/hosts", g.apiKey, false))
      .map(mapConsole);
  if (consoles.length === 0) {
    throw new Error("No consoles visible to this cloud API key");
  }
  return consoles.map((c) => ({
    base: proxyBase(c.id),
    target: c.id,
    consoleId: c.id,
    consoleShortname: c.shortname,
    insecure: false,
  }));
}

/**
 * Instance names map directly to on-disk storage paths, so every write must
 * go through this — a raw hostname (e.g. an IPv6 literal with colons) or site
 * name can carry characters that aren't safe there. Exported for testing.
 */
export function sanitizeInstanceName(raw: string): string {
  return raw.replace(/[^A-Za-z0-9._-]/g, "-");
}

/**
 * Data instance name for a site. Uses the bare site name for single-target
 * scans so local and cloud modes converge on the same instance; only appends
 * a console-identity suffix when fanning out over multiple consoles, where it
 * is needed to keep same-named sites from colliding. The suffix always
 * includes `consoleId` (the API's actual unique identifier) rather than
 * `consoleShortname` alone — shortname is just a hardware model name (e.g.
 * "UDMPRO") and repeats across consoles of the same model, which would
 * otherwise let two same-named sites on two same-model consoles silently
 * overwrite each other's stored resource. Suffix (not prefix) so a site's
 * instances sort together, e.g. "Default", "Default-UDMPRO-<consoleId>".
 */
export function instanceName(
  t: Target,
  siteName: string,
  disambiguate: boolean,
): string {
  const suffix = disambiguate
    ? (t.consoleShortname
      ? `${t.consoleShortname}-${t.consoleId}`
      : t.consoleId)
    : undefined;
  const raw = suffix ? `${siteName}-${suffix}` : siteName;
  return sanitizeInstanceName(raw);
}

// ── model ─────────────────────────────────────────────────────────────────────

interface Logger {
  info: (message: string, properties?: Record<string, unknown>) => void;
  warn: (message: string, properties?: Record<string, unknown>) => void;
}

interface Ctx {
  globalArgs: GlobalArgs;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

export const model = {
  type: "@shrug/unifi-networks",
  version: "2026.07.21.7",
  globalArguments: GlobalArgsSchema,
  // No-op: globalArguments hasn't changed shape across any prior version —
  // every bump so far has been bug fixes/logging/docs, not schema changes.
  // Establishes the upgrades pattern for whenever a real migration is needed.
  upgrades: [
    {
      toVersion: "2026.07.21.7",
      description: "Version bump, no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    consoles: {
      description: "UniFi consoles visible to the cloud API key",
      schema: ConsolesSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
    siteNetworks: {
      description: "Networks (VLANs) per UniFi site",
      schema: SiteNetworksSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    siteFirewall: {
      description: "Firewall zones and policies per UniFi site",
      schema: SiteFirewallSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    siteClients: {
      description:
        "Connected clients per UniFi site, mapped to VLAN by IP subnet",
      schema: SiteClientsSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    siteWifi: {
      description:
        "WiFi broadcasts (SSIDs) per UniFi site, mapped to VLAN by network",
      schema: SiteWifiSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    consoleUpdates: {
      description:
        "UniFi OS firmware and application update status from the management-plane websocket",
      schema: ConsoleUpdatesSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    consoles: {
      description:
        "List UniFi consoles visible to the cloud API key (cloud mode only). " +
        "Use to find a consoleId to pin.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        context.logger.info(
          "Discovering consoles visible to the cloud API key",
        );
        const g = context.globalArgs;
        if (g.mode !== "cloud") {
          throw new Error(
            "The 'consoles' method requires mode='cloud' (console discovery " +
              "is a cloud API feature)",
          );
        }
        const consoles =
          (await fetchAllPages(CLOUD_BASE, "/v1/hosts", g.apiKey, false))
            .map(mapConsole);

        const handle = await context.writeResource("consoles", "consoles", {
          fetchedAt: new Date().toISOString(),
          consoleCount: consoles.length,
          consoles,
        });
        context.logger.info("Found {count} console(s)", {
          count: consoles.length,
        });
        return { dataHandles: [handle] };
      },
    },

    scan: {
      description:
        "Fetch all networks/VLANs. Local mode scans the configured host; cloud " +
        "mode scans the given consoleId, or every visible console when omitted.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        context.logger.info("Scanning networks ({mode} mode)", {
          mode: context.globalArgs.mode,
        });
        const g = context.globalArgs;
        const targets = await resolveTargets(g);
        const disambiguate = targets.length > 1;
        const dataHandles = [];

        for (const t of targets) {
          const sites = await fetchAllPages(
            t.base,
            "/v1/sites",
            g.apiKey,
            t.insecure,
          );

          for (const site of sites) {
            const siteId = site.id as string;
            const siteName = (site.name as string) ?? siteId;
            const networks = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/networks`,
              g.apiKey,
              t.insecure,
            );

            const handle = await context.writeResource(
              "siteNetworks",
              instanceName(t, siteName, disambiguate),
              {
                scannedAt: new Date().toISOString(),
                mode: g.mode,
                target: t.target,
                consoleId: t.consoleId,
                consoleShortname: t.consoleShortname,
                siteId,
                siteName,
                networkCount: networks.length,
                networks: networks.map(mapNetwork),
              },
            );
            dataHandles.push(handle);
          }
        }

        context.logger.info("Wrote {count} site network snapshot(s)", {
          count: dataHandles.length,
        });
        return { dataHandles };
      },
    },

    scanFirewall: {
      description:
        "Fetch firewall zones and policies per site, joined so policies show " +
        "human-readable source/destination zone names. Same mode/fan-out rules as scan.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        context.logger.info(
          "Scanning firewall zones and policies ({mode} mode)",
          {
            mode: context.globalArgs.mode,
          },
        );
        const g = context.globalArgs;
        const targets = await resolveTargets(g);
        const disambiguate = targets.length > 1;
        const dataHandles = [];

        for (const t of targets) {
          const sites = await fetchAllPages(
            t.base,
            "/v1/sites",
            g.apiKey,
            t.insecure,
          );

          for (const site of sites) {
            const siteId = site.id as string;
            const siteName = (site.name as string) ?? siteId;

            const rawZones = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/firewall/zones`,
              g.apiKey,
              t.insecure,
            );
            const rawPolicies = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/firewall/policies`,
              g.apiKey,
              t.insecure,
            );

            const zones = rawZones.map(mapZone);
            const zoneNames: Record<string, string> = {};
            for (const z_ of zones) zoneNames[z_.id] = z_.name;

            const policies = rawPolicies
              .map((p) => mapPolicy(p, zoneNames))
              .sort((a, b) => a.index - b.index);

            const handle = await context.writeResource(
              "siteFirewall",
              instanceName(t, siteName, disambiguate),
              {
                scannedAt: new Date().toISOString(),
                mode: g.mode,
                target: t.target,
                consoleId: t.consoleId,
                consoleShortname: t.consoleShortname,
                siteId,
                siteName,
                zoneCount: zones.length,
                policyCount: policies.length,
                zones,
                policies,
              },
            );
            dataHandles.push(handle);
          }
        }

        context.logger.info("Wrote {count} site firewall snapshot(s)", {
          count: dataHandles.length,
        });
        return { dataHandles };
      },
    },

    scanWifi: {
      description:
        "Fetch WiFi broadcasts (SSIDs) per site and map each to its VLAN via " +
        "its network reference (SPECIFIC → networkId; NATIVE → default/untagged). " +
        "Same mode/fan-out rules as scan.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        context.logger.info("Scanning WiFi broadcasts ({mode} mode)", {
          mode: context.globalArgs.mode,
        });
        const g = context.globalArgs;
        const targets = await resolveTargets(g);
        const disambiguate = targets.length > 1;
        const dataHandles = [];

        for (const t of targets) {
          const sites = await fetchAllPages(
            t.base,
            "/v1/sites",
            g.apiKey,
            t.insecure,
          );

          for (const site of sites) {
            const siteId = site.id as string;
            const siteName = (site.name as string) ?? siteId;

            const networks = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/networks`,
              g.apiKey,
              t.insecure,
            );
            const netLookup: NetworkLookup = {};
            let defaultNet:
              | { id: string; name: string; vlanId?: number }
              | undefined;
            for (const n of networks) {
              const entry = {
                name: n.name as string,
                vlanId: n.vlanId as number | undefined,
              };
              netLookup[n.id as string] = entry;
              if (n.default === true) {
                defaultNet = { id: n.id as string, ...entry };
              }
            }

            const rawWifis = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/wifi/broadcasts`,
              g.apiKey,
              t.insecure,
            );
            const wifis = rawWifis.map((w) =>
              mapWifi(w, netLookup, defaultNet)
            );

            const handle = await context.writeResource(
              "siteWifi",
              instanceName(t, siteName, disambiguate),
              {
                scannedAt: new Date().toISOString(),
                mode: g.mode,
                target: t.target,
                consoleId: t.consoleId,
                consoleShortname: t.consoleShortname,
                siteId,
                siteName,
                wifiCount: wifis.length,
                wifis,
              },
            );
            dataHandles.push(handle);
          }
        }

        context.logger.info("Wrote {count} site WiFi snapshot(s)", {
          count: dataHandles.length,
        });
        return { dataHandles };
      },
    },

    scanUpdates: {
      description:
        "Fetch UniFi OS firmware and application update status via the management-plane " +
        "websocket. Requires username/password in globalArgs (not the Integration API key). " +
        "Authenticates, opens wss://<host>/api/ws/system, triggers a checkUpdates POST, " +
        "then parses the SYSTEM message for OS and controller update data.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        context.logger.info("Scanning UDM OS/app update status");
        const g = context.globalArgs;
        if (g.mode !== "local") {
          throw new Error(
            "scanUpdates requires mode='local' (management-plane access)",
          );
        }
        if (!g.host) {
          throw new Error(
            "scanUpdates requires 'host' (the console IP/hostname)",
          );
        }
        if (!g.username || !g.password) {
          throw new Error(
            "scanUpdates requires 'username' and 'password' in globalArgs",
          );
        }

        const host = g.host;
        const baseUrl = `https://${host}`;

        // Step 1: Authenticate via POST /api/auth/login
        const loginUrl = `${baseUrl}/api/auth/login`;
        const loginResp = await fetch(loginUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
          },
          body: JSON.stringify({ username: g.username, password: g.password }),
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        });
        const loginText = await loginResp.text();
        if (loginResp.status < 200 || loginResp.status >= 300) {
          throw new Error(`Login failed (${loginResp.status}): ${loginText}`);
        }

        // Extract CSRF token and session cookie
        const csrfToken = loginResp.headers.get("x-csrf-token") ?? "";
        const sessionCookie = extractSessionToken(
          loginResp.headers.get("set-cookie") ?? "",
        );

        if (!csrfToken || !sessionCookie) {
          throw new Error(
            "Failed to extract CSRF token or session cookie from login response",
          );
        }

        // Step 2: POST /api/controllers/checkUpdates to trigger update check
        const checkUrl = `${baseUrl}/api/controllers/checkUpdates`;
        const checkResp = await fetch(checkUrl, {
          method: "POST",
          headers: {
            "x-csrf-token": csrfToken,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Cookie": `TOKEN=${sessionCookie}`,
          },
          body: JSON.stringify({
            controllersToCheck: [
              "network",
              "protect",
              "access",
              "talk",
              "connect",
              "innerspace",
            ],
          }),
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        });
        if (checkResp.status < 200 || checkResp.status >= 300) {
          throw new Error(
            `checkUpdates failed (${checkResp.status}): ${await checkResp
              .text()}`,
          );
        }

        // Step 3: Open websocket and listen for SYSTEM message. The
        // constructor call lives inside the try (not just the awaited
        // promise) so a synchronous throw from `new WebSocket(...)` still
        // reaches the finally below and attempts the session logout.
        let systemData: Record<string, unknown>;
        try {
          const wsUrl = `wss://${host}/api/ws/system`;
          const ws = new WebSocket(wsUrl, {
            headers: {
              "Cookie": `TOKEN=${sessionCookie}`,
              "x-csrf-token": csrfToken,
            },
          });

          systemData = await new Promise<Record<string, unknown>>(
            (resolve, reject) => {
              const timeout = setTimeout(() => {
                ws.close();
                reject(
                  new Error("WebSocket timeout waiting for SYSTEM message"),
                );
              }, 15000);

              ws.onopen = () => {
                // Connection opened
              };

              ws.onmessage = (event) => {
                try {
                  const msg = JSON.parse(event.data as string);
                  if (msg.type === "SYSTEM") {
                    clearTimeout(timeout);
                    ws.close();
                    resolve(msg);
                  }
                } catch {
                  // Ignore parse errors from non-JSON messages
                }
              };

              ws.onerror = (err) => {
                clearTimeout(timeout);
                ws.close();
                // `err` is a bare Event on most runtimes (no useful .message),
                // so surface the URL/readyState instead of stringifying it —
                // `${err}` on an Event typically yields "[object Event]".
                const detail = err && typeof err === "object" &&
                    "message" in err
                  ? String((err as { message: unknown }).message)
                  : `readyState=${ws.readyState}`;
                reject(
                  new Error(
                    `WebSocket error connecting to ${wsUrl}: ${detail}`,
                  ),
                );
              };

              ws.onclose = () => {
                // Connection closed
              };
            },
          );
        } finally {
          // Best-effort session logout — the TOKEN cookie stays valid on the
          // console until it naturally expires otherwise. Runs regardless of
          // whether the WebSocket step above succeeded, timed out, or
          // errored, so a failed scan doesn't leak a live session. Never
          // fails the method itself: this is cleanup, not the actual scan.
          try {
            await fetch(`${baseUrl}/api/auth/logout`, {
              method: "POST",
              headers: {
                "x-csrf-token": csrfToken,
                "Cookie": `TOKEN=${sessionCookie}`,
              },
              signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
            });
          } catch (e) {
            context.logger.warn(
              "Failed to log out of UDM session (non-fatal): {error}",
              { error: e instanceof Error ? e.message : String(e) },
            );
          }
        }

        // Step 4: Parse the SYSTEM message
        const { os, controllers: controllerUpdates } = mapSystemMessage(
          systemData,
        );

        const handle = await context.writeResource(
          "consoleUpdates",
          sanitizeInstanceName(host),
          {
            scannedAt: new Date().toISOString(),
            host,
            os,
            controllers: controllerUpdates,
          },
        );

        context.logger.info(
          "UDM update scan complete: OS updateAvailable={updateAvailable}",
          {
            updateAvailable: os.updateAvailable,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    scanClients: {
      description:
        "Fetch connected clients per site and map each to its VLAN/network by " +
        "matching the client IP against network subnets (clients carry no " +
        "networkId). Same mode/fan-out rules as scan.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, context: Ctx) => {
        context.logger.info("Scanning connected clients ({mode} mode)", {
          mode: context.globalArgs.mode,
        });
        const g = context.globalArgs;
        const targets = await resolveTargets(g);
        const disambiguate = targets.length > 1;
        const dataHandles = [];

        for (const t of targets) {
          const sites = await fetchAllPages(
            t.base,
            "/v1/sites",
            g.apiKey,
            t.insecure,
          );

          for (const site of sites) {
            const siteId = site.id as string;
            const siteName = (site.name as string) ?? siteId;

            // Build the subnet table: list networks, then fetch each detail for
            // its IPv4 gateway/prefix (only the detail endpoint exposes subnets).
            const networks = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/networks`,
              g.apiKey,
              t.insecure,
            );
            const subnets: Subnet[] = [];
            for (const n of networks) {
              const detail = await apiGet(
                `${t.base}/v1/sites/${siteId}/networks/${n.id}`,
                g.apiKey,
                t.insecure,
              );
              const ipv4 = detail.ipv4Configuration as
                | Record<string, unknown>
                | undefined;
              const hostIp = ipv4?.hostIpAddress as string | undefined;
              const prefix = ipv4?.prefixLength as number | undefined;
              if (hostIp && prefix != null) {
                subnets.push({
                  networkId: n.id as string,
                  networkName: n.name as string,
                  vlanId: n.vlanId as number | undefined,
                  hostIp,
                  prefix,
                });
              }
            }

            const rawClients = await fetchAllPages(
              t.base,
              `/v1/sites/${siteId}/clients`,
              g.apiKey,
              t.insecure,
            );
            const clients = rawClients.map((c) => mapClient(c, subnets));

            // Aggregate counts per network (plus an unmapped bucket)
            const counts = new Map<
              string,
              z.infer<typeof VlanClientCountSchema>
            >();
            let unmapped = 0;
            for (const c of clients) {
              // Key by networkId, not networkName: two distinct VLANs can
              // share a display name, and grouping by name would silently
              // merge their counts under whichever one's vlanId won the race.
              if (!c.networkId || !c.networkName) {
                unmapped++;
                continue;
              }
              const key = c.networkId;
              const entry = counts.get(key) ??
                {
                  vlanId: c.vlanId,
                  networkName: c.networkName,
                  clientCount: 0,
                };
              entry.clientCount++;
              counts.set(key, entry);
            }
            const byVlan = [...counts.values()].sort(
              (a, b) => (a.vlanId ?? 0) - (b.vlanId ?? 0),
            );

            const handle = await context.writeResource(
              "siteClients",
              instanceName(t, siteName, disambiguate),
              {
                scannedAt: new Date().toISOString(),
                mode: g.mode,
                target: t.target,
                consoleId: t.consoleId,
                consoleShortname: t.consoleShortname,
                siteId,
                siteName,
                clientCount: clients.length,
                unmappedCount: unmapped,
                byVlan,
                clients,
              },
            );
            dataHandles.push(handle);
          }
        }

        context.logger.info("Wrote {count} site client snapshot(s)", {
          count: dataHandles.length,
        });
        return { dataHandles };
      },
    },

    deletePolicy: {
      description:
        "Delete a single user-defined firewall policy by ID. Verifies the " +
        "policy exists and is USER_DEFINED before deleting (refuses derived/" +
        "system rules); UniFi removes the auto-generated Return companion. " +
        "Resolves to exactly one console — pass consoleId to disambiguate.",
      arguments: z.object({
        siteId: z.string().describe("Site ID containing the policy"),
        policyId: z.string().describe("Firewall policy ID to delete"),
        consoleId: z.string().optional().describe(
          "Console to target when the key sees more than one",
        ),
      }),
      execute: async (
        args: { siteId: string; policyId: string; consoleId?: string },
        context: Ctx,
      ) => {
        context.logger.info("Deleting firewall policy {policyId}", {
          policyId: args.policyId,
        });
        const g = context.globalArgs;
        let targets = await resolveTargets(g);
        if (args.consoleId) {
          targets = targets.filter((t) => t.consoleId === args.consoleId);
        }
        if (targets.length !== 1) {
          throw new Error(
            `deletePolicy needs exactly one target console; resolved ` +
              `${targets.length}. Pass consoleId to disambiguate.`,
          );
        }
        const t = targets[0];
        const policyUrl =
          `${t.base}/v1/sites/${args.siteId}/firewall/policies/${args.policyId}`;

        // Verify before destroying (rule #5): must exist and be user-defined.
        // A 404 here means the policy is already gone — succeed rather than
        // throw, so a repeated deletePolicy call is idempotent.
        let policy: Record<string, unknown>;
        try {
          policy = await apiGet(policyUrl, g.apiKey, t.insecure);
        } catch (e) {
          if (e instanceof Error && /\(404\)/.test(e.message)) {
            context.logger.info(
              "Policy {policyId} already gone — treating as deleted",
              { policyId: args.policyId },
            );
            return { dataHandles: [] };
          }
          throw e;
        }
        const origin = (policy.metadata as Obj)?.origin;
        if (origin !== "USER_DEFINED") {
          throw new Error(
            `Refusing to delete policy ${args.policyId} ("${policy.name}"): ` +
              `origin is ${origin}, only USER_DEFINED policies are deletable`,
          );
        }

        // The DELETE itself can also 404 (TOCTOU: something else deleted the
        // policy between the check above and here) — same idempotent success.
        try {
          await apiDelete(policyUrl, g.apiKey, t.insecure);
        } catch (e) {
          if (!(e instanceof Error && /\(404\)/.test(e.message))) throw e;
        }
        context.logger.info("Deleted firewall policy {policyId}", {
          policyId: args.policyId,
        });
        return { dataHandles: [] };
      },
    },
  },
  checks: {
    "console-reachable": {
      description:
        "Confirm the target console is reachable and the API key authenticates " +
        "before a destructive change. Labelled 'live' (makes an API call) so it " +
        "can be skipped with --skip-check-label live.",
      labels: ["live"],
      appliesTo: ["deletePolicy"],
      // Checks receive globalArgs but not the per-call method arguments, so this
      // verifies connectivity/auth to the resolved target(s); the policy-specific
      // USER_DEFINED guard stays inline in deletePolicy where policyId is known.
      execute: async (context: { globalArgs: GlobalArgs }) => {
        const g = context.globalArgs;
        try {
          const targets = await resolveTargets(g);
          const t = targets[0];
          await apiGet(`${t.base}/v1/info`, g.apiKey, t.insecure);
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `Console not reachable or API key rejected: ${
                e instanceof Error ? e.message : String(e)
              }`,
            ],
          };
        }
      },
    },
  },
};
