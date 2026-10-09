# `vanguard-ioc` feed format, version 1

A local, offline file (or API request body) that lists indicators of compromise. VANGUARD never fetches feeds and never fetches anything named inside one: `reference` is stored as inert text.

## Document form (JSON)

```json
{
  "format": "vanguard-ioc",
  "version": 1,
  "source": "my-feed",
  "generated_at": "2026-10-01T00:00:00Z",
  "indicators": [
    {
      "type": "ip",
      "value": "203.0.113.7",
      "description": "mass scanner",
      "reference": "https://example.invalid/report/1",
      "confidence": "high",
      "created_at": "2026-09-30T12:00:00Z",
      "expires_at": "2027-01-01T00:00:00Z",
      "enabled": true
    }
  ]
}
```

## JSONL form

First line: the header object (no `indicators`). Every following non-empty line: one indicator object (each line ≤ 16 KiB). A malformed line rejects the whole file (a damaged stream is not trusted partially).

## Fields

| Field | Required | Notes |
|---|---|---|
| `format`, `version` | yes | exactly `vanguard-ioc` / `1` |
| `source` | yes (header, or `--source`/`?source=`) | `^[a-z0-9][a-z0-9._-]{0,63}$`; must not conflict with the requested source |
| `generated_at` | no | RFC 3339 |
| `type` | yes | `ip`, `domain`, `url`, `sha256` (file paths are intentionally unsupported) |
| `value` | yes | normalized as below; ≤ 2048 bytes |
| `description`, `reference` | no | ≤ 512 bytes each; control characters become spaces |
| `confidence` | no | `low`, `medium`, `high`, or absent = *unrated*. VANGUARD never invents one |
| `created_at`, `expires_at` | no | RFC 3339. **Absent `expires_at` means no expiry, not expired** |
| `enabled` | no | default `true`; `false` stores the record disabled |

Unknown fields reject that record.

## Normalization (identity = `(type, value, source)`)

- **ip** – canonical text; IPv4‑mapped IPv6 is unmapped to IPv4; no zones, ports or CIDR; loopback / unspecified / multicast rejected.
- **domain** – lowercase ASCII, one trailing dot removed, letters/digits/`-`/`_` labels, ≥ 2 labels, ≤ 253 chars, no wildcards; internationalized names must be given as punycode. Matching is **exact host only** (no subdomain or suffix matching).
- **url** – `http`/`https` only; host lowercased; default port dropped; fragment dropped; **userinfo rejected** (credentials); path and query kept byte‑exact. Matching ignores the scheme and compares `host[:port]/path?query`.
- **sha256** – 64 hex characters, lowercased.

## Limits

10 MiB per import · 50 000 records · 100 000 stored indicators · 500 retained import records · match history capped at 100 000 rows / 30 days.

## Import semantics

- Whole‑import rejection (nothing written except an audit row): empty/oversize input, malformed JSON/JSONL, wrong `format`/`version`, bad or conflicting `source`, no indicators, **no valid unexpired indicator**, over the record cap, or a store that would exceed its cap. `strict` additionally rejects the whole import if any record is invalid.
- Otherwise invalid records are rejected individually and reported (`reject_sample` shows up to 10); valid ones are applied in **one transaction**.
- Report counts: `accepted` (new), `updated` (metadata changed in place), `duplicate` (unchanged, or repeated within the file), `rejected`, `expired` (already expired at import; **not stored**), `disabled` (stored disabled), `removed` (replace mode).
- Additive by default. `replace_source` deletes that source's indicators absent from the feed only if ≤ 20 % of records are invalid and the feed keeps ≥ 50 % of what the source held (`allow_shrink` overrides the latter).
- A re‑import never re‑enables an indicator an operator disabled.

## What matching can and cannot do

| Type | Compared with | Not observable when |
|---|---|---|
| ip | source address of auth/web/honeypot events; outbound address of flagged processes | behind a proxy/CDN/NAT the logged address is the proxy |
| domain, url | `Host` header (+ request target) | the access‑log format does not record `Host` (the stock combined format does not) |
| sha256 | hashes VANGUARD computed for monitored files (FIM, binary integrity, config drift) | the file is not in a monitored set |

A match means *a locally imported feed lists this exact value*. It does not show compromise, identify an actor, or prove the indicator is still accurate.
