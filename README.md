# Burp BAC Replay Auditor

A legacy Burp Suite Extender extension written in Python for Jython 2.7 to help authorized testers compare requests made with an administrator session against replay attempts using captured low-privilege authentication values.


## Features

- Adds a dedicated **BAC Replay Auditor** tab to Burp Suite.
- Captures selected low-privilege session values from requests tagged with `X-PwnFox-Color`.
- Always considers the low-privilege Cookie cache when available; the replay can also use configured low-privilege headers and parameter values.
- Supports configured header replacement and parameter replacement in URL query strings, form-urlencoded bodies, and JSON request bodies.
- Ignores `OPTIONS` preflight requests.
- Uses a background work queue for replay requests and updates the Swing table on the Event Dispatch Thread.
- Shows administrator and low-privilege HTTP status codes and response body lengths.
- Highlights potential HTTP 200 outcomes, can filter low-privilege 4xx rows, and supports copying selected cells or rows.
- Includes exclude-path configuration and an extension marker to avoid replay loops.

A `200 OK` response is only a signal for manual review, not proof of Broken Access Control. Compare response content and confirm the authorization impact before reporting a finding.

## Requirements

- Burp Suite with the legacy Extender API / Python extension support enabled.
- Jython 2.7 standalone JAR configured in Burp's Python environment.
- PwnFox or a compatible setup that makes `X-PwnFox-Color` visible to the extension.
- An authorized target added to Burp's Target scope.

This project targets the legacy Jython extension API; it is not a Montoya API extension.

## Installation

1. Configure the Jython standalone JAR in Burp Suite's extension settings.
2. Open **Extensions → Installed → Add**.
3. Select **Python** as the extension type and load `bac_replay_auditor.py`.
4. Add the authorized test host to Burp's Target scope.
5. Open the **BAC Replay Auditor** tab and set the target host, low-privilege color (commonly `cyan`), and admin color (commonly `magenta`).
6. Browse with the low-privilege session first so the extension can refresh its cached values.
7. Enable replay only when ready to test. Replay is disabled by default.

## Configuration

- **Target Host:** Hostname to monitor; requests to other hosts are ignored.
- **Low-Priv Color / Admin Color:** Must match the PwnFox color header values visible to Burp.
- **Exclude Paths:** Comma-separated path fragments to exclude.
- **Replace with low-priv headers:** Header names whose values should be learned from the low-privilege session and used for replay. If a configured header is present in the admin request but no low-privilege value is cached, its admin value is removed rather than reused.
- **Keep original admin headers:** Exceptions for selected sensitive headers that would otherwise be removed. Use sparingly; retaining administrator authentication can invalidate the test.
- **Replace parameter values:** Comma-separated parameter names to replace using captured low-privilege values. Supported locations include URL query parameters, form-urlencoded body parameters, and JSON properties. If no low-privilege value is cached, a configured admin parameter is removed.
- **Enable replay (GET/HEAD):** Enables safe-method replay.
- **Also replay POST/PUT/PATCH/DELETE:** Additional opt-in for methods that may change server state. Keep disabled unless explicitly authorized and safe for the target.
- **Hide low-priv 4xx responses:** Filters rows from view; it does not delete results.

After changing the header or parameter replacement lists, browse with the low-privilege session again to refresh the corresponding caches.

## Interpreting results

The table compares the original admin response with a replay that uses cached low-privilege authentication values. A low-privilege status of `200` is marked as a potential BAC result. This can be a false positive if the endpoint is public, returns a generic error page with status 200, or does not expose the protected operation. Manually validate response content and side effects.


## Limitations

- The extension depends on the behavior of Burp's legacy Extender API, Jython, and PwnFox header visibility; it has not been validated across every Burp/Jython/PwnFox combination.
- Dynamic authentication flows, per-request CSRF tokens, request signing, and application-specific state may need additional configuration or manual handling.
- No automated response-body equivalence or semantic authorization analysis is performed.

## Responsible disclosure

Follow the target organization's testing policy and disclosure process. Avoid destructive operations and do not include session cookies, authorization tokens, or customer data in issues or logs.
