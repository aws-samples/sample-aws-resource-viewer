# Security Policy

## Reporting a Vulnerability

If you discover a potential security issue in this project we ask that you
**not** create a public GitHub issue, and instead report it through the
appropriate private channel for your organization's vulnerability disclosure
process.

Please do not create a public issue for security findings.

## Disclaimer

This project is provided as **sample / educational code** to demonstrate
read-only AWS resource inventory via AWS Resource Explorer. It is **not
intended for production use** without additional security hardening — see the
"Security Posture of This Tool" and "Running Responsibly" sections below.
Review and adapt it to your own security requirements before relying on it in
any shared or sensitive environment.

## Security Posture of This Tool

This is a **local, single-operator tool**. It has no authentication of its own
and no identity of its own: it borrows yours. Read this section before running
it, and especially before changing `HOST`.

### The two things that matter most

- **There is no authentication. Loopback is the only access control.** Anyone
  who can reach the port can use every AWS profile configured on this machine,
  including production ones, with no prompt and no credential of their own.
  `lib/config.js` therefore **refuses to start** if `HOST` is not a loopback
  address, unless you set `ALLOW_NON_LOOPBACK=true` to acknowledge the risk.
  That flag is for someone deliberately fronting this with their own
  authentication and TLS. It is not a convenience switch, and setting it on a
  shared or internet-reachable host effectively publishes your AWS access.

- **The app's permissions are exactly your profile's permissions. There is no
  least-privilege boundary.** The app calls AWS with whatever the
  profile you select in the settings drawer can do — if that profile is an
  admin, the app is running as an admin. The app only ever *makes* read calls
  (Resource Explorer `ListResources` plus per-resource `Describe`/`Get`), but
  nothing stops the credentials it resolves from being capable of far more.
  **If you want a least-privilege guarantee, select a least-privilege
  profile.** Configuring a dedicated read-only profile for this tool is the
  recommended setup;
  [README: IAM permissions the profile needs](README.md#iam-permissions-the-profile-needs)
  lists every action the app calls, so you can grant exactly those and nothing
  else. The minimum is the AWS managed `AWSResourceExplorerReadOnlyAccess`
  policy, which yields a full inventory with generic detail panels.

### Credential handling

- **No credentials are created, entered, or stored by this app.** It resolves
  them through the standard AWS credential chain
  (`@aws-sdk/credential-providers` `fromNodeProviderChain`) for the profile you
  pick, exactly as the AWS CLI would. Nothing is written to disk. There is no
  credential input field anywhere in the UI.
- **Credentials stay server-side.** The browser never receives an access key,
  secret, or session token. It sends a profile *name* and receives resource
  metadata.
- **Resolved credentials are cached in memory only**, keyed by profile name,
  for the lifetime of the process — until 5 minutes before their expiry, or 5
  minutes for credential types that report no expiry, so that edits to
  `~/.aws/*` are picked up without a restart. They are never persisted, and are
  lost on exit.
- **Profile discovery exposes names, not secrets.** `GET /api/profiles` parses
  `~/.aws/config` and `~/.aws/credentials` and returns only each profile's
  name, its configured region, its credential *type* (`sso`, `process`,
  `role`, `static`, …), and which file it came from. Access keys, secret keys,
  session tokens, `credential_process` command lines, and role ARNs are never
  read into the response.
- **Caller-supplied profile names are validated against the parsed profile
  list**, not used to build a path, so a request cannot coerce the server into
  reading an arbitrary file.

### Residual exposure, stated rather than claimed away

IAM cannot filter response fields, so some read calls this app makes return
more than it displays. With a broad profile, that data is reachable:

- `lambda:GetFunctionConfiguration` returns **Lambda environment variables in
  plaintext**. The app does not render them, but the call returns them.
- `iam:GetRole` returns a role's full trust policy.
- `cloudfront:GetDistribution` returns origin custom headers.
- `states:DescribeStateMachine` returns the full state machine definition.

None of these is a stored-secret read and none is destructive, but none is
"metadata only" either. You control this by
choosing a profile whose permissions you are comfortable with.

### Application-level hardening

- **Errors do not leak internals.** A terminal error handler logs the stack
  server-side against a short reference id and returns only that id, so AWS
  failure text — which embeds account IDs and ARNs — is not echoed to the
  browser. Responses carry `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, and `X-Frame-Options: DENY`. There is no
  Content-Security-Policy: the page uses inline event handlers, so a CSP
  permissive enough to keep it working would add little. The XSS defence is
  escaping every interpolation instead.
- **No sessions, no cookies, no tokens.** There is no session store, no session
  secret, and no cookie to steal or rotate. Removing the auth layer removed
  that entire class of issue along with the protection it provided.
- **The app persists no user data.** No database, no log of what you viewed.

### Audit trail

Calls appear in CloudTrail as the identity behind the profile you selected —
your own IAM user, assumed role, or SSO session. Attribution is therefore
whatever your organization already gets from that identity; this app adds no
session name of its own and does not obscure who acted. It also means **this
tool's activity is indistinguishable in CloudTrail from your own CLI
activity**, which is worth knowing if you are trying to attribute a specific
API call.

## Running Responsibly

- **Keep `HOST` on loopback.** If you must widen it, put real authentication and
  TLS in front, and understand that you are exposing every local profile.
- **Select a dedicated read-only profile** rather than an admin one. This is the
  only mechanism that limits what the tool can reach.
- **Treat the port as equivalent to your `~/.aws` directory** when deciding who
  can access the machine.
- **Do not run it on a shared or multi-user host** without the above.
