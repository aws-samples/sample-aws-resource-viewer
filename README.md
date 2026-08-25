# AWS Resource Viewer

A single-page web app that gives you a fast, visual inventory of the AWS
resources in an account. It runs locally, uses the AWS CLI profiles you already
have, and discovers resources through **AWS Resource Explorer** rather than
calling dozens of per-service list APIs.

- **Uses your existing AWS CLI profiles.** Pick one in the settings drawer. No
  sign-in, no identity provider, no access keys to paste, nothing to deploy to
  your account.
- **Nothing loads until you choose a profile.** The app has no implicit
  credentials and makes no AWS call before you select one.
- **Compare two regions side by side.** One account at a time, up to two
  regions, one panel each. Every panel header names the account id it is showing.
- **Broad discovery.** Resource Explorer surfaces ~90 resource types (IAM, VPC,
  CloudWatch, Lambda, S3, and more) - far beyond a hand-written fetcher list.
- **Search by name.** Filter discovered resources by name to quickly find what
  you are looking for across all panels.
- **Search by AWS tags.** Filter resources by tag key, tag value, or both to
  locate resources by cost center, environment, team, or any tagging convention
  you use.
- **Export snapshot.** Save the current inventory to a JSON file for
  record-keeping, offline analysis, or sharing with teammates.
- **Compare snapshots.** Load two previously exported snapshots and see what was
  added, removed, or changed between them - useful for drift detection and
  change review.
- **View resource dependencies.** Visualize resource dependencies
  for EC2, Lambda, RDS, ECS, and EKS resources.  
- **On-demand detail.** Click any resource to fetch its details lazily.
- **Extensible for what Resource Explorer doesn't index yet.** Drop a file in
  `lib/supplemental-sources/` to track a resource type before Resource
  Explorer supports it - see [Onboarding new AWS services](#onboarding-new-aws-services).
- **Official AWS icons**, vendored locally (no third-party CDN).
- **Light/dark theme**, toggled from the top nav and remembered per browser.
- **Runs anywhere Node does.** Windows, macOS and Linux, no shell utilities
  required.

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [IAM permissions the profile needs](#iam-permissions-the-profile-needs)
- [Enabling Resource Explorer in a region](#enabling-resource-explorer-in-a-region)
- [Where global resources show up](#where-global-resources-show-up)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Security](#security)
- [Choosing a profile](#choosing-a-profile)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)
- [Scripts](#scripts)
- [Onboarding new AWS services](#onboarding-new-aws-services)

## Requirements

- **Node.js >= 18.** Nothing else - no build step and no shell utilities.
- **The AWS CLI configured with at least one profile** (`aws configure` or
  `aws configure sso`). The CLI does not have to be on your PATH at runtime -
  the app reads `~/.aws/config` and `~/.aws/credentials` directly - but if
  `aws sts get-caller-identity --profile NAME` works, the app works with
  profile `NAME`.
- **A Resource Explorer index in each region you want to view**, plus one in
  `us-east-1` for global resources. See
  [Enabling Resource Explorer in a region](#enabling-resource-explorer-in-a-region).
- **Permissions on the profile you select.** See
  [IAM permissions the profile needs](#iam-permissions-the-profile-needs).

## Quick start

```
git clone <this-repo>
cd sample-aws-resource-viewer
npm install
npm start
```

Open http://127.0.0.1:3000. The commands are identical on Windows, macOS and
Linux.

In the app: click the **profile selector** in the top bar (or the gear button
bottom-right) to open Settings, choose a profile from the dropdown, pick up to
two regions from the **Region** menu, then press **Discover Resources**.

That is the whole setup. There is no deploy step and no configuration file to
write. Nothing is created in your AWS account.

## IAM permissions the profile needs

The app makes **read-only calls only**. It never creates, modifies or deletes
anything. But it has no permissions of its own - it acts entirely as the profile
you select, so that profile needs the following.

### Required - discovery will not work without these

| Action | Why |
|---|---|
| `resource-explorer-2:GetIndex` | Preflight check that the region has a usable index, so a missing one produces a clear prompt instead of an empty screen |
| `resource-explorer-2:ListResources` | The actual inventory query, run once per region plus once for global resources |

The AWS managed policy **`AWSResourceExplorerReadOnlyAccess`** grants exactly
this and nothing else. If you want the app to do nothing but list inventory,
that single policy is sufficient.

### Optional - per-service, only for the detail panel

Clicking a resource fetches its details. Each service has its own action, and
**a missing permission is not an error**: the click falls back to showing the
ARN, resource type, service, region, account and last-reported time. So you can
grant as few or as many of these as you like.

| Service | Actions used |
|---|---|
| EC2 / VPC | `ec2:DescribeInstances`, `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeSecurityGroups`, `ec2:DescribeRouteTables`, `ec2:DescribeInternetGateways`, `ec2:DescribeNatGateways`, `ec2:DescribeAddresses`, `ec2:DescribeVpcEndpoints` |
| Lambda | `lambda:GetFunctionConfiguration` |
| DynamoDB | `dynamodb:DescribeTable` |
| RDS | `rds:DescribeDBInstances` |
| ElastiCache | `elasticache:DescribeCacheClusters` |
| OpenSearch | `es:DescribeDomain` |
| S3 / EFS | `elasticfilesystem:DescribeFileSystems` |
| ECS | `ecs:DescribeServices`, `ecs:DescribeClusters` |
| EKS | `eks:DescribeCluster` |
| ECR | `ecr:DescribeRepositories` |
| Load balancing | `elasticloadbalancing:DescribeLoadBalancers` |
| CloudFront | `cloudfront:GetDistribution` |
| SQS / SNS | `sqs:GetQueueUrl`, `sqs:GetQueueAttributes`, `sns:GetTopicAttributes` |
| Step Functions | `states:DescribeStateMachine` |
| EventBridge | `events:DescribeRule` |
| IAM | `iam:GetRole`, `iam:GetPolicy`, `iam:GetUser`, `iam:GetInstanceProfile` |
| CloudFormation | `cloudformation:DescribeStacks` |
| CloudWatch | `cloudwatch:DescribeAlarms`, `logs:DescribeLogGroups` |
| KMS | `kms:DescribeKey` |
| ACM | `acm:DescribeCertificate` |
| Secrets Manager | `secretsmanager:DescribeSecret` (metadata only - **never** `GetSecretValue`) |
| Systems Manager | `ssm:DescribeParameters` (names only - **never** `GetParameter`) |
| Bedrock AgentCore | `bedrock-agentcore:ListGateways`, `bedrock-agentcore:GetGateway` |

### What the app never asks for

There is deliberately no data-plane read anywhere in the code:
`secretsmanager:GetSecretValue`, `ssm:GetParameter`, `kms:Decrypt`,
`s3:GetObject`, `dynamodb:GetItem`/`Scan`/`Query` and `sqs:ReceiveMessage` are
never called. The tool shows *what exists*, not *what is inside it*. If you are
writing a policy by hand, you never need to grant any of those.

Note that credential resolution itself may need permissions depending on your
profile type - an SSO profile needs a valid `aws sso login` session, and a
`role_arn` profile needs `sts:AssumeRole` on the source credentials. That is
handled by the AWS credential chain exactly as it is for the `aws` CLI, and is
not specific to this app.

## Enabling Resource Explorer in a region

Resource Explorer is regional, and a local index contains only its own region's
resources. Every region you select in the UI needs its own index. The app
detects a region with no usable index and shows a panel prompting you to create
one, linking to the right console page.

To do it from the CLI instead, run these commands, substituting your region.
They work as written in PowerShell, cmd and any POSIX shell:

```
aws resource-explorer-2 create-index --region us-east-2

aws resource-explorer-2 get-index --region us-east-2

aws resource-explorer-2 create-view --view-name all-resources --region us-east-2 --query View.ViewArn --output text

aws resource-explorer-2 associate-default-view --view-arn PASTE_ARN_FROM_PREVIOUS_COMMAND --region us-east-2
```

Wait for `get-index` to report `"State": "ACTIVE"` before creating the view -
usually a few minutes. Creating an index needs write permissions
(`resource-explorer-2:CreateIndex`, `CreateView`, `AssociateDefaultView`), which
is a one-off admin task rather than something the viewing profile needs.

A **default view is required.** The app queries without an explicit `ViewArn`,
so an index with no associated default view still fails. Allow a few minutes
after creation for the index to populate - a freshly created index legitimately
returns few or no resources at first.

You do **not** need an account-wide aggregator index. A local index per region
is sufficient and keeps the footprint minimal.

## Where global resources show up

IAM, CloudFront and Route 53 resources are global. AWS indexes them in
**`us-east-1` only** - a local index elsewhere will never contain them. This is
a permanent property of Resource Explorer, not indexing lag: with an ACTIVE
local index in two regions, a `region:global` query returns hundreds of results
in `us-east-1` and zero in the other, reporting `Complete: true` in both cases.

The app works around it. Global resources are always fetched from `us-east-1`
regardless of which region you are viewing, so selecting only `us-east-2` still
shows your IAM roles.

They appear in **every panel**, so IAM is there whichever region you are looking
at, and a panel is never a misleadingly partial picture of what the profile can
reach. Any panel showing globals pulled from another region says so.

Because they belong to the account rather than to a region, the same IAM role
legitimately appears in two panels when you select two regions. The
**Total Resources** count therefore counts unique ARNs rather than summing the
panels - otherwise selecting two regions would report hundreds of roles twice
and overstate the size of the account. Per-panel counts are the contents of that
panel, so they will not add up to the total, by design.

**S3 buckets are not global, despite the global bucket namespace.** Every bucket
lives in exactly one region and Resource Explorer reports that region, so a
bucket appears only in its own region's panel. That is intentional: it shows you
where your data physically resides. Only IAM, CloudFront, Route 53 and Cost
Explorer come back from Resource Explorer as `region:global`.

This means you need an index in `us-east-1` even if you never view that region.
Without one, the app reports the inventory as partial and names `us-east-1` as
the fix rather than silently omitting IAM.

An `AGGREGATOR` index would also solve this and is deliberately not used: only
one is permitted per account, promotion is rate-limited to once per 24 hours,
and it forces Resource Explorer onto regions you may not want indexed.

## Configuration

None required. Every setting has a default and the app starts with no `.env` at
all. To change one, either export it in the environment or create a `.env` file
with the variables below:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Port to listen on |
| `HOST` | `127.0.0.1` | Bind address. A non-loopback value is refused unless `ALLOW_NON_LOOPBACK=true` |
| `ALLOW_NON_LOOPBACK` | `false` | Acknowledges the risk of binding to a routable interface. See [Security](#security) |
| `AWS_REGION` | `us-east-1` | Region for STS/SSO calls the credential chain may need. Not the regions you query - those are chosen in the UI |
| `AWS_CONFIG_FILE` | `~/.aws/config` | Standard AWS CLI override, honoured as-is |
| `AWS_SHARED_CREDENTIALS_FILE` | `~/.aws/credentials` | Standard AWS CLI override, honoured as-is |

Real environment variables take precedence over `.env`.

## Architecture

```
Browser ──▶ Express app (localhost only)
             │
             │  profile name  ──▶  AWS credential chain (~/.aws/config,
             │                      ~/.aws/credentials): SSO, credential_process,
             │                      assume-role, static keys - whatever you use
             ▼
      credentials for that profile (in-memory, never written to disk)
             │
             ▼
      AWS Resource Explorer  (discovery: one query per region, plus one for globals)
      per-service Describe/Get  (detail: on click)
```

The browser only ever sends a profile **name** and receives resource metadata.
Credentials stay in the server process. There is no session, no cookie, and no
token.

> **The app's permissions are your profile's permissions.** There is no
> least-privilege boundary between the two - see [Security](#security).

## Security

This is **sample / educational code, not intended for production use** without
additional hardening. See **[SECURITY.md](SECURITY.md)**. The two things to know
before you run it:

1. **There is no authentication.** Loopback binding is the only access control,
   so the app refuses to start on a non-loopback `HOST` unless you set
   `ALLOW_NON_LOOPBACK=true` to acknowledge that you are exposing every AWS
   profile on the machine to anyone who can reach the port.
2. **It inherits the permissions of the profile you select.** If that profile is
   an admin, the app is running as an admin. Use a dedicated read-only profile if
   you want a bound on what it can reach - see
   [Choosing a profile](#choosing-a-profile).

## Choosing a profile

The app only ever *makes* read calls, but the credentials it resolves can do
whatever your profile can. The narrower the profile, the smaller the blast
radius.

Reaching for the AWS managed **`ReadOnlyAccess`** policy is the obvious move, and
it is better than admin, but know what it includes. Checked directly against the
live policy (`aws iam get-policy-version`) rather than assumed:

- It does **not** grant `secretsmanager:GetSecretValue` or `kms:Decrypt` - so it
  cannot read a Secrets Manager secret's value, and that is a real,
  unconditional exclusion.
- It **does** grant `ssm:Get*` (covers `ssm:GetParameter`, which returns a
  SecureString's decrypted value if the caller also has KMS access on that
  key), `s3:GetObject`, `dynamodb:GetItem`/`Scan`/`Query`, and
  `sqs:ReceiveMessage` - unconditional access to object contents, table rows,
  and queue message bodies.

None of that is destructive, but all of it is confidential-data exposure, which
is more than a tool meant to show *what exists* needs. For the tightest setup,
grant only what the app actually calls - see
[IAM permissions the profile needs](#iam-permissions-the-profile-needs). The
narrowest useful profile is `AWSResourceExplorerReadOnlyAccess` alone, which
gives full inventory with generic detail panels.

Be honest about the part no policy choice fixes: IAM authorizes *operations*, not
response fields, so some describe calls hand back more than the app renders -
Lambda environment variables, an IAM role's trust policy, CloudFront origin
custom headers, and a Step Functions definition. SECURITY.md lists each one.

## Troubleshooting

**"Select an AWS profile to begin" and the drawer opens by itself.**
Expected on first run: nothing is discovered until you pick a profile.

**No profiles in the dropdown.**
The app read `~/.aws/config` and `~/.aws/credentials` and found none. Run
`aws configure` or `aws configure sso`, then reopen the drawer. The paths it
actually read are shown at the bottom of the picker.

**"No Resource Explorer index in REGION".**
That region has no index, or has one with no default view. See
[Enabling Resource Explorer in a region](#enabling-resource-explorer-in-a-region).

**No IAM roles anywhere, or a partial-inventory warning naming `us-east-1`.**
Global resources are indexed only in `us-east-1`, so you need an index there
even if you do not view that region. See
[Where global resources show up](#where-global-resources-show-up).

**A region shows far fewer resources than expected.**
A freshly created index takes a few minutes to populate. Re-run discovery.

**"Profile X is not configured in the AWS CLI on this machine."**
The name sent by the browser is not in the parsed profile list. Reopen the
drawer to reload profiles - this happens if `~/.aws/config` changed after the
page loaded.

**An SSO profile fails with a re-authentication message.**
Its cached SSO token expired. Run the `aws sso login --profile NAME` command the
error names, then retry. No app restart needed.

**Clicking a resource shows only ARN, type, region and account.**
That is the deliberate fallback - either no detail fetcher exists for that
resource type yet, or the profile lacks that one service's describe permission.
Discovery is unaffected.

**"Refusing to bind to ..." at startup.**
`HOST` is not a loopback address. Set `HOST=127.0.0.1`, or set
`ALLOW_NON_LOOPBACK=true` if you genuinely intend to expose it and have your own
authentication in front. Read [Security](#security) first.

## Project layout

```
server-v1.js                     Express server + the entire single-page UI
                                 (HTML, CSS and client JS in one template literal)
lib/config.js                    Env config; enforces the loopback bind
lib/profiles.js                  Parses ~/.aws/config + credentials into a profile list
lib/credentials.js               Resolves credentials per profile, cached in memory
lib/supplemental-sources/        Optional extra resource types not yet indexed by
                                 Resource Explorer
public/icons/                    Vendored official AWS service icons
scripts/sync-aws-icons.js        Re-vendors icons from the official AWS package
scripts/aws-icons.manifest.json  Icon id -> official filename mapping
scripts/aws-icons.lock.json      Pinned release + SHA-256 per vendored icon
```

## Scripts

| Command | What it does |
|---|---|
| `npm start` | Run the app |
| `npm run verify-icons` | Check vendored icons against the lockfile |
| `npm run sync-icons` | Re-vendor icons from the pinned release |
| `npm run sync-icons:latest` | Discover the newest AWS icon package and move the pin forward |

## Onboarding new AWS services

### What happens automatically

Discovery scales with zero code changes. New services and resource types
appear in AWS Resource Explorer's index as AWS rolls out support for them, and
`ListResources` picks them up on the next discovery call - no deploy, no
release, no waiting on this project.

Presentation degrades gracefully rather than breaking. Anything without an
explicit mapping still shows up correctly, just less polished:

| Layer | With a mapping | Without one (fallback) |
|---|---|---|
| Grouping (`classifyResource`) | Named category (Compute, Database, ...) | `Other` |
| Icon (`getIconKey`) | Official per-service AWS icon | `generic.svg` |
| Detail (`fetchResourceDetails`) | Rich, live `Describe`/`Get` call | `genericDetail()` - ARN parsed into resource ID, type, service, region, account, plus Resource Explorer's last-reported time |

So a brand-new service is discoverable and inspectable on day one. Nothing
required for the tool to keep working; the steps below are only for giving a
service its own icon and richer detail.

### Giving a service its own icon

1. Find its exact filename in the official
   [AWS Architecture Icons](https://aws.amazon.com/architecture/icons/) package
   (service icons are 64px, `Arch_<Service>_64.svg`; a few, like NAT Gateway,
   are 48px resource icons, `Res_..._48.svg`).
2. Add one entry to `scripts/aws-icons.manifest.json` mapping a short id to that
   exact filename. Matching is by exact basename on purpose - `EC2` and
   `EC2-Auto-Scaling` are different icons, and a substring match has silently
   picked the wrong one before.
3. Map the Resource Explorer service token to that id in `getIconKey()` in
   `server-v1.js` (`svcIconMap`).
4. Run `npm run sync-icons:latest`. It fails loudly if the filename doesn't
   exist in the current AWS package, rather than vendoring nothing.

### Giving a service rich detail

1. Add a `case` to the switch in `fetchResourceDetails()` (`server-v1.js`) for
   the new `service:resourceType`, and a small `describeX(config, id)` function
   that calls the service's `Describe*`/`Get*` API and returns a `details`
   object.
2. Add the IAM action it calls to the table in
   [IAM permissions the profile needs](#iam-permissions-the-profile-needs), so
   operators can tell whether their profile is permitted to call it. The app
   grants nothing; permissions come entirely from the chosen profile.
3. If the fetch fails at runtime (e.g. the selected profile lacks that
   permission), it automatically falls back to `genericDetail()` instead of
   showing a bare error - confirmed by the `catch` block wrapping every case.

### Tracking a resource type Resource Explorer doesn't index yet

Not every AWS resource type is indexed by Resource Explorer on day one. As one
example, at the time of writing Resource Explorer indexes
`bedrock-agentcore:runtime` but not that service's Gateway, Memory, or Identity
resources - confirmed against
`aws resource-explorer-2 list-supported-resource-types`, not assumed. For cases
like that, `lib/supplemental-sources/` lets you add a resource type without
building a second, parallel discovery/render/detail path.

Each file in that directory returns items shaped exactly like a Resource
Explorer item (`arn`/`name`/`resourceType`/`service`/`lastReported`). The app
merges them into the same array as `ListResources` output *before* grouping,
icon lookup, and tag extraction run - so a supplemental item gets everything
the UI already does for free, and nothing else in the codebase needs to know
where it came from. See `lib/supplemental-sources/bedrock-agentcore-gateway.js`
for a complete, working example (AgentCore Gateway).

To add one:
1. Copy an existing file in `lib/supplemental-sources/`.
2. Implement `list(config)` (required) and `detail(config, item)` (optional -
   without it, a click falls back to `genericDetail()`).
3. Declare `group` and `icon`, reusing an existing group/icon where sensible
   rather than inventing new UI.
4. List the IAM actions it calls in the module's `iamActions` field, so operators
   can confirm the profile they select is permitted to call them.

To retire one once Resource Explorer adds native support for the type: delete
the file, or set `enabled: false` in it. Nothing else references it by name.
One broken or slow source is logged and skipped - it never blocks Resource
Explorer's own results or any other source.

## Icons

Service icons are the official AWS Architecture Icons, vendored unmodified into
`public/icons/` and served from this origin. See [NOTICE](NOTICE) for
attribution and `scripts/sync-aws-icons.js` for how they are synced.

## License

MIT-0. See [LICENSE](LICENSE).
