#!/usr/bin/env node
/**
 * AWS Resource Viewer v1
 *
 * This version:
 *   1. Uses AWS Resource Explorer's ListResources API for initial inventory (1-2 calls)
 *   2. Lazy-loads detailed resource info on-demand when a user clicks a resource
 *
 * Resource Groups:
 *   Compute, Containers, Database, Storage, Networking, Messaging,
 *   Security, Integration, CI/CD, AI/ML, IAM, Other
 *
 * Prerequisites:
 *   - AWS Resource Explorer must be enabled in the account
 *   - An index (local or aggregator) must exist in the queried region
 *
 * Usage:
 *   node server-v1.js
 *   Then open http://localhost:3000
 */

const fs = require('fs');
const express = require('express');
const path = require('path');

/**
 * Load .env into process.env if present. Hand-rolled instead of
 * `node --env-file` (Node 22+ only, breaks the >=18 engines range) or the
 * dotenv package (an extra dependency for ~15 lines). Real environment
 * variables win over .env, matching container and CI precedence.
 */
function loadDotEnvIfPresent(envPath) {
    if (!fs.existsSync(envPath)) return;
    for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eq = trimmed.indexOf('=');
        if (eq === -1) continue;
        const key = trimmed.slice(0, eq).trim();
        let value = trimmed.slice(eq + 1).trim();
        if (/^".*"$/.test(value) || /^'.*'$/.test(value)) value = value.slice(1, -1);
        if (!(key in process.env)) process.env[key] = value;
    }
}
loadDotEnvIfPresent(path.join(__dirname, '.env'));

// Credentials come from the operator's own AWS CLI profiles (see lib/).
const { loadConfig } = require('./lib/config');
const profiles = require('./lib/profiles');
const { resolveCredentials, invalidateCredentials } = require('./lib/credentials');
const supplementalSources = require('./lib/supplemental-sources');

// Resource Explorer SDK
const {
    ResourceExplorer2Client,
    ListResourcesCommand,
    GetIndexCommand
} = require('@aws-sdk/client-resource-explorer-2');

// Detail fetchers (on-demand only). Only the services that fetchResourceDetails
// actually describes are imported; everything else falls to its default branch
// and shows discovery-level info without an extra API call.
const {
    EC2Client, DescribeInstancesCommand, DescribeNatGatewaysCommand,
    DescribeVpcsCommand, DescribeSubnetsCommand, DescribeSecurityGroupsCommand,
    DescribeRouteTablesCommand, DescribeInternetGatewaysCommand,
    DescribeAddressesCommand, DescribeVpcEndpointsCommand
} = require('@aws-sdk/client-ec2');
const { LambdaClient, GetFunctionConfigurationCommand } = require('@aws-sdk/client-lambda');
const { DynamoDBClient, DescribeTableCommand } = require('@aws-sdk/client-dynamodb');
const { SQSClient, GetQueueAttributesCommand, GetQueueUrlCommand } = require('@aws-sdk/client-sqs');
const { SNSClient, GetTopicAttributesCommand } = require('@aws-sdk/client-sns');
const { RDSClient, DescribeDBInstancesCommand } = require('@aws-sdk/client-rds');
const { SecretsManagerClient, DescribeSecretCommand } = require('@aws-sdk/client-secrets-manager');
const { ECSClient, DescribeServicesCommand, DescribeClustersCommand } = require('@aws-sdk/client-ecs');
const { EKSClient, DescribeClusterCommand } = require('@aws-sdk/client-eks');
const { ElasticLoadBalancingV2Client, DescribeLoadBalancersCommand } = require('@aws-sdk/client-elastic-load-balancing-v2');
const { CloudFrontClient, GetDistributionCommand } = require('@aws-sdk/client-cloudfront');
const { EFSClient, DescribeFileSystemsCommand } = require('@aws-sdk/client-efs');
const { ElastiCacheClient, DescribeCacheClustersCommand } = require('@aws-sdk/client-elasticache');
const { OpenSearchClient, DescribeDomainCommand } = require('@aws-sdk/client-opensearch');
const { ECRClient, DescribeRepositoriesCommand } = require('@aws-sdk/client-ecr');
const { SFNClient, DescribeStateMachineCommand } = require('@aws-sdk/client-sfn');
const { EventBridgeClient, DescribeRuleCommand } = require('@aws-sdk/client-eventbridge');
const { SSMClient, DescribeParametersCommand } = require('@aws-sdk/client-ssm');
const { IAMClient, GetRoleCommand, GetPolicyCommand, GetUserCommand, GetInstanceProfileCommand } = require('@aws-sdk/client-iam');
const { CloudFormationClient, DescribeStacksCommand } = require('@aws-sdk/client-cloudformation');
const { CloudWatchClient, DescribeAlarmsCommand } = require('@aws-sdk/client-cloudwatch');
const { CloudWatchLogsClient, DescribeLogGroupsCommand } = require('@aws-sdk/client-cloudwatch-logs');
const { KMSClient, DescribeKeyCommand } = require('@aws-sdk/client-kms');
const { ACMClient, DescribeCertificateCommand } = require('@aws-sdk/client-acm');

// Fail fast on missing/invalid configuration.
let CFG;
try {
    CFG = loadConfig();
} catch (err) {
    console.error('\nConfiguration error\n');
    console.error(err.message + '\n');
    process.exit(1);
}

const app = express();
const PORT = CFG.port;
const HOST = CFG.host;

/**
 * Validate an AWS region identifier.
 *
 * The previous inline regex was /^[a-z]{2}(-[a-z]+)+-\d$/. Its nested quantifier
 * -- (-[a-z]+)+ -- is the classic ReDoS shape: a crafted string can force
 * catastrophic backtracking. The input here is caller-supplied, so a public
 * sample should not model that pattern even though the blast radius is small.
 *
 * This form has no nested quantifier and cannot backtrack pathologically:
 * exactly two or three lowercase segments separated by single hyphens, ending
 * in a digit -- covering us-east-1, ap-southeast-1, us-gov-east-1, etc. The
 * length guard makes any backtracking question moot regardless.
 */
const REGION_RE = /^[a-z]{2}-[a-z]+-\d$|^[a-z]{2}-[a-z]+-[a-z]+-\d$/;
function isValidRegion(region) {
    return typeof region === 'string' && region.length <= 32 && REGION_RE.test(region);
}

app.use(express.json({ limit: '64kb' }));

// Baseline response headers.
//
// No Content-Security-Policy: the page uses inline on* handlers and an inline
// <script>, so any CSP permissive enough to keep it working would need
// 'unsafe-inline' and buy almost nothing. The real XSS defence here is escaping
// every interpolation (see escHtml in the page script) - if you restructure the
// frontend to external scripts and addEventListener, add a strict CSP then.
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    next();
});

// CSRF defence for state-changing requests.
//
// There is no cookie or session to protect - credentials are resolved
// server-side per request - but the routes still act on the operator's AWS
// access, so a page on another origin must not be able to drive them. With no
// cookie involved, this Origin check is the whole defence rather than a second
// layer: state-changing routes here are same-origin JSON fetches from this
// app's own page, so require the Origin (or Referer) to match this host.
// A cross-site attacker cannot forge Origin from a browser, and a simple
// <form> cross-site POST cannot send Content-Type: application/json without a
// preflight - which this check plus the JSON body parser already gate.
app.use((req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();

    const origin = req.get('origin') || req.get('referer');
    // No Origin/Referer at all (e.g. curl) is allowed: those are not browser
    // CSRF vectors, and blocking them would break legitimate CLI use.
    if (!origin) return next();

    let host;
    try { host = new URL(origin).host; } catch { return res.status(403).json({ error: 'Bad origin' }); }
    if (host !== req.get('host')) {
        return res.status(403).json({ error: 'Cross-origin request refused' });
    }
    next();
});

// Vendored AWS icons, served from this origin (no third-party CDN) so the page
// never makes a third-party request and a CSP of img-src 'self' stays viable.
app.use('/icons', express.static(path.join(__dirname, 'public', 'icons'), {
    maxAge: '1h',
    fallthrough: true
}));

// ─── AWS profiles ──────────────────────────────────────────────────────────────
//
// There is no application login. The user selects an AWS CLI profile and the
// server resolves credentials for it through the standard credential chain,
// exactly as the `aws` command would.

/**
 * GET /api/profiles
 *
 * The profile picker's data source. Returns profile NAMES and non-sensitive
 * metadata only - never a key, secret, session token, or SSO token. Credentials
 * are resolved server-side per request and never serialised to the browser.
 */
app.get('/api/profiles', (req, res) => {
    try {
        const list = profiles.listProfiles();
        res.json({
            profiles: list,
            // Both paths are reported because a profile can be defined in
            // either file, and the picker names them so the operator knows
            // which files were actually read.
            configFile: profiles.configPath(),
            credentialsFile: profiles.credentialsPath()
        });
    } catch (err) {
        console.error('Could not list AWS profiles:', err.message);
        res.status(500).json({ error: 'Could not read AWS CLI configuration.' });
    }
});

/**
 * Resolve the profile named in a request body, or fail with a 400/401 the UI can
 * act on.
 *
 * Validating against the real profile list keeps a caller-supplied string out of
 * credential resolution. Returns { credentials } on success, or sends a response
 * and returns null.
 */
/**
 * Did AWS reject the credentials themselves, as opposed to denying one action?
 *
 * These arrive from the service call, not from credential resolution: the keys
 * in ~/.aws parse and resolve happily, and only the API call reveals they are
 * dead. AccessDeniedException is deliberately NOT here - that means valid
 * credentials lacking a permission, which is a different fix.
 */
const REJECTED_CREDENTIAL_ERRORS = new Set([
    'UnrecognizedClientException',   // key not recognised (deactivated/deleted)
    'InvalidClientTokenId',          // same, as STS words it
    'ExpiredToken',
    'ExpiredTokenException',
    'InvalidAccessKeyId',
    'SignatureDoesNotMatch',         // secret no longer matches the key id
    'AuthFailure'
]);

function isRejectedCredentials(err) {
    return !!err && (REJECTED_CREDENTIAL_ERRORS.has(err.name) ||
                     REJECTED_CREDENTIAL_ERRORS.has(err.Code));
}

/**
 * Evict the dead credentials and tell the operator what to do.
 *
 * Evicting matters: without it the cache serves the same rejected keys for up to
 * five minutes, so refreshing credentials appears to change nothing and the
 * obvious conclusion is that the refresh failed. Clearing here means the very
 * next request re-reads ~/.aws.
 */
function rejectedCredentialsResponse(profileName, err) {
    if (profileName) invalidateCredentials(profileName);
    console.error('Credentials for profile ' + profileName + ' were rejected by AWS (' +
                  err.name + '). Cache cleared; next request will re-read ~/.aws.');
    return {
        code: 'PROFILE_REAUTH',
        profile: profileName,
        error: 'AWS rejected the credentials for profile "' + profileName + '" (' + err.name + '). ' +
               'They may have expired, been rotated, or been deactivated. Refresh them ' +
               '(for SSO: aws sso login --profile ' + profileName + '), then try again - ' +
               'no restart needed. Verify with: aws sts get-caller-identity --profile ' + profileName
    };
}

async function credentialsForRequest(req, res, profileName, region) {
    if (!profileName) {
        res.status(400).json({ code: 'NO_PROFILE', error: 'Select an AWS profile first.' });
        return null;
    }
    if (!profiles.isKnownProfile(profileName)) {
        res.status(400).json({
            code: 'UNKNOWN_PROFILE',
            error: 'Profile "' + profileName + '" is not configured in the AWS CLI on this machine.'
        });
        return null;
    }
    try {
        return await resolveCredentials(profileName, region || CFG.region);
    } catch (err) {
        // PROFILE_REAUTH means a stale SSO session - actionable by the user, so
        // the message (which names the exact command) is passed through.
        const status = err.code === 'PROFILE_REAUTH' ? 401 : 502;
        console.error('Credential resolution failed for profile ' + profileName + ':', err.message);
        res.status(status).json({ code: err.code || 'PROFILE_UNUSABLE', profile: profileName, error: err.message });
        return null;
    }
}

// ─── Resource Type → Group Mapping ─────────────────────────────────────────────

const RESOURCE_GROUP_MAP = {
    // Compute
    'ec2:instance': 'Compute',
    'lambda:function': 'Compute',
    'autoscaling:autoScalingGroup': 'Compute',
    'elasticbeanstalk:environment': 'Compute',
    'batch:job-queue': 'Compute',
    'ec2:launch-template': 'Compute',
    'lightsail:instance': 'Compute',

    // Containers
    'ecs:cluster': 'Containers',
    'ecs:service': 'Containers',
    'ecs:task': 'Containers',
    'ecs:task-definition': 'Containers',
    'eks:cluster': 'Containers',
    'ecr:repository': 'Containers',

    // Database
    'rds:db': 'Database',
    'rds:cluster': 'Database',
    'dynamodb:table': 'Database',
    'dynamodb:global-table': 'Database',
    'elasticache:cluster': 'Database',
    'opensearch:domain': 'Database',
    'redshift:cluster': 'Database',
    'neptune:db': 'Database',
    'docdb:cluster': 'Database',

    // Storage
    's3:bucket': 'Storage',
    'efs:file-system': 'Storage',
    'fsx:file-system': 'Storage',
    'backup:backup-vault': 'Storage',
    'ebs:volume': 'Storage',
    'ec2:volume': 'Storage',

    // Networking
    'elasticloadbalancing:loadbalancer': 'Networking',
    'elasticloadbalancing:targetgroup': 'Networking',
    'cloudfront:distribution': 'Networking',
    'ec2:natgateway': 'Networking',
    'ec2:vpc': 'Networking',
    'ec2:subnet': 'Networking',
    'ec2:security-group': 'Networking',
    'ec2:elastic-ip': 'Networking',
    'route53:hostedzone': 'Networking',
    'ec2:internet-gateway': 'Networking',
    'ec2:route-table': 'Networking',
    'ec2:vpc-endpoint': 'Networking',

    // Messaging
    'sqs:queue': 'Messaging',
    'sns:topic': 'Messaging',
    'eventbridge:rule': 'Messaging',
    'events:rule': 'Messaging',
    'events:event-bus': 'Messaging',
    'kinesis:stream': 'Messaging',

    // Security
    'secretsmanager:secret': 'Security',
    'ssm:parameter': 'Security',
    'kms:key': 'Security',
    'acm:certificate': 'Security',
    'wafv2:webacl': 'Security',
    'guardduty:detector': 'Security',

    // Integration
    'states:stateMachine': 'Integration',
    'stepfunctions:stateMachine': 'Integration',
    'sns:subscription': 'Integration',
    'appsync:graphqlapi': 'Integration',
    'apigateway:restapi': 'Integration',
    'apigateway:api': 'Integration',
    'apigateway:websocket-api': 'Integration',

    // CI/CD
    'codebuild:project': 'CI/CD',
    'codedeploy:application': 'CI/CD',
    'codedeploy:deploymentgroup': 'CI/CD',
    'codepipeline:pipeline': 'CI/CD',
    'cloudformation:stack': 'CI/CD',
    'cloudformation:stackset': 'CI/CD',

    // AI/ML
    'sagemaker:endpoint': 'AI/ML',
    'sagemaker:notebook-instance': 'AI/ML',
    'sagemaker:model': 'AI/ML',
    'bedrock:model': 'AI/ML',
    'bedrock-agentcore:runtime': 'AI/ML',
    'comprehend:entity-recognizer': 'AI/ML',
    'rekognition:project': 'AI/ML',

    // IAM
    'iam:role': 'IAM',
    'iam:policy': 'IAM',
    'iam:user': 'IAM',
    'iam:group': 'IAM',
    'iam:instance-profile': 'IAM',

    // Observability
    'logs:log-group': 'Observability',
    'cloudwatch:alarm': 'Observability',
    'cloudtrail:trail': 'Observability'
};

/**
 * Determine group for a resource based on its ResourceType (e.g., "ec2:instance")
 * or Service (e.g., "ec2") field from Resource Explorer.
 */
function classifyResource(resourceType, service) {
    const rt = (resourceType || '').toLowerCase();
    const svc = (service || '').toLowerCase();

    // A supplemental source's declared group takes priority, so a type it
    // owns is grouped correctly even before anyone adds it to the static maps
    // below (see lib/supplemental-sources).
    const supplemental = supplementalSources.findSourceForType(rt);
    if (supplemental) return supplemental.group;

    // Direct match
    if (RESOURCE_GROUP_MAP[rt]) return RESOURCE_GROUP_MAP[rt];

    // Try service:type format normalization
    const normalized = rt.replace('::', ':').toLowerCase();
    if (RESOURCE_GROUP_MAP[normalized]) return RESOURCE_GROUP_MAP[normalized];

    // Fallback by service name
    const serviceGroupMap = {
        'ec2': 'Compute',
        'lambda': 'Compute',
        'autoscaling': 'Compute',
        'elasticbeanstalk': 'Compute',
        'batch': 'Compute',
        'lightsail': 'Compute',
        'ecs': 'Containers',
        'eks': 'Containers',
        'ecr': 'Containers',
        'rds': 'Database',
        'dynamodb': 'Database',
        'elasticache': 'Database',
        'opensearch': 'Database',
        'redshift': 'Database',
        'neptune': 'Database',
        'docdb': 'Database',
        's3': 'Storage',
        'efs': 'Storage',
        'fsx': 'Storage',
        'backup': 'Storage',
        'elasticloadbalancing': 'Networking',
        'cloudfront': 'Networking',
        'route53': 'Networking',
        'sqs': 'Messaging',
        'sns': 'Messaging',
        'events': 'Messaging',
        'eventbridge': 'Messaging',
        'kinesis': 'Messaging',
        'secretsmanager': 'Security',
        'ssm': 'Security',
        'kms': 'Security',
        'acm': 'Security',
        'wafv2': 'Security',
        'guardduty': 'Security',
        'states': 'Integration',
        'stepfunctions': 'Integration',
        'appsync': 'Integration',
        'apigateway': 'Integration',
        'codebuild': 'CI/CD',
        'codedeploy': 'CI/CD',
        'codepipeline': 'CI/CD',
        'cloudformation': 'CI/CD',
        'sagemaker': 'AI/ML',
        'bedrock': 'AI/ML',
        'bedrock-agentcore': 'AI/ML',
        'comprehend': 'AI/ML',
        'rekognition': 'AI/ML',
        'iam': 'IAM',
        'cognito-idp': 'IAM',
        'cognito-identity': 'IAM',
        'logs': 'Observability',
        'cloudwatch': 'Observability',
        'cloudtrail': 'Observability',
        'xray': 'Observability',
        'ce': 'Observability',
        'cost-optimization-hub': 'Observability',
        'auditmanager': 'Security',
        'apprunner': 'Compute',
        'memorydb': 'Database',
        'athena': 'Analytics',
        'databrew': 'Analytics',
        'resource-explorer-2': 'Observability'
    };

    if (serviceGroupMap[svc]) return serviceGroupMap[svc];

    return 'Other';
}

/**
 * Map a Resource Explorer resource type to an icon key for the frontend.
 */
function getIconKey(resourceType, service) {
    const rt = (resourceType || '').toLowerCase();
    const svc = (service || '').toLowerCase();

    // A supplemental source's declared icon takes priority, for the same
    // reason as classifyResource above.
    const supplemental = supplementalSources.findSourceForType(rt);
    if (supplemental) return supplemental.icon;

    // Exact resource-type overrides, where a type needs a different icon than
    // its service default (e.g. ECS service vs cluster, EC2 NAT gateway vs
    // instance, and EC2 networking sub-types that belong under the VPC icon).
    const iconMap = {
        'ec2:instance': 'ec2',
        'ec2:natgateway': 'natgw',
        'ec2:vpc': 'vpc',
        'ec2:subnet': 'vpc',
        'ec2:security-group': 'vpc',
        'ec2:security-group-rule': 'vpc',
        'ec2:route-table': 'vpc',
        'ec2:network-acl': 'vpc',
        'ec2:network-interface': 'vpc',
        'ec2:internet-gateway': 'vpc',
        'ec2:elastic-ip': 'vpc',
        'ec2:vpc-endpoint': 'vpc',
        'ec2:dhcp-options': 'vpc',
        'ec2:launch-template': 'ec2',
        'ecs:service': 'ecsServices',
        'apigateway:restapi': 'apigateway',
        'apigateway:api': 'apigateway'
    };
    if (iconMap[rt]) return iconMap[rt];

    // Service-level default. Resource Explorer's service token is the part
    // before the colon in the resource type; map it to a vendored icon key.
    const svcIconMap = {
        'ec2': 'ec2', 'autoscaling': 'asg', 'lambda': 'lambda',
        'elasticbeanstalk': 'beanstalk', 'batch': 'batch', 'apprunner': 'apprunner',
        's3': 's3', 'efs': 'efs',
        'dynamodb': 'dynamodb', 'rds': 'rds', 'elasticache': 'elasticache',
        'memorydb': 'memorydb', 'redshift': 'redshift',
        'sqs': 'sqs', 'sns': 'sns', 'kinesis': 'kinesis',
        'apigateway': 'apigateway', 'states': 'stepfunctions', 'stepfunctions': 'stepfunctions',
        'events': 'eventbridge', 'eventbridge': 'eventbridge',
        'ecs': 'ecs', 'eks': 'eks', 'ecr': 'ecr',
        'elasticloadbalancing': 'elb', 'cloudfront': 'cloudfront',
        'ec2': 'ec2', 'route53': 'route53',
        'opensearch': 'opensearch', 'es': 'opensearch', 'athena': 'athena',
        'secretsmanager': 'secrets', 'ssm': 'ssm', 'iam': 'iam',
        'kms': 'kms', 'acm': 'acm', 'cognito-idp': 'cognito', 'cognito': 'cognito',
        'guardduty': 'guardduty',
        'cloudwatch': 'cloudwatch', 'logs': 'cloudwatch', 'cloudtrail': 'cloudtrail',
        'cloudformation': 'cloudformation', 'codebuild': 'codebuild',
        'bedrock': 'bedrock', 'bedrock-agentcore': 'bedrock', 'sagemaker': 'sagemaker',
        'xray': 'xray'
    };

    // 'generic' is always a valid vendored icon, so the UI never renders a bare
    // text badge for an unmapped long-tail resource type.
    return svcIconMap[svc] || 'generic';
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function toIso(value) {
    if (!value) return '-';
    const d = value instanceof Date ? value : new Date(value);
    return Number.isNaN(d.getTime()) ? '-' : d.toISOString();
}

/** Extract a human-friendly name from an ARN */
function nameFromArn(arn) {
    if (!arn) return 'unknown';
    const parts = arn.split(/[:/]/);
    return parts[parts.length - 1] || parts[parts.length - 2] || arn;
}

/**
 * The resource's FULL identifier from its ARN, preserving embedded slashes.
 *
 * nameFromArn keeps only the last segment, which is fine for a short display
 * label but wrong as an API identifier for any path-style name: the log group
 * /aws/lambda/my-fn collapses to "my-fn", the SSM parameter /prod/db/password
 * to "password", and the ECR repository team/svc/api to "api". Describe calls
 * built from those values either miss or, worse, prefix-match a DIFFERENT
 * resource and report its data as the requested one.
 *
 * The resource portion of an ARN is service-specific and separated from its
 * type by either ':' or '/', whichever comes first:
 *   logs   arn:aws:logs:r:acct:log-group:/aws/lambda/my-fn:*
 *   ssm    arn:aws:ssm:r:acct:parameter/prod/db/password
 *   ecr    arn:aws:ecr:r:acct:repository/team/svc/api
 *   ec2    arn:aws:ec2:r:acct:instance/i-0123
 */
function resourceIdFromArn(arn) {
    if (!arn) return '';
    const parts = String(arn).split(':');
    if (parts.length < 6) return String(arn);

    // Rejoin - the resource portion itself can contain ':'.
    let resource = parts.slice(5).join(':');

    // CloudWatch Logs appends a ':*' wildcard to log-group ARNs.
    resource = resource.replace(/:\*$/, '');

    // Split on the FIRST delimiter, whichever kind it is. Testing for '/'
    // before ':' would mis-split log-group ARNs, whose id starts with '/'.
    const m = resource.match(/^([^:/]+)([:/])([\s\S]+)$/);
    if (!m) return resource;

    const [, type, sep, id] = m;

    // ':' separator - the id is already complete, including any leading slash.
    if (sep === ':') return id;

    // '/' separator. SSM parameter names are path-style and the leading slash
    // is part of the name; most other types' ids are not.
    if (type === 'parameter') return '/' + id;
    return id;
}

// ─── API Routes ────────────────────────────────────────────────────────────────

/**
 * POST /api/discover-resources
 * Uses Resource Explorer ListResources to get an inventory of all resources.
 * Returns grouped resources with minimal info (ARN, type, name, region, group).
 * This replaces the 25+ individual API calls with 1 paginated call.
 */
// Page size for ListResources. Must stay BELOW 1000: the API documents that
// "ListResources does not generate a NextToken if you set MaxResults to 1000",
// so requesting the maximum silently disables pagination and caps discovery at
// one page. That looked like a working inventory while quietly dropping
// everything past the first 1000 resources.
const RE_PAGE_SIZE = 500;

// Upper bound on what one region query will accumulate and render. Reaching it
// is reported to the client rather than silently trimmed.
const MAX_RESOURCES = 20000;

// Global resources (IAM, CloudFront, Route 53, Cost Explorer) have no region of
// their own, and Resource Explorer indexes them in us-east-1 ONLY. A LOCAL index
// holds just its own region's resources, so `region:global` returns 0 everywhere
// else even with a healthy index. Verified live: 247 results in us-east-1, 0 in
// us-east-2, Complete:true in both.
//
// So to show global resources alongside, say, us-east-2, they must be fetched
// from us-east-1 explicitly. That is what this constant is for. The alternative
// - an AGGREGATOR index - is deliberately not used: one per account, promotion
// is rate-limited to once per 24h, and it forces indexing on regions the
// operator may not want indexed.
const GLOBAL_INDEX_REGION = 'us-east-1';

/**
 * Bounded network behaviour for Resource Explorer calls.
 *
 * Without this, choosing a region the account is not opted into hangs the
 * request for minutes: the endpoint (resource-explorer-2.me-south-1.amazonaws.com,
 * for one) accepts no connection, and the SDK's default retry policy keeps
 * trying with exponential backoff. Measured live - a single GetIndex against
 * me-south-1 had still not returned after 120 seconds, so the UI just sat there
 * with no panel and no error.
 *
 * A dead region should be reported in seconds, not eventually. These bounds are
 * generous for a working region (a live index query returns well inside 3s) and
 * cap the unreachable case at about 8s, verified against me-south-1.
 *
 * requestHandler is passed as a plain options object on purpose. The alternative
 * is importing NodeHttpHandler from @smithy/node-http-handler, which is only a
 * transitive dependency here - relying on it directly would break the day the
 * tree flattens differently.
 */
const RE_CONNECT_TIMEOUT_MS = 4000;
const RE_REQUEST_TIMEOUT_MS = 8000;
const RE_MAX_ATTEMPTS = 2;

function resourceExplorerClient(region, credentials) {
    return new ResourceExplorer2Client({
        region,
        credentials,
        maxAttempts: RE_MAX_ATTEMPTS,
        requestHandler: {
            connectionTimeout: RE_CONNECT_TIMEOUT_MS,
            requestTimeout: RE_REQUEST_TIMEOUT_MS
        }
    });
}

/**
 * Is this failure the region being unreachable, rather than anything to do with
 * the caller's credentials or permissions?
 *
 * Regions the account has not opted into fail in two different shapes, both seen
 * live: me-south-1 accepts no connection (a TimeoutError from the socket), while
 * af-south-1 answers and rejects the request outright. Only the first is
 * unambiguous here - the second is indistinguishable from expired credentials by
 * error name, and is separated out by probing in regionOrCredentialFailure().
 */
function isRegionUnreachable(err) {
    if (!err) return false;
    const name = err.name || '';
    const code = err.code || '';
    const msg = err.message || '';
    return name === 'TimeoutError' || name === 'RequestTimeout' ||
           code === 'ETIMEDOUT' || code === 'ECONNREFUSED' ||
           code === 'ENOTFOUND' || code === 'EAI_AGAIN' ||
           /did not establish a connection|connect timeout|socket hang up|getaddrinfo/i.test(msg);
}

/**
 * Decide whether a failed call means "this region is unusable" or "these
 * credentials are dead", and answer accordingly.
 *
 * AWS returns UnrecognizedClientException for BOTH an expired key and a region
 * the account has not opted into, so the error alone cannot separate them - and
 * guessing is wrong in a costly direction either way. Blaming the credentials
 * sends the operator off to re-authenticate for nothing and evicts a perfectly
 * good cached credential (which is exactly what this code did when first
 * written, on a region that was merely disabled). Blaming the region would hide
 * a real expiry.
 *
 * So ask a region known to work. If the same credentials succeed there, they are
 * fine and the requested region is at fault. One extra call, only on this path.
 *
 * Returns { status, body } to send, or null when this is neither case.
 */
async function regionOrCredentialFailure(err, profileName, region, credentials) {
    if (isRegionUnreachable(err)) {
        return { status: 409, body: regionUnavailableBody(region, err) };
    }
    if (!isRejectedCredentials(err)) return null;

    // Nothing to compare against when the requested region already IS the
    // reference region, so trust the original error.
    if (region !== GLOBAL_INDEX_REGION) {
        try {
            await resourceExplorerClient(GLOBAL_INDEX_REGION, credentials)
                .send(new GetIndexCommand({}));
            return { status: 409, body: regionUnavailableBody(region, err) };
        } catch (probeErr) {
            // The probe failing for a reason of its own (no index in us-east-1,
            // say) does not prove the credentials are bad either.
            if (!isRejectedCredentials(probeErr)) {
                return { status: 409, body: regionUnavailableBody(region, err) };
            }
        }
    }
    return { status: 401, body: rejectedCredentialsResponse(profileName, err) };
}

/**
 * Reuses the NO_INDEX code deliberately. To the operator this is the same
 * situation - "this region cannot be viewed yet, and here is why" - and the UI
 * already renders NO_INDEX as an informative panel rather than a toast. A
 * separate code would need parallel UI for no added clarity.
 */
function regionUnavailableBody(region, err) {
    return {
        code: 'NO_INDEX',
        region,
        error: 'Could not reach AWS Resource Explorer in ' + region + ' (' + (err.name || 'unreachable') + '). ' +
               'Usually this means the region is not enabled for this AWS account - opt in under ' +
               'Account settings > Regions in the console, then try again. It can also mean the ' +
               'region has no Resource Explorer index yet.'
    };
}

app.post('/api/discover-resources', async (req, res) => {
    const { region, profile, includeGlobal } = req.body || {};

    // Whether to include the account's global resources (IAM, CloudFront,
    // Route 53) alongside this region's own. Defaults to true so every pane is a
    // complete picture and IAM is present whichever region is being viewed; the
    // UI de-duplicates by ARN when totalling, so the same role appearing in two
    // panes does not inflate the count. A caller that only wants one region's
    // own resources can pass false and skip the extra query.
    const wantGlobal = includeGlobal !== false;

    if (!region) {
        return res.status(400).json({ error: 'Missing region' });
    }
    if (!isValidRegion(region)) {
        return res.status(400).json({ error: 'Invalid region: ' + region });
    }

    // Credentials come from the selected AWS CLI profile. The profile name is
    // validated against the machine's real profile list before use.
    const awsCredentials = await credentialsForRequest(req, res, profile, region);
    if (!awsCredentials) return; // response already sent

    const config = { region, credentials: awsCredentials };

    // Bounded client: an unreachable region must fail in seconds. See
    // resourceExplorerClient().
    const client = resourceExplorerClient(region, awsCredentials);

    // Preflight: Resource Explorer only returns data when an index (and a
    // default view) exist in the region. Detect that up front and return a
    // structured, actionable signal instead of an opaque empty result.
    try {
        const idx = await client.send(new GetIndexCommand({}));

        // A region needs its OWN, usable index. Two gaps this guards against,
        // both observed live:
        //
        //  1. GetIndex in a region with no index can still return an index
        //     record the account routes to, and can report State DELETED for a
        //     torn-down index. Checking only idx.Arn accepted both, so a region
        //     the user never set up looked "ready" and then returned a
        //     confusing empty result rather than a prompt to set it up.
        //  2. The index's ARN region must match the region being queried. An
        //     index in another region answering this call is not the same as
        //     this region being indexed, and its contents belong to that other
        //     region.
        //
        // Separately, and NOT a fault this preflight can detect: global
        // resources (IAM, CloudFront, Route 53) are indexed only in us-east-1.
        // The region:global query below therefore returns 0 in every other
        // region even with a healthy ACTIVE local index. That is correct AWS
        // behaviour - a LOCAL index holds only its own region's resources - so
        // an empty global result outside us-east-1 must not be reported as a
        // setup problem. Verified live: region:global returns 247 in us-east-1
        // and 0 in us-east-2, Complete:true in both.
        //
        // Anything short of an ACTIVE index owned by this region is treated the
        // same as "not enabled here" so the UI prompts the user to create one.
        const indexRegion = idx && idx.Arn ? idx.Arn.split(':')[3] : null;
        const usableState = idx && (idx.State === 'ACTIVE' || idx.State === 'UPDATING');
        if (!idx || !idx.Arn || !usableState || indexRegion !== region) {
            throw Object.assign(new Error('no usable index in ' + region), { name: 'ResourceNotFoundException' });
        }
    } catch (idxErr) {
        if (idxErr.name === 'ResourceNotFoundException') {
            return res.status(409).json({
                code: 'NO_INDEX',
                region,
                error: 'AWS Resource Explorer has no index in ' + region + '. ' +
                       'Each region you want to view needs its own Resource Explorer index. ' +
                       'Create one for ' + region + ' in the console (Resource Explorer > Settings), ' +
                       'or run: aws resource-explorer-2 create-index --region ' + region + ' ' +
                       '(then create a view and make it the default). Indexing takes a few minutes.'
            });
        }
        // An unreachable or disabled region is caught here rather than being
        // allowed to fall through: the main ListResources call below would fail
        // the same way but is harder to attribute, and this is the path that
        // produces the informative setup panel.
        const classified = await regionOrCredentialFailure(idxErr, profile, region, awsCredentials);
        if (classified) {
            console.warn('Preflight for ' + region + ' failed:', idxErr.name, '->', classified.body.code);
            return res.status(classified.status).json(classified.body);
        }
        if (idxErr.name === 'AccessDeniedException') {
            return res.status(403).json({
                code: 'ACCESS_DENIED',
                error: 'This profile lacks Resource Explorer read permissions ' +
                       '(resource-explorer-2:GetIndex and resource-explorer-2:ListResources). ' +
                       'Select a profile with read access, or ask an admin to grant them - the ' +
                       'AWSResourceExplorerReadOnlyAccess managed policy is enough.'
            });
        }
        // Unknown preflight failure: fall through and let the main call surface it.
    }

    try {
        const allResources = [];
        let nextToken;
        // Set when the inventory returned is knowingly incomplete, so the UI can
        // say so instead of presenting a partial count as the whole account.
        let truncated = false;
        let partialReason = null;

        // Region-scoped query. `region` is validated against a strict region
        // pattern above before it reaches this filter string; do not introduce
        // another caller-supplied value here without validating it the same
        // way, since this string is Resource Explorer query syntax and an
        // unvalidated value can inject filter terms.
        const filterString = `region:${region}`;

        do {
            const params = {
                MaxResults: RE_PAGE_SIZE,
                ...(nextToken && { NextToken: nextToken }),
                Filters: { FilterString: filterString }
            };

            const response = await client.send(new ListResourcesCommand(params));
            if (response.Resources) {
                allResources.push(...response.Resources);
            }
            nextToken = response.NextToken;
            if (allResources.length >= MAX_RESOURCES) { truncated = true; break; }
        } while (nextToken);

        // Global resources (IAM, CloudFront, Route 53, Cost Explorer) are a
        // second query, always issued against GLOBAL_INDEX_REGION because that
        // is the only region whose index holds them - see the constant. When the
        // caller is already asking for that region we reuse the client we have;
        // otherwise we need one pinned to it, which is what makes globals
        // visible alongside a region like us-east-2 at all.
        if (wantGlobal) {
            const globalClient = region === GLOBAL_INDEX_REGION
                ? client
                : resourceExplorerClient(GLOBAL_INDEX_REGION, awsCredentials);

            nextToken = undefined;
            try {
                do {
                    const params = {
                        MaxResults: RE_PAGE_SIZE,
                        ...(nextToken && { NextToken: nextToken }),
                        Filters: { FilterString: 'region:global' }
                    };
                    const response = await globalClient.send(new ListResourcesCommand(params));
                    if (response.Resources) {
                        allResources.push(...response.Resources);
                    }
                    nextToken = response.NextToken;
                    if (allResources.length >= MAX_RESOURCES) { truncated = true; break; }
                } while (nextToken);
            } catch (globalErr) {
                // A failure here still leaves a usable region result, but the
                // inventory is then incomplete and saying nothing would present
                // a partial list as the whole account. Flag it and log it rather
                // than swallowing it.
                //
                // The common cause is now specific enough to name: pulling
                // globals requires an index in GLOBAL_INDEX_REGION, which the
                // operator may never have created if they only work in another
                // region. That is a different fix from the queried region's own
                // index, so it gets its own message.
                const missingIndex = globalErr.name === 'ResourceNotFoundException' ||
                                     globalErr.name === 'UnauthorizedException';
                partialReason = missingIndex
                    ? 'Global resources (IAM, CloudFront, Route 53) are indexed only in ' +
                      GLOBAL_INDEX_REGION + ', which has no usable Resource Explorer index. ' +
                      'Create one there to include them.'
                    : 'Global resources (IAM, CloudFront, Route 53) could not be listed: ' + globalErr.name;
                console.warn('global resource query failed:', globalErr.name, globalErr.message);
            }
        }

        // Merge in resource types Resource Explorer doesn't index yet (see
        // lib/supplemental-sources). Returned in the same raw shape as
        // ListResources output, so everything below - dedup, classification,
        // icon lookup, tag extraction - treats them identically. One failing
        // source is logged and skipped by collectAll; it never blocks this.
        // Which account these resources belong to. Derived from an already-
        // discovered ARN rather than from STS: every ARN Resource Explorer
        // returned belongs to the account being viewed, so this needs no extra
        // API call and no sts client dependency. Undefined only when the region
        // returned nothing at all.
        //
        // Computed here rather than inside the try below because it is used
        // twice: supplemental sources need it to build ARNs, and the response
        // carries it so the panel header can name the account. The account id is
        // the unambiguous label - a profile name says nothing about which
        // account it actually reaches.
        const discoveredAccountId = accountIdFromResources(allResources);

        try {
            // accountId is passed alongside the SDK client config because some
            // services' List* responses omit the resource ARN (AgentCore's
            // GatewaySummary, for one), leaving a source to build it.
            allResources.push(...(await supplementalSources.collectAll(
                Object.assign({ accountId: discoveredAccountId }, config)
            )));
        } catch (suppErr) {
            console.warn('supplemental sources failed:', suppErr.message);
        }

        // Services whose resources genuinely have no region, and so must not be
        // dropped by the region filter below. Resource Explorer already reports
        // these with Region 'global', so this set is a backstop for the case
        // where it returns no region at all.
        //
        // s3 is deliberately NOT here, though the S3 *namespace* is global. An
        // individual bucket lives in exactly one region and Resource Explorer
        // reports that real region, so a bucket must be filtered like any other
        // regional resource - otherwise a us-east-1 bucket could render in a
        // us-east-2 panel, which is the opposite of showing buckets where they
        // physically are. Verified against live data: a region:global query
        // returns iam, cloudfront, route53 and ce, and never s3.
        const GLOBAL_SERVICES = new Set(['iam', 'cloudfront', 'route53', 'ce', 'waf', 'wafv2', 'organizations']);

        // Group and transform resources, filtering to only the requested region
        // but allowing global resources through
        const grouped = {};
        const seenArns = new Set(); // deduplicate in case of overlap
        const allTagsMap = new Map(); // key -> Set of values

        for (const resource of allResources) {
            // An item with no ARN cannot be deduplicated or rendered usefully,
            // and would otherwise claim the `undefined` key and suppress every
            // later ARN-less item.
            if (!resource.Arn) continue;

            const svc = (resource.Service || '').toLowerCase();
            const isGlobal = GLOBAL_SERVICES.has(svc) || resource.Region === 'global' || !resource.Region;

            // Region filter runs BEFORE the dedup bookkeeping below, not after.
            // Claiming the ARN first meant that when the same ARN arrived twice
            // with different Region values, whichever copy came first took the
            // key - and if that was the copy this filter rejects, the copy that
            // actually belonged to the requested region was then discarded as a
            // duplicate and the resource vanished from the inventory entirely.
            if (!isGlobal && resource.Region && resource.Region !== region) continue;

            if (seenArns.has(resource.Arn)) continue;
            seenArns.add(resource.Arn);

            const group = classifyResource(resource.ResourceType, resource.Service);
            if (!grouped[group]) grouped[group] = [];

            const name = nameFromArn(resource.Arn);
            const iconKey = getIconKey(resource.ResourceType, resource.Service);

            // Extract tags from Properties
            const tags = [];
            for (const prop of (resource.Properties || [])) {
                if (prop.Name === 'tags' && Array.isArray(prop.Data)) {
                    prop.Data.forEach(t => {
                        if (t.Key && !t.Key.startsWith('aws:')) {
                            tags.push({ key: t.Key, value: t.Value || '' });
                            // Track for available tags
                            if (!allTagsMap.has(t.Key)) allTagsMap.set(t.Key, new Set());
                            allTagsMap.get(t.Key).add(t.Value || '');
                        }
                    });
                }
            }

            grouped[group].push({
                arn: resource.Arn,
                name,
                resourceType: resource.ResourceType,
                service: resource.Service,
                region: resource.Region || 'global',
                icon: iconKey,
                lastReported: resource.LastReportedAt,
                tags
            });
        }

        // Build availableTags: { key: [value1, value2, ...] }
        const availableTags = {};
        for (const [key, values] of allTagsMap.entries()) {
            availableTags[key] = [...values].sort();
        }

        // Both conditions can hold at once, so append rather than overwrite -
        // reporting only one would hide the other.
        if (truncated) {
            const capMsg = 'Stopped at the ' + MAX_RESOURCES.toLocaleString() +
                ' resource display limit. This region holds more than are shown.';
            partialReason = partialReason ? partialReason + ' ' + capMsg : capMsg;
        }

        res.json({
            totalResources: Object.values(grouped).reduce((sum, arr) => sum + arr.length, 0),
            groups: grouped,
            availableTags,
            // Null when the region held nothing to read an account from. The UI
            // falls back to the profile name in that case rather than showing a
            // header with a gap in it.
            accountId: discoveredAccountId || null,

            // Non-null whenever the result is knowingly incomplete. An inventory
            // tool that quietly under-reports is worse than one that admits a
            // limit, so this is surfaced rather than logged and forgotten.
            partial: partialReason
        });
    } catch (err) {
        // No default view is the other common "not fully set up" state. It
        // surfaces as UnauthorizedException (401) per the ListResources error
        // list, not ResourceNotFoundException, so match on both - the GetIndex
        // preflight cannot catch it because the index itself does exist.
        if (err.name === 'ResourceNotFoundException' || err.name === 'UnauthorizedException') {
            return res.status(409).json({
                code: 'NO_INDEX',
                region,
                error: 'AWS Resource Explorer has no index, or no default view, in ' + region + '. ' +
                       'A default view is required: this app queries without an explicit ViewArn. ' +
                       'Enable it in the console (Resource Explorer > Settings) for ' + region + '.'
            });
        }
        if (err.name === 'AccessDeniedException') {
            return res.status(403).json({
                code: 'ACCESS_DENIED',
                error: 'This profile is not authorized for resource-explorer-2. ' +
                       'Select a profile with read access to Resource Explorer in ' + region + '.'
            });
        }
        if (err.name === 'ThrottlingException') {
            return res.status(429).json({ error: 'Resource Explorer is rate limiting this account. Try again shortly.' });
        }
        // Region-unreachable is checked before credentials for the same reason as
        // in the preflight: the two produce the same error name, and reporting
        // the wrong one sends the operator to fix something that is not broken.
        const classified = await regionOrCredentialFailure(err, profile, region, awsCredentials);
        if (classified) {
            console.warn('Discovery in ' + region + ' failed:', err.name, '->', classified.body.code);
            return res.status(classified.status).json(classified.body);
        }
        // Log the real error server-side; return a generic message. AWS error
        // text embeds the role ARN, account ID and session name, none of which
        // belongs in a browser response.
        console.error('Discovery failed:', err.name, err.message);
        res.status(500).json({ error: 'Failed to discover resources. See server logs for details.' });
    }
});

/**
 * POST /api/resource-details
 * Fetches detailed info for a single resource on-demand.
 * Called when user clicks a resource in the UI.
 */
app.post('/api/resource-details', async (req, res) => {
    const { region, arn, resourceType, service, lastReported, profile } = req.body || {};

    if (!arn) {
        return res.status(400).json({ error: 'Missing resource ARN' });
    }
    const rgn = region || CFG.region;
    if (!isValidRegion(rgn)) {
        return res.status(400).json({ error: 'Invalid region: ' + rgn });
    }

    const awsCredentials = await credentialsForRequest(req, res, profile, rgn);
    if (!awsCredentials) return; // response already sent

    // accountId must be present here too, not just in discovery: a supplemental
    // source's detail() receives this same config, and the documented contract
    // says accountId is part of it. Omitting it gave list() and detail()
    // different shapes for no reason other than where they were called from.
    // Taken from the resource's own ARN, which is the account being viewed.
    const config = {
        region: rgn,
        credentials: awsCredentials,
        accountId: parseArn(arn).account || undefined
    };

    try {
        const details = await fetchResourceDetails(config, arn, resourceType, service, lastReported);
        res.json(details);
    } catch (err) {
        // Same treatment as discovery: dead credentials are evicted so the next
        // request re-reads ~/.aws, rather than failing identically for five
        // minutes after the operator has already fixed them.
        if (isRejectedCredentials(err)) {
            return res.status(401).json(rejectedCredentialsResponse(profile, err));
        }
        console.error('Detail fetch failed for', arn, '-', err.name, err.message);
        res.status(500).json({ error: 'Failed to fetch resource details.' });
    }
});

// ─── Dependency Graph API ──────────────────────────────────────────────────────

/**
 * Resource types eligible for dependency graph visualization.
 * Only these types show the dependency graph icon in the popup.
 */
const DEPENDENCY_ELIGIBLE_TYPES = new Set([
    'ec2:instance',
    'lambda:function',
    'ecs:cluster',
    'eks:cluster',
    'rds:db',
    'elasticache:cluster',
    'opensearch:domain'
]);

/**
 * Fetch dependency graph for a given resource. Returns a tree structure with
 * at least 2 levels of nesting showing how resources relate to each other.
 */
app.post('/api/resource-dependencies', async (req, res) => {
    const { region, arn, resourceType, service, profile } = req.body || {};

    if (!arn) {
        return res.status(400).json({ error: 'Missing resource ARN' });
    }
    const rgn = region || CFG.region;
    if (!isValidRegion(rgn)) {
        return res.status(400).json({ error: 'Invalid region: ' + rgn });
    }

    const rt = (resourceType || '').toLowerCase();
    if (!DEPENDENCY_ELIGIBLE_TYPES.has(rt)) {
        return res.status(400).json({ error: 'Resource type not eligible for dependency graph' });
    }

    const awsCredentials = await credentialsForRequest(req, res, profile, rgn);
    if (!awsCredentials) return;

    const config = { region: rgn, credentials: awsCredentials };

    try {
        const graph = await fetchDependencyGraph(config, arn, rt);
        res.json(graph);
    } catch (err) {
        if (isRejectedCredentials(err)) {
            return res.status(401).json(rejectedCredentialsResponse(profile, err));
        }
        console.error('Dependency graph failed for', arn, '-', err.name, err.message);
        res.status(500).json({ error: 'Failed to fetch dependency graph.' });
    }
});

/**
 * Build a dependency tree for the given resource. Each node has:
 *   { name, type, id, consoleUrl, children: [...] }
 * Returns at least 2 levels of nested dependencies.
 * consoleUrl is included where a direct console link can be constructed.
 */
async function fetchDependencyGraph(config, arn, resourceType) {
    const resourceId = nameFromArn(arn);
    const region = config.region;

    switch (resourceType) {
        case 'ec2:instance':
            return await ec2InstanceDependencies(config, resourceId, region);
        case 'lambda:function':
            return await lambdaDependencies(config, resourceId, region);
        case 'ecs:cluster':
            return await ecsClusterDependencies(config, resourceId, region);
        case 'eks:cluster':
            return await eksClusterDependencies(config, resourceId, region);
        case 'rds:db':
            return await rdsDependencies(config, resourceId, region);
        case 'elasticache:cluster':
            return await elasticacheDependencies(config, resourceId, region);
        case 'opensearch:domain':
            return await opensearchDependencies(config, resourceId, region);
        default:
            return { name: resourceId, type: resourceType, id: resourceId, children: [] };
    }
}

/** Build an AWS Console URL for a dependency node given its type and id. */
function depConsoleUrl(type, id, region) {
    const host = region || 'us-east-1';
    const base = 'https://' + host + '.console.aws.amazon.com';
    switch (type) {
        case 'VPC':
            return base + '/vpcconsole/home?region=' + host + '#/vpcs/' + encodeURIComponent(id);
        case 'Subnet':
            return base + '/vpcconsole/home?region=' + host + '#/subnets/' + encodeURIComponent(id);
        case 'Security Group':
            return base + '/vpcconsole/home?region=' + host + '#/securityGroups/' + encodeURIComponent(id);
        case 'IAM Role':
            return 'https://us-east-1.console.aws.amazon.com/iam/home#/roles/' + encodeURIComponent(id);
        case 'IAM Instance Profile':
            return 'https://us-east-1.console.aws.amazon.com/iam/home#/roles/' + encodeURIComponent(id);
        case 'EBS Volume':
            return base + '/ec2/home?region=' + host + '#/volumes/' + encodeURIComponent(id);
        case 'EC2 Instance':
            return base + '/ec2/home?region=' + host + '#/instances/' + encodeURIComponent(id);
        case 'Lambda Layer':
            return id ? base + '/lambda/home?region=' + host + '#/layers' : null;
        case 'Cache Node':
        case 'Cache Subnet Group':
            return base + '/elasticache/home?region=' + host + '#/caches';
        case 'Parameter Group':
            return base + '/rds/home?region=' + host + '#/parameter-groups';
        case 'DB Subnet Group':
            return base + '/rds/home?region=' + host + '#/subnet-groups/' + encodeURIComponent(id);
        case 'EBS Storage':
            return null;
        default:
            return null;
    }
}

async function ec2InstanceDependencies(config, instanceId, region) {
    const client = new EC2Client(config);
    const resp = await client.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
    const inst = resp.Reservations?.[0]?.Instances?.[0];
    if (!inst) return { name: instanceId, type: 'EC2 Instance', id: instanceId, children: [] };

    const name = (inst.Tags || []).find(t => t.Key === 'Name');
    const root = {
        name: name ? name.Value : instanceId,
        type: 'EC2 Instance',
        id: instanceId,
        consoleUrl: depConsoleUrl('EC2 Instance', instanceId, region),
        children: []
    };

    // VPC dependency with subnets
    if (inst.VpcId) {
        const vpcNode = { name: inst.VpcId, type: 'VPC', id: inst.VpcId, consoleUrl: depConsoleUrl('VPC', inst.VpcId, region), children: [] };
        if (inst.SubnetId) {
            vpcNode.children.push({ name: inst.SubnetId, type: 'Subnet', id: inst.SubnetId, consoleUrl: depConsoleUrl('Subnet', inst.SubnetId, region), children: [] });
        }
        root.children.push(vpcNode);
    }

    // Security groups
    if (inst.SecurityGroups && inst.SecurityGroups.length > 0) {
        const sgNode = { name: 'Security Groups', type: 'Security Groups', id: 'sgs', children: [] };
        for (const sg of inst.SecurityGroups) {
            sgNode.children.push({
                name: sg.GroupName || sg.GroupId,
                type: 'Security Group',
                id: sg.GroupId,
                consoleUrl: depConsoleUrl('Security Group', sg.GroupId, region),
                children: []
            });
        }
        root.children.push(sgNode);
    }

    // IAM instance profile
    if (inst.IamInstanceProfile) {
        const profileArn = inst.IamInstanceProfile.Arn || '';
        const profileName = profileArn.split('/').pop() || inst.IamInstanceProfile.Id;
        root.children.push({
            name: profileName,
            type: 'IAM Instance Profile',
            id: profileName,
            consoleUrl: depConsoleUrl('IAM Instance Profile', profileName, region),
            children: []
        });
    }

    // EBS volumes
    if (inst.BlockDeviceMappings && inst.BlockDeviceMappings.length > 0) {
        const volNode = { name: 'EBS Volumes', type: 'EBS Volumes', id: 'volumes', children: [] };
        for (const bdm of inst.BlockDeviceMappings) {
            if (bdm.Ebs && bdm.Ebs.VolumeId) {
                volNode.children.push({
                    name: bdm.DeviceName + ' (' + bdm.Ebs.VolumeId + ')',
                    type: 'EBS Volume',
                    id: bdm.Ebs.VolumeId,
                    consoleUrl: depConsoleUrl('EBS Volume', bdm.Ebs.VolumeId, region),
                    children: []
                });
            }
        }
        if (volNode.children.length > 0) root.children.push(volNode);
    }

    return root;
}

async function lambdaDependencies(config, functionName, region) {
    const client = new LambdaClient(config);
    const f = await client.send(new GetFunctionConfigurationCommand({ FunctionName: functionName }));
    if (!f) return { name: functionName, type: 'Lambda Function', id: functionName, children: [] };

    const root = {
        name: f.FunctionName || functionName,
        type: 'Lambda Function',
        id: functionName,
        children: []
    };

    // VPC config
    if (f.VpcConfig && f.VpcConfig.VpcId) {
        const vpcNode = { name: f.VpcConfig.VpcId, type: 'VPC', id: f.VpcConfig.VpcId, consoleUrl: depConsoleUrl('VPC', f.VpcConfig.VpcId, region), children: [] };
        if (f.VpcConfig.SubnetIds && f.VpcConfig.SubnetIds.length > 0) {
            for (const sub of f.VpcConfig.SubnetIds) {
                vpcNode.children.push({ name: sub, type: 'Subnet', id: sub, consoleUrl: depConsoleUrl('Subnet', sub, region), children: [] });
            }
        }
        if (f.VpcConfig.SecurityGroupIds && f.VpcConfig.SecurityGroupIds.length > 0) {
            for (const sg of f.VpcConfig.SecurityGroupIds) {
                vpcNode.children.push({ name: sg, type: 'Security Group', id: sg, consoleUrl: depConsoleUrl('Security Group', sg, region), children: [] });
            }
        }
        root.children.push(vpcNode);
    }

    // Execution role
    if (f.Role) {
        const roleName = f.Role.split('/').pop();
        root.children.push({ name: roleName, type: 'IAM Role', id: roleName, consoleUrl: depConsoleUrl('IAM Role', roleName, region), children: [] });
    }

    // Layers
    if (f.Layers && f.Layers.length > 0) {
        const layerNode = { name: 'Layers', type: 'Lambda Layers', id: 'layers', children: [] };
        for (const layer of f.Layers) {
            const layerName = (layer.Arn || '').split(':layer:')[1] || layer.Arn;
            layerNode.children.push({ name: layerName, type: 'Lambda Layer', id: layer.Arn, consoleUrl: depConsoleUrl('Lambda Layer', layer.Arn, region), children: [] });
        }
        root.children.push(layerNode);
    }

    return root;
}

async function ecsClusterDependencies(config, clusterName, region) {
    const client = new ECSClient(config);
    const resp = await client.send(new DescribeClustersCommand({ clusters: [clusterName] }));
    const c = resp.clusters?.[0];
    if (!c) return { name: clusterName, type: 'ECS Cluster', id: clusterName, children: [] };

    const root = {
        name: c.clusterName || clusterName,
        type: 'ECS Cluster',
        id: clusterName,
        children: []
    };

    // Cluster capacities / providers
    if (c.capacityProviders && c.capacityProviders.length > 0) {
        const cpNode = { name: 'Capacity Providers', type: 'Capacity Providers', id: 'cap-providers', children: [] };
        for (const cp of c.capacityProviders) {
            cpNode.children.push({ name: cp, type: 'Capacity Provider', id: cp, children: [] });
        }
        root.children.push(cpNode);
    }

    // Summary info as children for visual clarity
    if (c.activeServicesCount > 0) {
        root.children.push({
            name: c.activeServicesCount + ' Active Services',
            type: 'ECS Services',
            id: 'services',
            children: []
        });
    }
    if (c.runningTasksCount > 0) {
        root.children.push({
            name: c.runningTasksCount + ' Running Tasks',
            type: 'ECS Tasks',
            id: 'tasks',
            children: []
        });
    }
    if (c.registeredContainerInstancesCount > 0) {
        root.children.push({
            name: c.registeredContainerInstancesCount + ' Container Instances',
            type: 'EC2 Instances',
            id: 'instances',
            children: []
        });
    }

    return root;
}

async function eksClusterDependencies(config, clusterName, region) {
    const client = new EKSClient(config);
    const resp = await client.send(new DescribeClusterCommand({ name: clusterName }));
    const c = resp.cluster;
    if (!c) return { name: clusterName, type: 'EKS Cluster', id: clusterName, children: [] };

    const root = {
        name: c.name || clusterName,
        type: 'EKS Cluster',
        id: clusterName,
        children: []
    };

    // VPC config
    if (c.resourcesVpcConfig) {
        const vpc = c.resourcesVpcConfig;
        if (vpc.vpcId) {
            const vpcNode = { name: vpc.vpcId, type: 'VPC', id: vpc.vpcId, consoleUrl: depConsoleUrl('VPC', vpc.vpcId, region), children: [] };
            if (vpc.subnetIds && vpc.subnetIds.length > 0) {
                for (const sub of vpc.subnetIds) {
                    vpcNode.children.push({ name: sub, type: 'Subnet', id: sub, consoleUrl: depConsoleUrl('Subnet', sub, region), children: [] });
                }
            }
            if (vpc.securityGroupIds && vpc.securityGroupIds.length > 0) {
                for (const sg of vpc.securityGroupIds) {
                    vpcNode.children.push({ name: sg, type: 'Security Group', id: sg, consoleUrl: depConsoleUrl('Security Group', sg, region), children: [] });
                }
            }
            root.children.push(vpcNode);
        }
    }

    // IAM Role
    if (c.roleArn) {
        const roleName = c.roleArn.split('/').pop();
        root.children.push({ name: roleName, type: 'IAM Role', id: roleName, consoleUrl: depConsoleUrl('IAM Role', roleName, region), children: [] });
    }

    return root;
}

async function rdsDependencies(config, dbId, region) {
    const client = new RDSClient(config);
    const resp = await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: dbId }));
    const db = resp.DBInstances?.[0];
    if (!db) return { name: dbId, type: 'RDS Instance', id: dbId, children: [] };

    const root = {
        name: db.DBInstanceIdentifier || dbId,
        type: 'RDS Instance',
        id: dbId,
        children: []
    };

    // Subnet group (VPC)
    if (db.DBSubnetGroup) {
        const sgNode = {
            name: db.DBSubnetGroup.DBSubnetGroupName || 'Subnet Group',
            type: 'DB Subnet Group',
            id: db.DBSubnetGroup.DBSubnetGroupName,
            consoleUrl: depConsoleUrl('DB Subnet Group', db.DBSubnetGroup.DBSubnetGroupName, region),
            children: []
        };
        if (db.DBSubnetGroup.VpcId) {
            sgNode.children.push({ name: db.DBSubnetGroup.VpcId, type: 'VPC', id: db.DBSubnetGroup.VpcId, consoleUrl: depConsoleUrl('VPC', db.DBSubnetGroup.VpcId, region), children: [] });
        }
        if (db.DBSubnetGroup.Subnets) {
            for (const sub of db.DBSubnetGroup.Subnets) {
                sgNode.children.push({
                    name: sub.SubnetIdentifier + ' (' + (sub.SubnetAvailabilityZone?.Name || '') + ')',
                    type: 'Subnet',
                    id: sub.SubnetIdentifier,
                    consoleUrl: depConsoleUrl('Subnet', sub.SubnetIdentifier, region),
                    children: []
                });
            }
        }
        root.children.push(sgNode);
    }

    // Security groups
    if (db.VpcSecurityGroups && db.VpcSecurityGroups.length > 0) {
        const secNode = { name: 'Security Groups', type: 'VPC Security Groups', id: 'sgs', children: [] };
        for (const sg of db.VpcSecurityGroups) {
            secNode.children.push({
                name: sg.VpcSecurityGroupId,
                type: 'Security Group',
                id: sg.VpcSecurityGroupId,
                consoleUrl: depConsoleUrl('Security Group', sg.VpcSecurityGroupId, region),
                children: []
            });
        }
        root.children.push(secNode);
    }

    // Parameter group
    if (db.DBParameterGroups && db.DBParameterGroups.length > 0) {
        for (const pg of db.DBParameterGroups) {
            root.children.push({
                name: pg.DBParameterGroupName,
                type: 'Parameter Group',
                id: pg.DBParameterGroupName,
                consoleUrl: depConsoleUrl('Parameter Group', pg.DBParameterGroupName, region),
                children: []
            });
        }
    }

    return root;
}

async function elasticacheDependencies(config, clusterId, region) {
    const client = new ElastiCacheClient(config);
    const resp = await client.send(new DescribeCacheClustersCommand({
        CacheClusterId: clusterId, ShowCacheNodeInfo: true
    }));
    const cluster = resp.CacheClusters?.[0];
    if (!cluster) return { name: clusterId, type: 'ElastiCache Cluster', id: clusterId, children: [] };

    const root = {
        name: cluster.CacheClusterId || clusterId,
        type: 'ElastiCache Cluster',
        id: clusterId,
        children: []
    };

    // Subnet group
    if (cluster.CacheSubnetGroupName) {
        root.children.push({
            name: cluster.CacheSubnetGroupName,
            type: 'Cache Subnet Group',
            id: cluster.CacheSubnetGroupName,
            consoleUrl: depConsoleUrl('Cache Subnet Group', cluster.CacheSubnetGroupName, region),
            children: []
        });
    }

    // Security groups
    if (cluster.SecurityGroups && cluster.SecurityGroups.length > 0) {
        const sgNode = { name: 'Security Groups', type: 'Security Groups', id: 'sgs', children: [] };
        for (const sg of cluster.SecurityGroups) {
            sgNode.children.push({
                name: sg.SecurityGroupId,
                type: 'Security Group',
                id: sg.SecurityGroupId,
                consoleUrl: depConsoleUrl('Security Group', sg.SecurityGroupId, region),
                children: []
            });
        }
        root.children.push(sgNode);
    }

    // Cache nodes
    if (cluster.CacheNodes && cluster.CacheNodes.length > 0) {
        const nodesNode = { name: 'Cache Nodes', type: 'Cache Nodes', id: 'nodes', children: [] };
        for (const node of cluster.CacheNodes) {
            nodesNode.children.push({
                name: 'Node ' + node.CacheNodeId + ' (' + (node.CacheNodeStatus || '') + ')',
                type: 'Cache Node',
                id: node.CacheNodeId,
                consoleUrl: depConsoleUrl('Cache Node', node.CacheNodeId, region),
                children: []
            });
        }
        root.children.push(nodesNode);
    }

    return root;
}

async function opensearchDependencies(config, domainName, region) {
    const client = new OpenSearchClient(config);
    const resp = await client.send(new DescribeDomainCommand({ DomainName: domainName }));
    const domain = resp.DomainStatus;
    if (!domain) return { name: domainName, type: 'OpenSearch Domain', id: domainName, children: [] };

    const root = {
        name: domain.DomainName || domainName,
        type: 'OpenSearch Domain',
        id: domainName,
        children: []
    };

    // VPC config
    if (domain.VPCOptions) {
        const vpc = domain.VPCOptions;
        if (vpc.VPCId) {
            const vpcNode = { name: vpc.VPCId, type: 'VPC', id: vpc.VPCId, consoleUrl: depConsoleUrl('VPC', vpc.VPCId, region), children: [] };
            if (vpc.SubnetIds && vpc.SubnetIds.length > 0) {
                for (const sub of vpc.SubnetIds) {
                    vpcNode.children.push({ name: sub, type: 'Subnet', id: sub, consoleUrl: depConsoleUrl('Subnet', sub, region), children: [] });
                }
            }
            if (vpc.SecurityGroupIds && vpc.SecurityGroupIds.length > 0) {
                for (const sg of vpc.SecurityGroupIds) {
                    vpcNode.children.push({ name: sg, type: 'Security Group', id: sg, consoleUrl: depConsoleUrl('Security Group', sg, region), children: [] });
                }
            }
            root.children.push(vpcNode);
        }
    }

    // EBS storage
    if (domain.EBSOptions && domain.EBSOptions.EBSEnabled) {
        root.children.push({
            name: (domain.EBSOptions.VolumeSize || '?') + ' GB ' + (domain.EBSOptions.VolumeType || 'EBS'),
            type: 'EBS Storage',
            id: 'ebs',
            consoleUrl: depConsoleUrl('EBS Storage', 'ebs', region),
            children: []
        });
    }

    return root;
}

/**
 * The AWS account id these resources belong to, read off the first ARN that
 * carries one.
 *
 * Used to build ARNs for supplemental sources whose List* responses omit them.
 * Reading it from discovered data avoids an sts:GetCallerIdentity call and the
 * client-sts dependency; some ARNs legitimately have an empty account field
 * (S3, for one), hence the scan rather than just taking [0].
 */
function accountIdFromResources(resources) {
    for (const r of resources) {
        const account = r && r.Arn ? String(r.Arn).split(':')[4] : '';
        if (account) return account;
    }
    return undefined;
}

/**
 * Split an ARN into its components. Handles both `resourcetype/id` and
 * `resourcetype:id` trailing forms.
 *   arn:partition:service:region:account:resource
 */
function parseArn(arn) {
    const parts = (arn || '').split(':');
    return {
        partition: parts[1] || '-',
        service: parts[2] || '-',
        region: parts[3] || '',
        account: parts[4] || '',
        resource: parts.slice(5).join(':')
    };
}

/**
 * Structured detail available for ANY resource type with no extra API call,
 * built from the ARN plus the fields Resource Explorer always returns. Used as
 * the baseline for types without a dedicated live fetcher, and as the fallback
 * when a dedicated fetch fails (e.g. missing permission).
 */
function genericDetail(arn, resourceType, service, extra) {
    const p = parseArn(arn);
    const base = {
        'Resource ID': nameFromArn(arn),
        'Resource Type': resourceType || '-',
        'Service': service || p.service,
        'Region': p.region || 'global',
        'Account': p.account || '-',
        'ARN': arn
    };
    return { details: Object.assign(base, extra || {}) };
}

/**
 * Fetch detailed information for a specific resource based on its type.
 * `lastReported` is the Resource Explorer LastReportedAt passed from discovery.
 *
 * Thin wrapper over the dispatcher so the Resource Explorer "Last reported"
 * row is appended for EVERY type. It used to be threaded only into the generic
 * and error paths, so the row appeared or vanished depending on which resource
 * you clicked - it looked like missing data rather than an inconsistency in
 * this code. Appending centrally is idempotent: paths that already include it
 * write the same key and value.
 */
async function fetchResourceDetails(config, arn, resourceType, service, lastReported) {
    const result = await dispatchResourceDetails(config, arn, resourceType, service, lastReported);
    if (!result || !result.details) return result;
    const reported = lastReported ? { 'Last reported (Resource Explorer)': toIso(lastReported) } : {};
    return { details: Object.assign({}, result.details, reported) };
}

async function dispatchResourceDetails(config, arn, resourceType, service, lastReported) {
    const rt = (resourceType || '').toLowerCase();
    const resourceId = nameFromArn(arn);
    const reported = lastReported ? { 'Last reported (Resource Explorer)': toIso(lastReported) } : {};

    // A supplemental source owns this type - use its detail(), or fall back
    // to the generic ARN-based detail if it doesn't implement one.
    const supplemental = supplementalSources.findSourceForType(rt);
    if (supplemental) {
        try {
            if (supplemental.detail) return await supplemental.detail(config, { arn, name: resourceId });
            return genericDetail(arn, resourceType, service, reported);
        } catch (err) {
            console.warn('supplemental detail failed for', rt, arn, '-', err.name, err.message);
            return genericDetail(arn, resourceType, service,
                Object.assign({ 'Note': 'Limited detail: ' + (err.message || err.name) }, reported));
        }
    }

    try {
        switch (rt) {
            case 'ec2:instance':
                return await describeEC2Instance(config, resourceId);
            case 'lambda:function':
                return await describeLambdaFunction(config, resourceId);
            case 'dynamodb:table':
                return await describeDynamoDBTable(config, resourceId);
            case 'rds:db':
                return await describeRDSInstance(config, resourceId);
            // No S3 client dependency and no s3 IAM action by design: bucket
            // detail would need s3:GetBucket* calls, and the nearby s3:GetObject
            // is exactly what this role refuses to grant. Return the standard
            // baseline rather than an ad-hoc two-field object, which previously
            // dropped Region, Account, Service and the last-reported time that
            // every other resource type shows.
            case 's3:bucket':
                return genericDetail(arn, resourceType, service, reported);
            case 'sqs:queue':
                return await describeSQSQueue(config, arn);
            case 'sns:topic':
                return await describeSNSTopic(config, arn);
            case 'ecs:cluster':
                return await describeECSCluster(config, resourceId);
            case 'ecs:service':
                return await describeECSService(config, arn);
            case 'eks:cluster':
                return await describeEKSCluster(config, resourceId);
            case 'elasticloadbalancing:loadbalancer':
                return await describeELB(config, arn);
            case 'cloudfront:distribution':
                return await describeCloudFront(config, resourceId);
            case 'secretsmanager:secret':
                return await describeSecret(config, arn);
            case 'opensearch:domain':
                return await describeOpenSearch(config, resourceId);
            case 'elasticache:cluster':
                return await describeElastiCache(config, resourceId);
            case 'efs:file-system':
                return await describeEFS(config, resourceId);
            // Path-style names: pass the full identifier, not the last segment.
            case 'ecr:repository':
                return await describeECR(config, resourceIdFromArn(arn));
            case 'states:statemachine':
                return await describeStepFunction(config, arn);
            // Passed the ARN, not the bare name: the event bus is encoded in it
            // and a rule on a custom bus cannot be described without it.
            case 'events:rule':
                return await describeEventBridgeRule(config, arn);
            case 'ssm:parameter':
                return await describeSSMParameter(config, resourceIdFromArn(arn));
            case 'ec2:natgateway':
                return await describeNATGateway(config, resourceId);

            // EC2 networking - reuses the EC2 client already imported.
            case 'ec2:vpc':
                return await describeVpc(config, resourceId);
            case 'ec2:subnet':
                return await describeSubnet(config, resourceId);
            case 'ec2:security-group':
                return await describeSecurityGroup(config, resourceId);
            case 'ec2:route-table':
                return await describeRouteTable(config, resourceId);
            case 'ec2:internet-gateway':
                return await describeInternetGateway(config, resourceId);
            case 'ec2:elastic-ip':
                return await describeElasticIp(config, resourceId);
            case 'ec2:vpc-endpoint':
                return await describeVpcEndpoint(config, resourceId);

            // IAM (global) - the highest-volume resource family.
            case 'iam:role':
                return await describeIamRole(config, resourceId);
            case 'iam:policy':
                return await describeIamPolicy(config, arn);
            case 'iam:user':
                return await describeIamUser(config, resourceId);
            case 'iam:instance-profile':
                return await describeInstanceProfile(config, resourceId);

            // Management / observability / security.
            case 'cloudformation:stack':
                return await describeCfnStack(config, arn);
            case 'cloudwatch:alarm':
                return await describeAlarm(config, resourceId);
            case 'logs:log-group':
                return await describeLogGroup(config, resourceIdFromArn(arn));
            case 'kms:key':
                return await describeKmsKey(config, resourceId);
            case 'acm:certificate':
                return await describeCertificate(config, arn);

            default:
                // Every other type still gets structured detail from the ARN
                // and Resource Explorer metadata, with no extra API call.
                return genericDetail(arn, resourceType, service, reported);
        }
    } catch (err) {
        // A dedicated fetch failed (often a missing optional permission).
        // Degrade to the generic detail rather than showing only an error.
        //
        // Log it. Returning 200 with a "Limited detail" note and no log line
        // made throttling, an expired credential, a missing IAM action and an
        // outright code bug indistinguishable and operationally invisible -
        // there was no signal anywhere that anything had failed.
        console.warn('detail fetch degraded for', rt, arn, '-', err.name, err.message);
        return genericDetail(arn, resourceType, service,
            Object.assign({ 'Note': 'Limited detail: ' + (err.message || err.name) }, reported));
    }
}

// ─── On-Demand Detail Fetchers ─────────────────────────────────────────────────

async function describeEC2Instance(config, instanceId) {
    const client = new EC2Client(config);
    const resp = await client.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
    const inst = resp.Reservations?.[0]?.Instances?.[0];
    if (!inst) return { details: { 'Instance ID': instanceId, 'Error': 'Not found' } };
    const name = (inst.Tags || []).find(t => t.Key === 'Name');
    return {
        details: {
            'Instance ID': inst.InstanceId,
            'ARN': `arn:aws:ec2:${config.region}:${resp.Reservations[0].OwnerId || ''}:instance/${inst.InstanceId}`,
            'Name': name ? name.Value : '-',
            'Type': inst.InstanceType,
            'State': inst.State ? inst.State.Name : '-',
            'AZ': inst.Placement ? inst.Placement.AvailabilityZone : '-',
            'Private IP': inst.PrivateIpAddress || '-',
            'Public IP': inst.PublicIpAddress || '-',
            'VPC': inst.VpcId || '-',
            'Subnet': inst.SubnetId || '-',
            'AMI': inst.ImageId || '-',
            'Launch Time': toIso(inst.LaunchTime)
        }
    };
}

/**
 * GetFunctionConfiguration rather than GetFunction: GetFunction additionally
 * returns Code.Location, a pre-signed URL that downloads the deployment
 * package, and nothing here needs it. The response is flat - GetFunction wraps
 * the same fields in a Configuration object, GetFunctionConfiguration does not.
 *
 * This response still contains Environment.Variables in plaintext. We do not
 * read or render it, but lambda:GetFunctionConfiguration cannot exclude it, so
 * any profile that can call this can see Lambda env vars. See SECURITY.md.
 */
async function describeLambdaFunction(config, functionName) {
    const client = new LambdaClient(config);
    const f = await client.send(new GetFunctionConfigurationCommand({ FunctionName: functionName }));
    if (!f) return { details: { 'Error': 'Function not found' } };
    return {
        details: {
            'Function Name': f.FunctionName,
            'ARN': f.FunctionArn,
            'Runtime': f.Runtime || '-',
            'Handler': f.Handler || '-',
            'Memory': (f.MemorySize || '-') + ' MB',
            'Timeout': (f.Timeout || '-') + ' s',
            'Code Size': f.CodeSize ? Math.round(f.CodeSize / 1024) + ' KB' : '-',
            'Last Modified': f.LastModified || '-',
            // Report what the API returned. Defaulting this to 'Active' claimed
            // a state AWS had not confirmed.
            'State': f.State || '-'
        }
    };
}

async function describeDynamoDBTable(config, tableName) {
    const client = new DynamoDBClient(config);
    const resp = await client.send(new DescribeTableCommand({ TableName: tableName }));
    const t = resp.Table;
    if (!t) return { details: { 'Table Name': tableName, 'Error': 'Not found' } };
    return {
        details: {
            'Table Name': t.TableName,
            'ARN': t.TableArn,
            'Status': t.TableStatus,
            'Item Count': t.ItemCount != null ? t.ItemCount : '-',
            'Size (bytes)': t.TableSizeBytes != null ? t.TableSizeBytes : '-',
            // Report only what the API returned. Defaulting to PROVISIONED
            // asserted a billing mode AWS had not confirmed.
            'Billing Mode': t.BillingModeSummary && t.BillingModeSummary.BillingMode
                ? t.BillingModeSummary.BillingMode : '-',
            'Created': toIso(t.CreationDateTime)
        }
    };
}

async function describeRDSInstance(config, dbId) {
    const client = new RDSClient(config);
    const resp = await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: dbId }));
    const db = resp.DBInstances?.[0];
    if (!db) return { details: { 'DB Identifier': dbId, 'Error': 'Not found' } };
    return {
        details: {
            'DB Identifier': db.DBInstanceIdentifier,
            'ARN': db.DBInstanceArn || '-',
            'Engine': db.Engine,
            'Version': db.EngineVersion,
            'Class': db.DBInstanceClass,
            'Status': db.DBInstanceStatus,
            'Endpoint': db.Endpoint ? db.Endpoint.Address : '-',
            'Port': db.Endpoint ? db.Endpoint.Port : '-',
            'Multi-AZ': db.MultiAZ ? 'Yes' : 'No',
            'Storage': (db.AllocatedStorage || '-') + ' GB'
        }
    };
}

async function describeSQSQueue(config, arn) {
    const parts = arn.split(':');
    const accountId = parts[4];
    const queueName = parts[5];
    const client = new SQSClient(config);

    // Ask SQS for the URL instead of composing one. The previous version built
    // `https://sqs.${config.region}.amazonaws.com/${accountId}/${queueName}`,
    // which hardcoded the commercial-partition host (wrong in aws-cn, where it
    // is amazonaws.com.cn) and used the REQUEST's region rather than the
    // region in the ARN, so a cross-region view targeted the wrong endpoint.
    // It also interpolated unvalidated ARN segments straight into a URL path.
    const urlResp = await client.send(new GetQueueUrlCommand({
        QueueName: queueName,
        QueueOwnerAWSAccountId: accountId
    }));
    const queueUrl = urlResp.QueueUrl;
    if (!queueUrl) return { details: { 'Queue Name': queueName, 'ARN': arn, 'Error': 'Queue URL not resolvable' } };

    // Request only the attributes rendered below. 'All' additionally returns
    // Policy, RedrivePolicy and KmsMasterKeyId, none of which is displayed.
    const resp = await client.send(new GetQueueAttributesCommand({
        QueueUrl: queueUrl,
        AttributeNames: [
            'ApproximateNumberOfMessages',
            'ApproximateNumberOfMessagesNotVisible',
            'CreatedTimestamp',
            'VisibilityTimeout'
        ]
    }));
    const attrs = resp.Attributes || {};
    return {
        details: {
            'Queue Name': queueName,
            'ARN': arn,
            'URL': queueUrl,
            'Messages Available': attrs.ApproximateNumberOfMessages || '0',
            'Messages In Flight': attrs.ApproximateNumberOfMessagesNotVisible || '0',
            'Created': toIso(attrs.CreatedTimestamp ? new Date(parseInt(attrs.CreatedTimestamp) * 1000) : null),
            'Visibility Timeout': (attrs.VisibilityTimeout || '-') + ' s'
        }
    };
}

async function describeSNSTopic(config, arn) {
    const client = new SNSClient(config);
    const resp = await client.send(new GetTopicAttributesCommand({ TopicArn: arn }));
    const attrs = resp.Attributes || {};
    return {
        details: {
            'Topic Name': arn.split(':').pop(),
            'ARN': arn,
            'Subscriptions Confirmed': attrs.SubscriptionsConfirmed || '0',
            'Subscriptions Pending': attrs.SubscriptionsPending || '0',
            'Display Name': attrs.DisplayName || '-',
            'Effective Delivery Policy': attrs.EffectiveDeliveryPolicy ? 'Configured' : '-'
        }
    };
}

async function describeECSCluster(config, clusterName) {
    const client = new ECSClient(config);
    const resp = await client.send(new DescribeClustersCommand({ clusters: [clusterName] }));
    const c = resp.clusters?.[0];
    if (!c) return { details: { 'Cluster': clusterName, 'Error': 'Not found' } };
    return {
        details: {
            'Cluster Name': c.clusterName,
            'ARN': c.clusterArn,
            'Status': c.status,
            'Running Tasks': c.runningTasksCount || 0,
            'Pending Tasks': c.pendingTasksCount || 0,
            'Active Services': c.activeServicesCount || 0,
            'Registered Instances': c.registeredContainerInstancesCount || 0
        }
    };
}

async function describeECSService(config, arn) {
    // Two ARN shapes exist:
    //   long  arn:aws:ecs:r:acct:service/<cluster>/<service>   -> 3 segments
    //   short arn:aws:ecs:r:acct:service/<service>              -> 2 segments
    // Taking parts[1] as the cluster unconditionally meant the short form used
    // the service name as its own cluster, and the call failed. When the
    // cluster is not in the ARN, omit it and let ECS resolve the default.
    const parts = arn.split('/');
    const hasCluster = parts.length >= 3;
    const clusterName = hasCluster ? parts[1] : null;
    const serviceName = parts[parts.length - 1];

    const client = new ECSClient(config);
    const resp = await client.send(new DescribeServicesCommand({
        ...(clusterName ? { cluster: clusterName } : {}),
        services: [serviceName]
    }));
    const svc = resp.services?.[0];
    if (!svc) {
        // resp.failures explains why (MISSING, ACCESS_DENIED, ...); surface it
        // rather than reporting a bare "Not found".
        const failure = (resp.failures || [])[0];
        return { details: {
            'Service': serviceName,
            'Cluster': clusterName || '(default)',
            'Error': failure ? (failure.reason || 'Not found') + (failure.detail ? ': ' + failure.detail : '') : 'Not found'
        } };
    }
    return {
        details: {
            'Service': svc.serviceName,
            'ARN': svc.serviceArn,
            // Prefer the cluster ARN the API returned over the one parsed out.
            'Cluster': svc.clusterArn ? svc.clusterArn.split('/').pop() : (clusterName || '-'),
            'Status': svc.status,
            'Desired': svc.desiredCount,
            'Running': svc.runningCount,
            'Pending': svc.pendingCount,
            'Launch Type': svc.launchType || '-',
            'Task Def': svc.taskDefinition ? svc.taskDefinition.split('/').pop() : '-'
        }
    };
}

async function describeEKSCluster(config, clusterName) {
    const client = new EKSClient(config);
    const resp = await client.send(new DescribeClusterCommand({ name: clusterName }));
    const c = resp.cluster;
    if (!c) return { details: { 'Cluster Name': clusterName, 'Error': 'Not found' } };
    return {
        details: {
            'Cluster Name': c.name,
            'ARN': c.arn,
            'Status': c.status,
            'Version': c.version,
            'Platform Version': c.platformVersion || '-',
            // Not truncated. Slicing to 80 characters presented a fragment of
            // the endpoint as the endpoint, which is worse than a long value.
            'Endpoint': c.endpoint || '-',
            'Role ARN': c.roleArn || '-'
        }
    };
}

async function describeELB(config, arn) {
    // Resource Explorer reports Classic (ELBv1) and ALB/NLB (ELBv2) under the
    // same elasticloadbalancing:loadbalancer type, but only the v2 client is
    // available here. The two ARN forms differ:
    //   v2       :loadbalancer/app/<name>/<id>  (or /net/, /gwy/)
    //   classic  :loadbalancer/<name>
    // Passing a Classic ARN to DescribeLoadBalancers (v2) is rejected, so
    // detect it and say why instead of surfacing an opaque validation error.
    const resourcePart = arn.split(':loadbalancer/')[1] || '';
    const isV2 = /^(app|net|gwy)\//.test(resourcePart);
    if (!isV2) {
        return { details: {
            'Name': resourcePart || nameFromArn(arn),
            'ARN': arn,
            'Type': 'classic',
            'Note': 'Classic Load Balancer. This app queries the ELBv2 API only, ' +
                    'so detail for Classic load balancers is not available. ' +
                    'Add @aws-sdk/client-elastic-load-balancing and ' +
                    'elasticloadbalancing:DescribeLoadBalancers if you need it.'
        } };
    }

    const client = new ElasticLoadBalancingV2Client(config);
    const resp = await client.send(new DescribeLoadBalancersCommand({ LoadBalancerArns: [arn] }));
    const lb = resp.LoadBalancers?.[0];
    if (!lb) return { details: { 'ARN': arn, 'Error': 'Not found' } };
    return {
        details: {
            'Name': lb.LoadBalancerName,
            'ARN': lb.LoadBalancerArn,
            'Type': lb.Type,
            'Scheme': lb.Scheme,
            'State': lb.State ? lb.State.Code : '-',
            'DNS': lb.DNSName || '-',
            'VPC': lb.VpcId || '-',
            'AZs': (lb.AvailabilityZones || []).map(az => az.ZoneName).join(', ')
        }
    };
}

async function describeCloudFront(config, distributionId) {
    const client = new CloudFrontClient({ ...config, region: 'us-east-1' }); // CloudFront is global
    const resp = await client.send(new GetDistributionCommand({ Id: distributionId }));
    const d = resp.Distribution;
    if (!d) return { details: { 'Distribution ID': distributionId, 'Error': 'Not found' } };
    return {
        details: {
            'Distribution ID': d.Id,
            'ARN': d.ARN,
            'Domain': d.DomainName,
            'Status': d.Status,
            'Enabled': d.DistributionConfig?.Enabled ? 'Yes' : 'No',
            'Origins': d.DistributionConfig?.Origins?.Items?.map(o => o.DomainName).join(', ') || '-',
            'Aliases': d.DistributionConfig?.Aliases?.Items?.join(', ') || '-'
        }
    };
}

async function describeSecret(config, arn) {
    const client = new SecretsManagerClient(config);
    const resp = await client.send(new DescribeSecretCommand({ SecretId: arn }));
    return {
        details: {
            'Name': resp.Name,
            'ARN': resp.ARN,
            'Description': resp.Description || '-',
            'Last Changed': toIso(resp.LastChangedDate),
            'Last Accessed': toIso(resp.LastAccessedDate),
            'Rotation Enabled': resp.RotationEnabled ? 'Yes' : 'No'
        }
    };
}

async function describeOpenSearch(config, domainName) {
    const client = new OpenSearchClient(config);
    const resp = await client.send(new DescribeDomainCommand({ DomainName: domainName }));
    const ds = resp.DomainStatus;
    if (!ds) return { details: { 'Domain': domainName, 'Error': 'Not found' } };
    return {
        details: {
            'Domain': ds.DomainName,
            'ARN': ds.ARN,
            'Engine Version': ds.EngineVersion || '-',
            'Instance Type': ds.ClusterConfig ? ds.ClusterConfig.InstanceType : '-',
            'Instance Count': ds.ClusterConfig ? ds.ClusterConfig.InstanceCount : '-',
            'Endpoint': ds.Endpoint || '-',
            'Encrypted': ds.EncryptionAtRestOptions?.Enabled ? 'Yes' : 'No'
        }
    };
}

async function describeElastiCache(config, clusterId) {
    const client = new ElastiCacheClient(config);
    const resp = await client.send(new DescribeCacheClustersCommand({ CacheClusterId: clusterId }));
    const c = resp.CacheClusters?.[0];
    if (!c) return { details: { 'Cluster ID': clusterId, 'Error': 'Not found' } };
    return {
        details: {
            'Cluster ID': c.CacheClusterId,
            'ARN': c.ARN || '-',
            'Engine': c.Engine,
            'Version': c.EngineVersion,
            'Node Type': c.CacheNodeType,
            'Nodes': c.NumCacheNodes,
            'Status': c.CacheClusterStatus,
            'AZ': c.PreferredAvailabilityZone || '-'
        }
    };
}

async function describeEFS(config, fileSystemId) {
    const client = new EFSClient(config);
    const resp = await client.send(new DescribeFileSystemsCommand({ FileSystemId: fileSystemId }));
    const fs = resp.FileSystems?.[0];
    if (!fs) return { details: { 'File System ID': fileSystemId, 'Error': 'Not found' } };
    return {
        details: {
            'File System ID': fs.FileSystemId,
            'ARN': fs.FileSystemArn || '-',
            'Name': fs.Name || fs.FileSystemId,
            'State': fs.LifeCycleState,
            'Size (bytes)': fs.SizeInBytes ? fs.SizeInBytes.Value : '-',
            'Performance Mode': fs.PerformanceMode || '-',
            'Throughput Mode': fs.ThroughputMode || '-',
            'Encrypted': fs.Encrypted ? 'Yes' : 'No'
        }
    };
}

async function describeECR(config, repoName) {
    const client = new ECRClient(config);
    const resp = await client.send(new DescribeRepositoriesCommand({ repositoryNames: [repoName] }));
    const r = resp.repositories?.[0];
    if (!r) return { details: { 'Repository': repoName, 'Error': 'Not found' } };
    return {
        details: {
            'Repository': r.repositoryName,
            'ARN': r.repositoryArn,
            'URI': r.repositoryUri || '-',
            'Created': toIso(r.createdAt),
            'Image Tag Mutability': r.imageTagMutability || '-',
            'Scan on Push': r.imageScanningConfiguration?.scanOnPush ? 'Yes' : 'No'
        }
    };
}

async function describeStepFunction(config, arn) {
    const client = new SFNClient(config);
    const resp = await client.send(new DescribeStateMachineCommand({ stateMachineArn: arn }));
    return {
        details: {
            'Name': resp.name,
            'ARN': resp.stateMachineArn,
            'Type': resp.type || 'STANDARD',
            'Status': resp.status,
            'Created': toIso(resp.creationDate),
            'Role ARN': resp.roleArn || '-'
        }
    };
}

async function describeEventBridgeRule(config, arn) {
    // DescribeRule defaults to the "default" event bus when EventBusName is
    // omitted, so every rule on a custom bus raised ResourceNotFoundException
    // and silently degraded to generic detail. The bus is in the ARN:
    //   default bus  :rule/<rule>
    //   custom bus   :rule/<bus>/<rule>
    const resourcePart = arn.includes(':rule/') ? arn.split(':rule/')[1] : '';
    const segments = resourcePart.split('/');
    const hasCustomBus = segments.length >= 2;
    const busName = hasCustomBus ? segments[0] : null;
    const ruleName = segments[segments.length - 1] || nameFromArn(arn);

    const client = new EventBridgeClient(config);
    const resp = await client.send(new DescribeRuleCommand({
        Name: ruleName,
        ...(busName ? { EventBusName: busName } : {})
    }));
    if (!resp || !resp.Name) return { details: { 'Rule Name': ruleName, 'Error': 'Not found' } };
    return {
        details: {
            'Rule Name': resp.Name,
            'ARN': resp.Arn,
            'State': resp.State,
            'Description': resp.Description || '-',
            'Schedule': resp.ScheduleExpression || '-',
            'Event Bus': resp.EventBusName || busName || 'default'
        }
    };
}

async function describeSSMParameter(config, paramName) {
    const client = new SSMClient(config);
    // resourceIdFromArn already returns the full path-style name with its
    // leading slash. This guard is belt-and-braces for a direct caller.
    const name = paramName.startsWith('/') ? paramName : '/' + paramName;
    // DescribeParameters returns metadata only. GetParameter would return the
    // value and requires ssm:GetParameter, which this role intentionally lacks
    // so it can never read secret material (e.g. SecureString parameters).
    const resp = await client.send(new DescribeParametersCommand({
        ParameterFilters: [{ Key: 'Name', Option: 'Equals', Values: [name] }]
    }));
    const p = (resp.Parameters || [])[0];
    if (!p) {
        return { details: { 'Name': name, 'Note': 'Parameter metadata not accessible' } };
    }
    return {
        details: {
            'Name': p.Name,
            'ARN': p.ARN || '-',
            'Type': p.Type,
            'Version': p.Version || '-',
            'Tier': p.Tier || 'Standard',
            'Last Modified': toIso(p.LastModifiedDate)
        }
    };
}

async function describeNATGateway(config, natGatewayId) {
    const client = new EC2Client(config);
    const resp = await client.send(new DescribeNatGatewaysCommand({ NatGatewayIds: [natGatewayId] }));
    const nat = resp.NatGateways?.[0];
    if (!nat) return { details: { 'NAT Gateway ID': natGatewayId, 'Error': 'Not found' } };
    return {
        details: {
            'NAT Gateway ID': nat.NatGatewayId,
            'State': nat.State,
            'VPC': nat.VpcId || '-',
            'Subnet': nat.SubnetId || '-',
            'Public IP': nat.NatGatewayAddresses?.[0]?.PublicIp || '-',
            'Private IP': nat.NatGatewayAddresses?.[0]?.PrivateIp || '-',
            'Type': nat.ConnectivityType || '-'
        }
    };
}

// EC2 networking (reuses EC2Client) ------------------------------------------

function tagName(tags) {
    return (tags || []).find(t => t.Key === 'Name')?.Value || '-';
}

async function describeVpc(config, vpcId) {
    const client = new EC2Client(config);
    const resp = await client.send(new DescribeVpcsCommand({ VpcIds: [vpcId] }));
    const v = resp.Vpcs?.[0];
    if (!v) return { details: { 'VPC ID': vpcId, 'Error': 'Not found' } };
    return { details: {
        'VPC ID': v.VpcId, 'Name': tagName(v.Tags), 'CIDR': v.CidrBlock,
        'State': v.State, 'Default': v.IsDefault ? 'Yes' : 'No',
        'Tenancy': v.InstanceTenancy || '-'
    } };
}

async function describeSubnet(config, subnetId) {
    const client = new EC2Client(config);
    const resp = await client.send(new DescribeSubnetsCommand({ SubnetIds: [subnetId] }));
    const s = resp.Subnets?.[0];
    if (!s) return { details: { 'Subnet ID': subnetId, 'Error': 'Not found' } };
    return { details: {
        'Subnet ID': s.SubnetId, 'Name': tagName(s.Tags), 'VPC': s.VpcId,
        'CIDR': s.CidrBlock, 'AZ': s.AvailabilityZone, 'State': s.State,
        'Available IPs': s.AvailableIpAddressCount, 'Public IP on launch': s.MapPublicIpOnLaunch ? 'Yes' : 'No'
    } };
}

/**
 * Number of security-group rules in a set of IpPermissions entries.
 *
 * EC2 groups rules by protocol/port range, so one entry may contain several
 * sources. The rule count is the total number of sources across all entries;
 * an entry with no sources still represents one rule.
 */
function countSgRules(permissions) {
    return (permissions || []).reduce((total, p) => {
        const sources = (p.IpRanges || []).length +
                        (p.Ipv6Ranges || []).length +
                        (p.UserIdGroupPairs || []).length +
                        (p.PrefixListIds || []).length;
        return total + (sources || 1);
    }, 0);
}

async function describeSecurityGroup(config, sgId) {
    const client = new EC2Client(config);
    const resp = await client.send(new DescribeSecurityGroupsCommand({ GroupIds: [sgId] }));
    const g = resp.SecurityGroups?.[0];
    if (!g) return { details: { 'Group ID': sgId, 'Error': 'Not found' } };
    return { details: {
        'Group ID': g.GroupId, 'Name': g.GroupName, 'VPC': g.VpcId || '-',
        'Description': g.Description || '-',
        // Count actual rules, not permission entries. One IpPermissions entry
        // can carry many IpRanges, Ipv6Ranges, UserIdGroupPairs and
        // PrefixListIds, and the console counts each of those as a rule - so
        // using entries.length under-reported, sometimes badly.
        'Inbound rules': countSgRules(g.IpPermissions),
        'Outbound rules': countSgRules(g.IpPermissionsEgress)
    } };
}

async function describeRouteTable(config, rtId) {
    const client = new EC2Client(config);
    const resp = await client.send(new DescribeRouteTablesCommand({ RouteTableIds: [rtId] }));
    const t = resp.RouteTables?.[0];
    if (!t) return { details: { 'Route Table ID': rtId, 'Error': 'Not found' } };
    return { details: {
        'Route Table ID': t.RouteTableId, 'Name': tagName(t.Tags), 'VPC': t.VpcId,
        'Routes': (t.Routes || []).length, 'Associations': (t.Associations || []).length
    } };
}

async function describeInternetGateway(config, igwId) {
    const client = new EC2Client(config);
    const resp = await client.send(new DescribeInternetGatewaysCommand({ InternetGatewayIds: [igwId] }));
    const g = resp.InternetGateways?.[0];
    if (!g) return { details: { 'Internet Gateway ID': igwId, 'Error': 'Not found' } };
    return { details: {
        'Internet Gateway ID': g.InternetGatewayId, 'Name': tagName(g.Tags),
        'Attached VPC': g.Attachments?.[0]?.VpcId || '(none)',
        'State': g.Attachments?.[0]?.State || '-'
    } };
}

async function describeElasticIp(config, allocId) {
    const client = new EC2Client(config);
    // Elastic IP ARNs carry the allocation id; look it up by that.
    const resp = await client.send(new DescribeAddressesCommand({ AllocationIds: [allocId] }));
    const a = resp.Addresses?.[0];
    if (!a) return { details: { 'Allocation ID': allocId, 'Error': 'Not found' } };
    return { details: {
        'Allocation ID': a.AllocationId, 'Name': tagName(a.Tags), 'Public IP': a.PublicIp,
        'Associated with': a.InstanceId || a.NetworkInterfaceId || '(unassociated)',
        'Private IP': a.PrivateIpAddress || '-', 'Domain': a.Domain || '-'
    } };
}

async function describeVpcEndpoint(config, vpceId) {
    const client = new EC2Client(config);
    const resp = await client.send(new DescribeVpcEndpointsCommand({ VpcEndpointIds: [vpceId] }));
    const e = resp.VpcEndpoints?.[0];
    if (!e) return { details: { 'VPC Endpoint ID': vpceId, 'Error': 'Not found' } };
    return { details: {
        'VPC Endpoint ID': e.VpcEndpointId, 'Service': e.ServiceName, 'VPC': e.VpcId,
        'Type': e.VpcEndpointType, 'State': e.State, 'Private DNS': e.PrivateDnsEnabled ? 'Yes' : 'No'
    } };
}

// IAM (global) ----------------------------------------------------------------

async function describeIamRole(config, roleName) {
    const client = new IAMClient(config);
    const resp = await client.send(new GetRoleCommand({ RoleName: roleName }));
    const r = resp.Role || {};
    return { details: {
        'Role Name': r.RoleName, 'ARN': r.Arn, 'Path': r.Path || '/',
        'Created': toIso(r.CreateDate),
        'Max Session': (r.MaxSessionDuration || '-') + ' s',
        'Last Used': toIso(r.RoleLastUsed?.LastUsedDate),
        'Description': r.Description || '-'
    } };
}

async function describeIamPolicy(config, arn) {
    const client = new IAMClient(config);
    const resp = await client.send(new GetPolicyCommand({ PolicyArn: arn }));
    const p = resp.Policy || {};
    return { details: {
        'Policy Name': p.PolicyName, 'ARN': p.Arn, 'Path': p.Path || '/',
        'Attachments': p.AttachmentCount, 'Default Version': p.DefaultVersionId || '-',
        'Created': toIso(p.CreateDate), 'Updated': toIso(p.UpdateDate),
        'Description': p.Description || '-'
    } };
}

async function describeIamUser(config, userName) {
    const client = new IAMClient(config);
    const resp = await client.send(new GetUserCommand({ UserName: userName }));
    const u = resp.User || {};
    return { details: {
        'User Name': u.UserName, 'ARN': u.Arn, 'Path': u.Path || '/',
        'Created': toIso(u.CreateDate), 'Password Last Used': toIso(u.PasswordLastUsed)
    } };
}

async function describeInstanceProfile(config, name) {
    const client = new IAMClient(config);
    const resp = await client.send(new GetInstanceProfileCommand({ InstanceProfileName: name }));
    const ip = resp.InstanceProfile || {};
    return { details: {
        'Instance Profile': ip.InstanceProfileName, 'ARN': ip.Arn, 'Path': ip.Path || '/',
        'Created': toIso(ip.CreateDate),
        'Roles': (ip.Roles || []).map(r => r.RoleName).join(', ') || '(none)'
    } };
}

// Management / observability / security --------------------------------------

async function describeCfnStack(config, arn) {
    const client = new CloudFormationClient(config);
    const resp = await client.send(new DescribeStacksCommand({ StackName: arn }));
    const s = resp.Stacks?.[0];
    if (!s) return { details: { 'ARN': arn, 'Error': 'Not found' } };
    return { details: {
        'Stack Name': s.StackName, 'Status': s.StackStatus, 'Created': toIso(s.CreationTime),
        'Updated': toIso(s.LastUpdatedTime), 'Drift': s.DriftInformation?.StackDriftStatus || '-',
        'Description': s.Description || '-'
    } };
}

async function describeAlarm(config, alarmName) {
    const client = new CloudWatchClient(config);
    const resp = await client.send(new DescribeAlarmsCommand({ AlarmNames: [alarmName] }));
    const a = resp.MetricAlarms?.[0] || resp.CompositeAlarms?.[0];
    if (!a) return { details: { 'Alarm': alarmName, 'Error': 'Not found' } };
    return { details: {
        'Alarm Name': a.AlarmName, 'State': a.StateValue,
        'Metric': a.MetricName || '(composite)', 'Namespace': a.Namespace || '-',
        'Actions enabled': a.ActionsEnabled ? 'Yes' : 'No', 'Updated': toIso(a.StateUpdatedTimestamp)
    } };
}

async function describeLogGroup(config, name) {
    const client = new CloudWatchLogsClient(config);
    const nm = name.startsWith('/') ? name : '/' + name;
    // logGroupNamePrefix is a PREFIX match, so /aws/lambda/foo also matches
    // /aws/lambda/foobar. Combined with limit:1 this previously returned
    // whichever group came first and rendered its retention, size and
    // encryption status as the requested group's. Ask for several and require
    // an exact name match rather than trusting position.
    const resp = await client.send(new DescribeLogGroupsCommand({ logGroupNamePrefix: nm, limit: 50 }));
    const g = (resp.logGroups || []).find(lg => lg.logGroupName === nm);
    if (!g) return { details: { 'Log Group': nm, 'Note': 'Metadata not accessible' } };
    return { details: {
        'Log Group': g.logGroupName, 'Retention': g.retentionInDays ? g.retentionInDays + ' days' : 'Never expire',
        'Stored': g.storedBytes != null ? Math.round(g.storedBytes / 1024) + ' KB' : '-',
        'Created': toIso(g.creationTime), 'Encrypted': g.kmsKeyId ? 'Yes (KMS)' : 'No'
    } };
}

async function describeKmsKey(config, keyId) {
    const client = new KMSClient(config);
    const resp = await client.send(new DescribeKeyCommand({ KeyId: keyId }));
    const k = resp.KeyMetadata || {};
    return { details: {
        'Key ID': k.KeyId, 'ARN': k.Arn, 'State': k.KeyState, 'Usage': k.KeyUsage,
        'Spec': k.KeySpec || k.CustomerMasterKeySpec || '-',
        'Manager': k.KeyManager, 'Created': toIso(k.CreationDate),
        'Description': k.Description || '-'
    } };
}

async function describeCertificate(config, arn) {
    const client = new ACMClient(config);
    const resp = await client.send(new DescribeCertificateCommand({ CertificateArn: arn }));
    const c = resp.Certificate || {};
    return { details: {
        'Domain': c.DomainName, 'ARN': c.CertificateArn, 'Status': c.Status,
        'Type': c.Type || '-', 'In Use By': (c.InUseBy || []).length,
        'Not After': toIso(c.NotAfter), 'Issued': toIso(c.IssuedAt),
        'Renewal': c.RenewalEligibility || '-'
    } };
}

// ─── Serve Frontend ────────────────────────────────────────────────────────────

app.get('/', (req, res) => {
    // Set the charset explicitly: res.send() only adds a default when
    // Content-Type is unset, and setting it here suppresses that.
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(HTML_PAGE);
});

// ─── Error handling ────────────────────────────────────────────────────────────
// Must be registered last, after every route.
//
// Without a terminal handler, any thrown error reaches Express's built-in
// finalhandler, which puts the full stack trace in the response body whenever
// NODE_ENV !== 'production' - and this app never sets NODE_ENV, so the leaky
// mode would be the default. Stack traces from a credential or SDK failure can
// name profile paths, role ARNs and account ids.
//
// Log the detail, return a correlation id, and keep the response generic.
app.use((err, req, res, next) => {
    const ref = Math.random().toString(36).slice(2, 10);
    console.error('[' + ref + '] Unhandled error on ' + req.method + ' ' + req.path + ':',
                  err && (err.stack || err.message || err));

    if (res.headersSent) return next(err);

    if (req.path.startsWith('/api/') || req.get('accept') === 'application/json') {
        return res.status(500).json({ error: 'Internal error. Reference: ' + ref });
    }
    res.status(500)
        .type('text/plain')
        .send('Internal error.\nReference: ' + ref + '\nSee the server log for details.\n');
});

app.listen(PORT, HOST, () => {
    const found = (() => {
        try { return profiles.listProfiles().length; } catch { return 0; }
    })();

    console.log('\n  AWS Resource Viewer (Resource Explorer) running at http://' + HOST + ':' + PORT);
    console.log('  Credentials   AWS CLI profiles (' + found + ' found in ' + profiles.configPath() + ')');
    console.log('  STS region    ' + CFG.region);
    if (CFG.isLoopbackBind) {
        console.log('  Bind          ' + HOST + '  (loopback - not reachable from the network)');
    } else {
        console.log('  Bind          ' + HOST + '  *** NON-LOOPBACK: this tool has no authentication and');
        console.log('                exposes every AWS profile on this machine. You set');
        console.log('                ALLOW_NON_LOOPBACK=true. Put your own auth in front of it. ***');
    }
    console.log('\n  Select an AWS profile in the app to begin.\n');
});


// ─── Embedded HTML ─────────────────────────────────────────────────────────────

const HTML_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS Resource Viewer</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Inter', -apple-system, sans-serif; background: #f7f8fa; color: #1a202c; min-height: 100vh; font-size: 13px; }

/* Top Navigation Bar */
.top-bar {
    background: #181c21;
    border-bottom: 1px solid #1a2332;
    padding: 10px 24px;
    display: flex; align-items: center;
    position: sticky; top: 0; z-index: 100;
}
.top-bar .logo { display: flex; align-items: center; gap: 12px; margin-right: 32px; }
.top-bar .logo span { font-size: 15px; font-weight: 600; color: #fff; }
.top-bar .logo .version-badge { font-size: 10px; background: #ff9900; color: #232f3e; padding: 2px 6px; border-radius: 3px; font-weight: 700; }
.top-bar .nav-right { margin-left: auto; display: flex; align-items: center; gap: 16px; }

/* Region Dropdown */
.region-dropdown-wrapper { position: relative; }
.region-dropdown-btn {
    display: flex; align-items: center; gap: 6px;
    padding: 6px 12px; background: rgba(255,255,255,0.1);
    border-radius: 4px; color: #fff; font-size: 12px; cursor: pointer;
    border: none; font-family: inherit;
}
.region-dropdown-btn:hover { background: rgba(255,255,255,0.15); }
.region-dropdown-panel {
    position: absolute; top: calc(100% + 6px); right: 0;
    width: 320px; background: #fff; border: 1px solid #e2e8f0;
    border-radius: 8px; box-shadow: 0 10px 40px rgba(0,0,0,0.15);
    z-index: 200; display: none; padding: 12px;
}
.region-dropdown-panel.open { display: block; }
.region-dropdown-panel .rdp-title { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #718096; margin-bottom: 8px; }
.region-selected-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; min-height: 28px; padding: 6px; background: #f7f8fa; border-radius: 4px; border: 1px solid #edf2f7; }
.region-sel-tag {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 3px 8px; background: #ebf8ff; border: 1px solid #bee3f8;
    border-radius: 4px; font-size: 11px; color: #2b6cb0; font-weight: 500;
}
.region-sel-tag .remove-tag { cursor: pointer; font-size: 13px; line-height: 1; color: #4299e1; }
.region-sel-tag .remove-tag:hover { color: #e53e3e; }
.region-add-select {
    width: 100%; padding: 7px 10px; border: 1px solid #e2e8f0;
    border-radius: 4px; font-size: 12px; font-family: inherit; color: #2d3748;
    background: #fff; cursor: pointer;
}
.rdp-hint { font-size: 10px; color: #a0aec0; margin-top: 8px; }

/* View Toggle */
.view-toggle {
    display: flex; align-items: center;
    background: rgba(255,255,255,0.1);
    border-radius: 6px; padding: 3px; gap: 0;
}
.view-toggle-option {
    padding: 5px 14px; border-radius: 4px;
    font-size: 11px; font-weight: 500;
    color: rgba(255,255,255,0.6); cursor: pointer;
    transition: all 0.2s ease; user-select: none; white-space: nowrap;
}
.view-toggle-option.active { background: #ff9900; color: #232f3e; font-weight: 600; }
.view-toggle-option:hover:not(.active) { color: #fff; }

.account-selector {
    display: flex; align-items: center; gap: 6px;
    padding: 6px 12px; background: rgba(255,255,255,0.1);
    border-radius: 4px; color: #fff; font-size: 12px; cursor: pointer;
}
.account-selector:hover { background: rgba(255,255,255,0.15); }

/* Theme Toggle */
.theme-toggle-btn {
    display: flex; align-items: center; justify-content: center;
    width: 30px; height: 30px; padding: 0;
    background: rgba(255,255,255,0.1); border: none; border-radius: 4px;
    color: #fff; font-size: 14px; cursor: pointer; font-family: inherit;
}
.theme-toggle-btn:hover { background: rgba(255,255,255,0.15); }

/* Shown beside the total when the server reports the inventory is knowingly
   incomplete (page cap hit, or the global-resource query failed). Hover for
   the reason. Deliberately visible rather than buried in a log. */
.stat-partial {
    margin-left: 6px; padding: 1px 6px; border-radius: 3px;
    background: #b7791f; color: #fff; font-size: 10px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.3px; cursor: help;
}

/* Export & Compare Buttons */
.stats-action-btn {
    display: flex; align-items: center; justify-content: center;
    width: 28px; height: 28px; padding: 0;
    background: rgba(0,0,0,0.15); border: none; border-radius: 4px;
    color: #000; cursor: pointer; flex-shrink: 0;
}
.stats-action-btn:hover { background: rgba(0,0,0,0.25); }
.stats-action-btn svg { width: 16px; height: 16px; }

/* Compare Modal */
.compare-overlay {
    position: fixed; inset: 0; z-index: 1000;
    background: rgba(0,0,0,0.5); display: none;
    align-items: center; justify-content: center;
}
.compare-overlay.visible { display: flex; }
.compare-modal {
    background: #fff; border-radius: 12px;
    width: 90vw; max-width: 700px; max-height: 80vh;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    padding: 24px; display: flex; flex-direction: column; overflow: hidden;
}
.compare-modal .compare-header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 16px; padding-bottom: 12px;
    border-bottom: 1px solid #e2e8f0;
}
.compare-modal .compare-header h3 { margin: 0; font-size: 15px; font-weight: 600; color: #1a202c; }
.compare-modal .compare-close {
    width: 28px; height: 28px; display: flex; align-items: center; justify-content: center;
    cursor: pointer; border-radius: 4px; font-size: 18px; color: #a0aec0;
    border: none; background: none;
}
.compare-modal .compare-close:hover { background: #edf2f7; color: #1a202c; }
.compare-modal .compare-inputs { display: flex; flex-direction: column; gap: 12px; margin-bottom: 16px; }
.compare-modal .compare-inputs label { font-size: 12px; font-weight: 500; color: #4a5568; display: flex; flex-direction: column; gap: 4px; }
.compare-modal .compare-inputs input[type="file"] { font-size: 12px; }
.compare-modal .compare-run-btn {
    padding: 8px 16px; background: #3182ce; color: #fff; border: none;
    border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer;
}
.compare-modal .compare-run-btn:hover { background: #2b6cb0; }
.compare-modal .compare-run-btn:disabled { background: #a0aec0; cursor: not-allowed; }
.compare-results { overflow-y: auto; flex: 1; min-height: 0; }
.compare-results h4 { font-size: 13px; font-weight: 600; margin: 12px 0 6px; color: #1a202c; }
.compare-results ul { list-style: disc; padding-left: 20px; font-size: 12px; color: #2d3748; margin-bottom: 8px; }
.compare-results ul li { margin-bottom: 3px; }
.compare-results .diff-none { color: #718096; font-size: 12px; }

/* Stats bar */
.stats-bar {
    background: #ed7100; 
    padding: 5px 24px; display: flex; align-items: center; gap: 16px;
    font-size: 11px; color: #000;
}
.stats-bar .stat-item { display: flex; align-items: center; gap: 4px; }
.stats-bar .stat-value { font-weight: 600; color: #000; }

/* Main Content */
/* At most two panels (one account, up to two regions), but wrapping is kept for
   narrow windows: below about 890px two side-by-side panels would compress past
   the point where a resource name and its type label both fit, and stacking them
   is better than truncating both. */
.main-content {
    display: flex; flex-wrap: wrap; gap: 16px; padding: 16px; flex: 1;
    align-content: flex-start;
    min-height: calc(100vh - 100px); background: #465061;
}
.region-panel {
    /* Grow to fill a row, but never below 420px - that is the floor at which a
       resource name plus its type label still fit without truncation. */
    flex: 1 1 420px; min-width: 420px; max-width: 100%;
    /* Matches main-content's min-height less its 32px of vertical padding, so a
       single row still fills the viewport and scrolls internally exactly as it
       did before wrapping was introduced. Without this, align-content:flex-start
       would size rows to their content and short panels would no longer reach the
       bottom of the window. */
    min-height: calc(100vh - 132px);
    display: flex; flex-direction: column;
    overflow: hidden; border-radius: 12px;
    border: 1px solid #555c65; background: #fff;
    box-shadow: 0 2px 8px 2px #000;
}
.region-panel-header {
    padding: 14px 16px; background: #181c21;
    border-bottom: 1px solid #6c7d95;
    /* Base weight is 500, not 700: the account id is the part that should carry
       the emphasis, and it cannot stand out if everything around it is bold. */
    font-size: 16px; font-weight: 500; color: #a8aebc;
    display: flex; align-items: center; justify-content: space-between;
}
/* Header reads "<account id> - <region> (<profile>)". The account id leads
   because it is the unambiguous fact: a profile name says nothing about which
   account it actually reaches. The profile is kept, in lighter text, because it
   is what the operator selected and therefore what they would change to look
   elsewhere. */
.region-panel-header .hdr-account { font-weight: 700; color: #cdd4de; }
.region-panel-header .hdr-profile { font-weight: 400; font-size: 13px; color: #7d8797; }
.region-panel-header .resource-count { font-size: 12px; font-weight: 400; color: #aaa; }
.region-panel-body {
    flex: 1; overflow-y: auto; padding: 16px; background: #1f2530;
}
.region-panel-body::-webkit-scrollbar { width: 6px; }
.region-panel-body::-webkit-scrollbar-thumb { background: #cbd5e0; border-radius: 3px; }

/* Group Section */
.group-section { margin-bottom: 10px; }
.group-header {
    display: flex; align-items: center; gap: 8px;
    padding: 5px 10px; background: #1d1d1d;
    border: 1px solid #e2e8f0; border-radius: 5px 5px 0 0;
    cursor: pointer; user-select: none;
}
.group-header:hover { background: #333; }
.group-header .group-name { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: #b2b2b2; flex: 1; }
.group-header .group-count { font-size: 11px; color: #ccc; }
.group-header .group-toggle { font-size: 12px; color: #a0aec0; transition: transform 0.2s; }
.group-section.collapsed .group-toggle { transform: rotate(-90deg); }
.group-section.collapsed .group-body { display: none; }

.group-body {
    border: 1px solid #e2e8f0; border-top: none;
    border-radius: 0 0 8px 8px; background: #fff;
    padding: 0px 5px;
}

/* Icon Matrix */
.icon-matrix {
    display: flex; flex-wrap: wrap; gap: 3px;
    align-content: flex-start; row-gap: 10px;
}
.icon-matrix-item {
    width: 40px; height: 40px; border-radius: 5px;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer; position: relative;
    transition: transform 0.1s, box-shadow 0.1s;
    background: #1e1e1e; padding: 4px;
}
.icon-matrix-item:hover {
    transform: scale(1.15);
    box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 10;
}
.icon-matrix-item img { width: 28px; height: 28px; object-fit: contain; }
.icon-matrix-item .icon-label {
    position: absolute; bottom: -11px; left: -4px; right: -4px;
    font-size: 7px; text-align: center; color: #e9e9e9;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    line-height: 1.2; font-weight: 500;
}
/* Card View - one resource per row.
   Deliberately a single column: at two columns the right-hand one was clipped
   by the panel edge, so long resource names (the common case for generated
   ARNs) were cut off with no way to read them. One full-width row per resource
   gives every name the whole panel to use. */
.card-grid { display: grid; grid-template-columns: 1fr; gap: 4px; }
.resource-card-item {
    display: flex; align-items: center; padding: 2px 10px; gap: 8px;
    border-radius: 4px; cursor: pointer; transition: background 0.1s;
}
/* Dark is the default theme, so the base hover must be a dark-theme value. A
   light #edf2f7 here put pale #ccc text (.rc-name below) on a near-white
   background at roughly 1.4:1 - the resource name vanished on hover. */
.resource-card-item:hover { background: rgba(255,255,255,0.08); }
.resource-card-item img { width: 20px; height: 20px; object-fit: contain; }
.resource-card-item .rc-name { font-size: 11px; color: #ccc; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
/* Never let a long resource name squeeze or wrap the type label: .rc-name is
   flex:1 and ellipsises, so the type stays pinned at the right of the row. */
.resource-card-item .rc-type { font-size: 9px; color: #a0aec0; flex-shrink: 0; white-space: nowrap; }

/* Detail Popup */
.detail-popup {
    position: fixed; z-index: 500;
    background: #fff; border: 1px solid #e2e8f0;
    border-radius: 10px; padding: 16px;
    min-width: 300px; width: max-content; max-width: 90vw;
    box-shadow: 0 10px 40px rgba(0,0,0,0.12);
    display: none; user-select: text;
}
.detail-popup.visible { display: block; }
.detail-popup .popup-header {
    display: flex; align-items: center;
    margin-bottom: 12px; padding-bottom: 10px;
    border-bottom: 1px solid #edf2f7;
}
.detail-popup .popup-header img { width: 24px; height: 24px; }
.detail-popup .popup-header .popup-title { font-size: 13px; font-weight: 600; color: #1a202c; flex: 1; word-break: break-all; margin-left: 8px; }
.detail-popup .popup-header .popup-close {
    width: 28px; height: 28px; display: flex; align-items: center; justify-content: center;
    cursor: pointer; border-radius: 4px; font-size: 18px; color: #a0aec0;
}
.detail-popup .popup-header .popup-close:hover { background: #edf2f7; color: #1a202c; }
/* Console link, sized and coloured to match the close button so the two read as
   one pair of controls rather than a link bolted next to an icon. */
.detail-popup .popup-header .popup-link {
    width: 28px; height: 28px; display: flex; align-items: center; justify-content: center;
    cursor: pointer; border-radius: 4px; color: #a0aec0;
    text-decoration: none; flex-shrink: 0;
}
/* The icon is an inline SVG stroked with currentColor, so it picks up the link's
   colour and hover without a rule of its own. display:block stops the inline
   baseline gap from pushing it off centre inside the 20px box. */
.detail-popup .popup-header .popup-link svg { display: block; }
.detail-popup .popup-header .popup-link:hover { background: #edf2f7; color: #1a202c; }
/* Dependency graph button in popup header */
.detail-popup .popup-header .popup-deps-btn {
    width: 28px; height: 28px; display: flex; align-items: center; justify-content: center;
    cursor: pointer; border-radius: 4px; color: #a0aec0;
    background: none; border: none; padding: 0; flex-shrink: 0;
}
.detail-popup .popup-header .popup-deps-btn:hover { background: #edf2f7; color: #1a202c; }
.detail-popup .popup-header .popup-deps-btn svg { display: block; }
.detail-popup .popup-loading { text-align: center; padding: 20px; color: #718096; font-size: 12px; }
.detail-popup .popup-row { display: flex; justify-content: space-between; padding: 4px 0; gap: 16px; }
.detail-popup .popup-row .popup-key { font-size: 11px; color: #718096; font-weight: 500; white-space: nowrap; }
.detail-popup .popup-row .popup-val { font-size: 11px; color: #1a202c; word-break: break-all; text-align: right; }

/* Dependency Graph Modal */
.dep-graph-overlay {
    position: fixed; inset: 0; z-index: 1000;
    background: rgba(0,0,0,0.5); display: flex;
    align-items: center; justify-content: center;
}
.dep-graph-modal {
    background: #fff; border-radius: 12px;
    width: 90vw; max-width: 720px;
    max-height: 80vh; overflow-y: auto;
    box-shadow: 0 20px 60px rgba(0,0,0,0.2);
    padding: 24px;
}
.dep-graph-modal .dep-header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 16px; padding-bottom: 12px;
    border-bottom: 1px solid #e2e8f0;
}
.dep-graph-modal .dep-header h3 {
    margin: 0; font-size: 15px; font-weight: 600; color: #1a202c;
}
.dep-graph-modal .dep-close {
    width: 28px; height: 28px; display: flex; align-items: center; justify-content: center;
    cursor: pointer; border-radius: 4px; font-size: 18px; color: #a0aec0;
    border: none; background: none;
}
.dep-graph-modal .dep-close:hover { background: #edf2f7; color: #1a202c; }
.dep-graph-modal .dep-loading { text-align: center; padding: 32px; color: #718096; font-size: 13px; }
.dep-graph-modal .dep-error { text-align: center; padding: 32px; color: #e53e3e; font-size: 13px; }

/* Tree rendering */
.dep-tree { padding: 0 4px; }
.dep-tree ul { list-style: none; padding-left: 24px; margin: 0; }
.dep-tree > ul { padding-left: 0; }
.dep-tree li { position: relative; padding: 6px 0; }
.dep-tree li::before {
    content: ''; position: absolute; left: -16px; top: 0;
    border-left: 1px solid #cbd5e0; height: 100%;
}
.dep-tree li::after {
    content: ''; position: absolute; left: -16px; top: 18px;
    border-top: 1px solid #cbd5e0; width: 12px;
}
.dep-tree li:last-child::before { height: 18px; }
.dep-tree > ul > li::before, .dep-tree > ul > li::after { display: none; }
.dep-node {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 4px 10px; border-radius: 6px;
    border: 1px solid #e2e8f0; background: #f7fafc;
}
.dep-node .dep-node-type {
    font-size: 9px; font-weight: 600; color: #718096;
    background: #edf2f7; padding: 2px 6px; border-radius: 3px;
    white-space: nowrap;
}
.dep-node .dep-node-name {
    font-size: 12px; color: #1a202c; font-weight: 500;
    word-break: break-all;
}
.dep-tree > ul > li > .dep-node {
    background: #ebf8ff; border-color: #90cdf4;
}
.dep-node-link { cursor: pointer; }
.dep-node-link:hover { background: #edf2f7; border-color: #a0aec0; }
.dep-node-link .dep-node-link-hint {
    font-size: 10px; color: #a0aec0; margin-left: 2px;
}
.dep-node-link:hover .dep-node-link-hint { color: #3182ce; }

/* Settings drawer */
.settings-toggle {
    position: fixed; bottom: 20px; right: 20px;
    width: 48px; height: 48px;
    background: #3182ce; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer; box-shadow: 0 4px 12px rgba(49,130,206,0.3);
    z-index: 200; font-size: 20px; color: white;
}
.settings-toggle:hover { transform: scale(1.1); }
.settings-drawer {
    position: fixed; top: 0; right: -420px; width: 420px; height: 100vh;
    background: #fff; border-left: 1px solid #e2e8f0;
    z-index: 300; transition: right 0.3s ease; display: flex; flex-direction: column;
}
.settings-drawer.open { right: 0; }
.settings-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.3); z-index: 250; display: none; }
.settings-overlay.open { display: block; }
.drawer-header { padding: 10px 20px; border-bottom: 1px solid #e2e8f0; display: flex; align-items: center; justify-content: space-between; }
.drawer-header h2 { font-size: 16px; font-weight: 600; color: #1a202c; }
.drawer-close { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; cursor: pointer; border-radius: 4px; font-size: 18px; color: #718096; }
.drawer-close:hover { background: #edf2f7; }
.drawer-body { flex: 1; overflow-y: auto; padding: 10px; }
/* Profile picker. Credentials come from the operator's AWS CLI profiles, so
   this is the app's entry gate - nothing loads until one is selected. Built as
   a dropdown plus a removable chip per selection, matching the region picker so
   multi-select behaves identically in both places. */
.profile-picker {
    border: 1px solid #e2e8f0; border-radius: 4px; background: #f7f8fa;
    padding: 10px 12px;
}
.profile-selected {
    display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 9px;
}
.profile-none { font-size: 11px; color: #a0aec0; }
.profile-sel-tag {
    display: inline-flex; align-items: center; gap: 6px;
    background: #ebf8ff; border: 1px solid #bee3f8; border-radius: 3px;
    padding: 4px 7px; font-size: 12px; color: #2c5282; max-width: 100%;
}
.profile-sel-tag .pst-name { font-weight: 600; word-break: break-all; }
.profile-sel-tag .pst-type { font-size: 10px; color: #4a7fa8; }
.profile-sel-tag .remove-tag {
    cursor: pointer; font-size: 14px; line-height: 1; color: #4299e1; flex-shrink: 0;
}
.profile-sel-tag .remove-tag:hover { color: #e53e3e; }
.profile-add-select {
    width: 100%; padding: 8px 10px; background: #fff;
    border: 1px solid #d2d6dc; border-radius: 4px;
    color: #1a202c; font-size: 12px; font-family: inherit; cursor: pointer;
}
.profile-add-select:focus { outline: none; border-color: #3182ce; box-shadow: 0 0 0 2px rgba(49,130,206,0.2); }
.profile-add-select:disabled { cursor: default; color: #a0aec0; background: #f7f8fa; }
.profile-source {
    padding-top: 8px; font-size: 10px; color: #a0aec0;
    border-top: 1px solid #edf2f7; word-break: break-all;
    font-family: ui-monospace, monospace; line-height: 1.5;
}
.profile-source code { font-size: 10px; }
.drawer-field { margin-bottom: 16px; }
.drawer-field label { display: block; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #718096; margin-bottom: 6px; }
.drawer-field input { width: 100%; padding: 9px 12px; background: #f7f8fa; border: 1px solid #d2d6dc; border-radius: 4px; color: #1a202c; font-size: 13px; font-family: inherit; }
.drawer-field input:focus { outline: none; border-color: #3182ce; box-shadow: 0 0 0 2px rgba(49,130,206,0.2); }
.drawer-footer { padding: 16px 20px; border-top: 1px solid #e2e8f0; }
.btn-fetch { width: 100%; padding: 10px; background: #3182ce; color: white; border: none; border-radius: 4px; font-size: 13px; font-weight: 600; cursor: pointer; font-family: inherit; }
.btn-fetch:hover { background: #2c5282; }
.btn-fetch:disabled { background: #cbd5e0; color: #718096; cursor: not-allowed; }
/* Same button in the empty state, where width:100% would stretch it across the
   whole viewport rather than the drawer it was sized for. */
.btn-fetch.empty-action { width: auto; padding: 9px 18px; margin-top: 18px; }
.drawer-info { margin-top: 12px; padding: 8px; background: #ebf8ff; border-radius: 6px; border: 1px solid #bee3f8; }
.drawer-info p { font-size: 11px; color: #2b6cb0; line-height: 1.5; }
.drawer-info .info-title { font-weight: 700; margin-bottom: 4px; }
.drawer-info code {
    background: #d9ecfb; padding: 1px 4px; border-radius: 3px;
    font-family: ui-monospace, monospace; font-size: 10px; word-break: break-all;
}

/* Empty state */
.empty-main { display: flex; align-items: center; justify-content: center; min-height: 60vh; color: #ccd3dc; font-size: 15px; text-align: center; width: 100%; }
.empty-icon { font-size: 48px; opacity: 0.5; }
.empty-sub { font-size: 12px; margin-top: 8px; opacity: 0.8; }

/* Tag Filter */
.tag-filter-wrapper { position: relative; min-width: 280px; max-width: 400px; }
.tag-filter-input-area {
    display: flex; flex-wrap: wrap; align-items: center; gap: 4px;
    padding: 4px 8px; background: #f7f8fa; border: 1px solid #e2e8f0;
    border-radius: 4px; cursor: text; min-height: 28px;
}
.tag-filter-input-area:focus-within { border-color: #3182ce; box-shadow: 0 0 0 2px rgba(49,130,206,0.15); }
.tag-search-input {
    border: none; outline: none; background: transparent;
    font-size: 11px; font-family: inherit; color: #2d3748;
    flex: 1; min-width: 80px; padding: 2px 0;
}
.tag-search-input::placeholder { color: #a0aec0; }
.tag-pills { display: flex; flex-wrap: wrap; gap: 3px; }
.tag-pill {
    display: inline-flex; align-items: center; gap: 3px;
    padding: 2px 6px; background: #ebf8ff; border: 1px solid #bee3f8;
    border-radius: 3px; font-size: 10px; color: #2b6cb0; font-weight: 500;
    white-space: nowrap; max-width: 180px;
}
.tag-pill .tag-pill-text {
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    max-width: 140px;
}
.tag-pill .tag-pill-remove {
    cursor: pointer; font-size: 14px; line-height: 1; color: #4299e1;
    flex-shrink: 0; padding: 0 2px;
}
.tag-pill .tag-pill-remove:hover { color: #e53e3e; }
.tag-dropdown-panel {
    position: absolute; top: calc(100% + 4px); left: 0; right: 0;
    background: #fff; border: 1px solid #e2e8f0; border-radius: 6px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.12); z-index: 300;
    max-height: 220px; overflow-y: auto; display: none;
}
.tag-dropdown-panel.open { display: block; }
.tag-dropdown-list { padding: 4px 0; }
.tag-dropdown-item {
    padding: 6px 12px; font-size: 11px; color: #2d3748; cursor: pointer;
    display: flex; align-items: center; gap: 6px;
}
.tag-dropdown-item:hover { background: #ebf8ff; }
.tag-dropdown-item .tag-key { font-weight: 600; color: #2b6cb0; }
.tag-dropdown-item .tag-val { color: #718096; }
.tag-dropdown-item.selected { background: #e6fffa; }
.tag-dropdown-empty { padding: 10px 12px; font-size: 11px; color: #a0aec0; text-align: center; }

/* Loading */
.loading-bar { position: fixed; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, #3182ce 0%, #805ad5 50%, #3182ce 100%); background-size: 200% 100%; animation: loadSlide 1.5s linear infinite; z-index: 9999; display: none; }
.loading-bar.active { display: block; }
@keyframes loadSlide { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }

/* Discovery Loading Spinner */
.loading-spinner-container {
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 16px; z-index: 800; pointer-events: none;
}
.loading-spinner {
    width: 36px; height: 36px; position: relative;
}
.loading-spinner .spinner-line {
    position: absolute; top: 0; left: 50%;
    width: 3px; height: 10px; margin-left: -1.5px;
    background: #3182ce; border-radius: 2px;
    transform-origin: center 18px;
    animation: spinFade 1s linear infinite;
}
@keyframes spinFade {
    0% { opacity: 1; }
    100% { opacity: 0.15; }
}
.loading-spinner-text { font-size: 13px; color: #718096; }

/* Name Search */
.name-search-input {
    border: 1px solid #e2e8f0; outline: none; background: #f7f8fa;
    border-radius: 4px; padding: 4px 10px; font-size: 12px;
    min-width: 160px; max-width: 220px; height: 28px;
    font-family: inherit; color: #1a202c;
}
.name-search-input:focus { border-color: #3182ce; box-shadow: 0 0 0 2px rgba(49,130,206,0.15); }
.name-search-input::placeholder { color: #a0aec0; }

/* Toast */
.toast { position: fixed; bottom: 80px; left: 50%; transform: translateX(-50%) translateY(20px); background: #e53e3e; color: white; padding: 10px 20px; border-radius: 6px; font-size: 13px; opacity: 0; transition: opacity 0.3s, transform 0.3s; z-index: 999; pointer-events: none; }
.toast.visible { opacity: 1; transform: translateX(-50%) translateY(0); }

/* Group color accents. Class names are built by concatenation in renderGroup()
   ('group-header-accent-' + group), so these look unreferenced to a plain
   search - they are not. A bare .group-accent-* set used to live here too and
   was genuinely dead: nothing ever produced that prefix. */
.group-header-accent-Compute { border: 1px solid #ff990070; }
.group-header-accent-Containers {  border: 1px solid #ed710070; }
.group-header-accent-Database { border: 1px solid #3b82f699; }
.group-header-accent-Storage { border: 1px solid #2f9e4499; }
.group-header-accent-Networking { border: 1px solid #9297fe99; }
.group-header-accent-Messaging { border: 1px solid #e91e6380; }
.group-header-accent-Security { border: 1px solid #e53e3e80; }
.group-header-accent-Integration { border: 1px solid #9c27b099; }
.group-header-accent-CICD { border: 1px solid #0097a799; }
.group-header-accent-Observability { border: 1px solid #0277bd99; }
.group-header-accent-AIML { border: 1px solid #6d4c4199; }
.group-header-accent-IAM { border: 1px solid #ff572270; }
.group-header-accent-Other { border: 1px solid #78909c99; }
.group-header-accent-Analytics { border: 1px solid #ceadf45e; }

.group-body-accent-Compute { background: #ff990020; border: 1px solid #ff990070; }
.group-body-accent-Containers { background: #ed710020; border: 1px solid #ed710070; }
.group-body-accent-Database { background: #3b82f620; border: 1px solid #3b82f699; }
.group-body-accent-Storage { background: #2f9e4420; border: 1px solid #2f9e4499; }
.group-body-accent-Networking { background: #9297fe20; border: 1px solid #9297fe99; }
.group-body-accent-Messaging { background: #e91e6320; border: 1px solid #e91e6380; }
.group-body-accent-Security { background: #e53e3e20; border: 1px solid #e53e3e80; }
.group-body-accent-Integration { background: #b982c320; border: 1px solid #9c27b099; }
.group-body-accent-CICD { background: #0097a720; border: 1px solid #0097a799; }
.group-body-accent-Observability { background: #9ad9ff20; border: 1px solid #0277bd99; }
.group-body-accent-AIML { background: #d0958120; border: 1px solid #6d4c4199; }
.group-body-accent-IAM { background: #ff572220; border: 1px solid #ff572270; }
.group-body-accent-Other { background: #6ccf9720; border: 1px solid #78909c99; }
.group-body-accent-Analytics { background: #5716a020; border: 1px solid #ceadf45e; }

/* Light theme override. Dark is the default (matches the app's own palette);
   toggling applies data-theme="light" to <html> and these rules
   take over. Scoped to the same selectors the dark theme touches, so the
   fixed accent colors and top-bar (already theme-neutral) are untouched. */
[data-theme="light"] .stats-bar { border-bottom: 1px solid #e2e8f0; }
[data-theme="light"] .stats-bar, [data-theme="light"] .stats-bar .stat-value { color: #2d3748; }
[data-theme="light"] .main-content { background: #edf2f7; }
[data-theme="light"] .region-panel { border: 1px solid #e2e8f0; background: #fff; }
[data-theme="light"] .region-panel-header { background: #d5d1d1; color: #1a202c; }
[data-theme="light"] .region-panel-header .resource-count { color: #444; }
/* #cdd4de and #7d8797 are tuned for the dark header; on #d5d1d1 they fall to
   roughly 1.4:1 and 2.4:1, so both need light-theme counterparts. */
[data-theme="light"] .region-panel-header .hdr-account { color: #10151c; }
[data-theme="light"] .region-panel-header .hdr-profile { color: #55606f; }
[data-theme="light"] .region-panel-body { background: #f7f8fa; }
[data-theme="light"] .group-header { background: #e9e9e9; }
[data-theme="light"] .group-header:hover { background: #f7fafc; }
[data-theme="light"] .group-header .group-name { color: #4a5568; }
[data-theme="light"] .group-header .group-count { color: #718096; }
[data-theme="light"] .group-body { background: #fff; }
[data-theme="light"] .icon-matrix-item { background: #fff; border: 1px solid #e2e8f0; }
[data-theme="light"] .icon-matrix-item .icon-label { color: #4a5568; }
[data-theme="light"] .resource-card-item .rc-name { color: #2d3748; }
/* Counterparts for rules whose base values are tuned for the dark default.
   Without these, each renders light-grey on white in light theme, well under
   the 4.5:1 WCAG AA threshold: .subtype-label #aaa ~2.3:1 (and it labels every
   resource group row, so not a corner case), .show-all-label #999 ~2.9:1,
   .rc-type #a0aec0 ~2.3:1. */
[data-theme="light"] .subtype-label { color: #4a5568; }
[data-theme="light"] .show-all-label { color: #4a5568; }
[data-theme="light"] .show-all-label:hover { color: #1a202c; }
[data-theme="light"] .resource-card-item .rc-type { color: #718096; }
[data-theme="light"] .resource-card-item:hover { background: #edf2f7; }
[data-theme="light"] .subtype-row { border-bottom: 1px solid #e2e8f0; }
[data-theme="light"] .empty-main { color: #4a5568; }
[data-theme="light"] .empty-icon { opacity: 0.7; }
[data-theme="light"] .empty-sub { opacity: 1; }
[data-theme="light"] .stats-action-btn { background: rgba(0,0,0,0.08); color: #2d3748; }
[data-theme="light"] .stats-action-btn:hover { background: rgba(0,0,0,0.15); }

/* Sub-type rows within a group */
.subtype-row {
    display: flex; align-items: flex-start; gap: 12px;
    padding: 8px 0;
    border-bottom: 1px solid #666;
    padding-bottom: 12px;
}
.subtype-row:last-child { border-bottom: none; }
.subtype-label {
    writing-mode: horizontal-tb;
    font-size: 9px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.05em;
    color: #bbb;
    white-space: normal; word-wrap: break-word; overflow-wrap: break-word;
    width: 90px; min-width: 90px; max-width: 90px;
    padding-top: 5px; flex-shrink: 0;
    line-height: 1.4;
}
.subtype-count {
    font-size: 10px; font-weight: 600; color: #718096;
    margin-top: 2px; letter-spacing: 0;
    text-transform: none;
}
.subtype-content { flex: 1; min-width: 0; }
.subtype-content-scrollable {
    max-height: 168px;
    overflow-y: auto;
    scrollbar-width: thin;
    scrollbar-color: #cbd5e0 transparent;
}
.subtype-content-scrollable::-webkit-scrollbar { width: 5px; }
.subtype-content-scrollable::-webkit-scrollbar-track { background: transparent; }
.subtype-content-scrollable::-webkit-scrollbar-thumb { background: #cbd5e0; border-radius: 3px; }
.subtype-content-scrollable::-webkit-scrollbar-thumb:hover { background: #a0aec0; }
.subtype-content-list-scrollable {
    max-height: 280px;
    overflow-y: auto;
    scrollbar-width: thin;
    scrollbar-color: #cbd5e0 transparent;
}
.subtype-content-list-scrollable::-webkit-scrollbar { width: 5px; }
.subtype-content-list-scrollable::-webkit-scrollbar-track { background: transparent; }
.subtype-content-list-scrollable::-webkit-scrollbar-thumb { background: #cbd5e0; border-radius: 3px; }
.subtype-content-list-scrollable::-webkit-scrollbar-thumb:hover { background: #a0aec0; }

/* Show All checkbox in group header */
.show-all-label {
    display: flex; align-items: center; gap: 4px;
    font-size: 10px; color: #999; font-weight: 400;
    cursor: pointer; white-space: nowrap; margin-right: 8px;
    user-select: none;
}
/* Hover must brighten against the dark group header, not darken toward it -
   #4a5568 on #010101 was about 2.8:1 and got harder to read on hover. */
.show-all-label:hover { color: #e2e8f0; }
.show-all-checkbox {
    width: 13px; height: 13px; cursor: pointer;
    accent-color: #3182ce;
}

</style>
</head>
<body>

<div class="loading-bar" id="loading-bar"></div>

<!-- Top Bar -->
<div class="top-bar">
    <div class="logo">
        <span>AWS Resource Viewer</span>
        <span class="version-badge">v1</span>
    </div>
    <div class="nav-right">
        <div class="region-dropdown-wrapper">
            <button class="region-dropdown-btn" onclick="toggleRegionDropdown(event)">
                <span>Region</span>
                <span style="font-size:10px;">&#9660;</span>
            </button>
            <div class="region-dropdown-panel" id="region-dropdown-panel">
                <div class="rdp-title">Selected Regions (max 2)</div>
                <div class="region-selected-tags" id="region-selected-tags"></div>
                <select class="region-add-select" id="region-add-select" onchange="addRegionFromDropdown(this.value)">
                    <option value="">+ Add a region...</option>
                </select>
                <div class="rdp-hint">Select up to 2 regions. Resource Explorer index must be enabled in selected regions.</div>
            </div>
        </div>
        <div class="account-selector" onclick="toggleSettings()" title="Choose AWS profiles">
            <span id="account-label">No profile</span>
            <span style="font-size:10px;">&#9660;</span>
        </div>
        <div class="view-toggle" id="view-toggle">
            <div class="view-toggle-option active" id="vt-matrix" onclick="setView('matrix')">Icon Matrix</div>
            <div class="view-toggle-option" id="vt-cards" onclick="setView('cards')">List View</div>
        </div>
        <button class="theme-toggle-btn" id="theme-toggle-btn" onclick="toggleTheme()" title="Switch theme" aria-label="Switch between light and dark theme">
            <span id="theme-toggle-icon">&#9728;</span>
        </button>
    </div>
</div>

<!-- Stats Bar -->
<div class="stats-bar" id="stats-bar" style="display:none;">
    <div class="stat-item"><span>Total Resources:</span> <span class="stat-value" id="stat-total">0</span><span class="stat-partial" id="stat-partial" style="display:none;" title="">incomplete</span></div>
    <div class="stat-item" style="margin-left:auto; gap: 8px;">
        <input type="text" class="name-search-input" id="name-search-input" placeholder="Search by name..." oninput="onNameSearchInput(this.value)" aria-label="Filter resources by name">
        <div class="tag-filter-wrapper">
            <div class="tag-filter-input-area" id="tag-filter-input-area" onclick="openTagDropdown(event)">
                <div class="tag-pills" id="tag-pills"></div>
                <input type="text" class="tag-search-input" id="tag-search-input" placeholder="Filter by tags..." oninput="onTagSearchInput(this.value)" onfocus="openTagDropdown(event)">
            </div>
            <div class="tag-dropdown-panel" id="tag-dropdown-panel">
                <div class="tag-dropdown-list" id="tag-dropdown-list"></div>
            </div>
        </div>
        <button class="stats-action-btn" id="compare-btn" onclick="openCompareModal()" title="Compare exported snapshots" aria-label="Compare two exported JSON snapshots">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v18"/><path d="M3 12h4l3-9 4 18 3-9h4"/></svg>
        </button>
        <button class="stats-action-btn" id="export-btn" onclick="exportResources()" title="Export resources to JSON" aria-label="Export current resources to JSON file">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        </button>
    </div>
</div>

<!-- Main Content -->
<div class="main-content" id="main-content">
    <!-- First paint only. renderDisplay() replaces this as soon as init() runs,
         so it deliberately mirrors the profile gate rather than saying "select a
         region" - that used to contradict the state the user actually landed in
         a moment later. -->
    <div class="empty-main" id="empty-state">
        <div>
            <div class="empty-icon">&#128273;</div>
            <p>Select an AWS profile to begin</p>
            <p class="empty-sub">Loading profiles from your AWS CLI configuration...</p>
        </div>
    </div>
</div>

<!-- Detail Popup -->
<div class="detail-popup" id="detail-popup"></div>

<!-- Dependency Graph Modal -->
<div class="dep-graph-overlay" id="dep-graph-overlay" style="display:none" onclick="closeDependencyGraph(event)">
    <div class="dep-graph-modal" id="dep-graph-modal" onclick="event.stopPropagation()">
        <div class="dep-header">
            <h3 id="dep-graph-title">Dependency Graph</h3>
            <button class="dep-close" onclick="closeDependencyGraph()">&times;</button>
        </div>
        <div id="dep-graph-content"></div>
    </div>
</div>

<!-- Compare Modal -->
<div class="compare-overlay" id="compare-overlay" onclick="closeCompareModal(event)">
    <div class="compare-modal" onclick="event.stopPropagation()">
        <div class="compare-header">
            <h3>Compare Resource Snapshots</h3>
            <button class="compare-close" onclick="closeCompareModal()">&times;</button>
        </div>
        <div class="compare-inputs">
            <label>Baseline (older snapshot)
                <input type="file" id="compare-file-a" accept=".json">
            </label>
            <label>Current (newer snapshot)
                <input type="file" id="compare-file-b" accept=".json">
            </label>
        </div>
        <button class="compare-run-btn" id="compare-run-btn" onclick="runCompare()">Compare</button>
        <div class="compare-results" id="compare-results"></div>
    </div>
</div>

<!-- Settings Drawer -->
<div class="settings-overlay" id="settings-overlay" onclick="toggleSettings()"></div>
<div class="settings-drawer" id="settings-drawer">
    <div class="drawer-header">
        <h2>AWS Configuration</h2>
        <div class="drawer-close" onclick="toggleSettings()">&times;</div>
    </div>
    <div class="drawer-body">
        <div class="drawer-field">
            <label id="profile-label">AWS profile</label>
            <div class="profile-picker" id="profile-list">
                <div class="profile-selected" id="profile-selected"></div>
                <select class="profile-add-select" id="profile-add-select"
                        aria-labelledby="profile-label"
                        onchange="addProfileFromDropdown(this.value)">
                    <option value="">Loading profiles...</option>
                </select>
                <div class="profile-source" id="profile-source"></div>
            </div>
        </div>
        <div class="drawer-info">
            <p class="info-title">Resource Explorer discovery</p>
            <p>Inventory comes from AWS Resource Explorer. Details are fetched on-demand when you click a resource.</p>
            <p style="margin-top:6px;">Prerequisite: each region you view needs its own Resource Explorer index. Global resources (IAM, CloudFront, Route&nbsp;53) are indexed only in us-east-1 and are pulled in from there automatically.</p>
            <p style="margin-top:6px;">Note: Account-wide global resources (IAM, CloudFront, Route&nbsp;53) will appear duplicated across all selected regions since they are not region-specific.</p>
        </div>
        <div class="drawer-info">
            <p class="info-title">Permissions this profile needs</p>
            <p>Discovery requires <code>resource-explorer-2:GetIndex</code> and <code>resource-explorer-2:ListResources</code>. Without both, nothing loads.</p>
            <p style="margin-top:6px;">Detail panels also use per-service read calls &mdash; <code>ec2:Describe*</code>, <code>lambda:GetFunctionConfiguration</code>, <code>iam:GetRole</code> and similar. Any the profile lacks simply fall back to basic ARN information rather than erroring.</p>
            <p style="margin-top:6px;">The AWS managed <code>ReadOnlyAccess</code> policy covers everything. The README lists a tighter set if you prefer least privilege.</p>
        </div>
        <div style="margin-top:16px; padding-top:12px; border-top: 1px solid #e2e8f0;">
            <p style="font-size:11px;color:#718096;line-height:1.5;">
                Credentials come from your AWS CLI configuration and are resolved on the
                server. No AWS keys are entered in, stored by, or sent to the browser.
                One account is viewed at a time - choosing another profile replaces it.
            </p>
        </div>
    </div>
    <div class="drawer-footer">
        <button class="btn-fetch" id="fetch-btn" onclick="discoverAllResources()">Discover Resources</button>
    </div>
</div>

<!-- Settings FAB -->
<div class="settings-toggle" onclick="toggleSettings()">&#9881;</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script>
const AWS_REGIONS = [
    'us-east-1','us-east-2','us-west-1','us-west-2',
    'eu-west-1','eu-west-2','eu-west-3','eu-central-1','eu-north-1',
    'ap-southeast-1','ap-southeast-2','ap-northeast-1','ap-northeast-2','ap-south-1',
    'sa-east-1','ca-central-1','me-south-1','af-south-1'
];

const AWS_ICONS = {
    ec2: '/icons/ec2.svg', asg: '/icons/asg.svg', lambda: '/icons/lambda.svg',
    beanstalk: '/icons/beanstalk.svg', batch: '/icons/batch.svg', apprunner: '/icons/apprunner.svg',
    s3: '/icons/s3.svg', efs: '/icons/efs.svg',
    dynamodb: '/icons/dynamodb.svg', rds: '/icons/rds.svg', elasticache: '/icons/elasticache.svg',
    memorydb: '/icons/memorydb.svg', redshift: '/icons/redshift.svg',
    sqs: '/icons/sqs.svg', sns: '/icons/sns.svg', kinesis: '/icons/kinesis.svg',
    apigateway: '/icons/apigateway.svg', stepfunctions: '/icons/stepfunctions.svg',
    eventbridge: '/icons/eventbridge.svg',
    ecs: '/icons/ecs.svg', ecsServices: '/icons/ecsServices.svg', eks: '/icons/eks.svg',
    ecr: '/icons/ecr.svg',
    elb: '/icons/elb.svg', cloudfront: '/icons/cloudfront.svg', natgw: '/icons/natgw.svg',
    vpc: '/icons/vpc.svg', route53: '/icons/route53.svg',
    opensearch: '/icons/opensearch.svg', athena: '/icons/athena.svg',
    secrets: '/icons/secrets.svg', ssm: '/icons/ssm.svg', iam: '/icons/iam.svg',
    kms: '/icons/kms.svg', acm: '/icons/acm.svg', cognito: '/icons/cognito.svg',
    guardduty: '/icons/guardduty.svg',
    cloudwatch: '/icons/cloudwatch.svg', cloudtrail: '/icons/cloudtrail.svg',
    cloudformation: '/icons/cloudformation.svg', codebuild: '/icons/codebuild.svg',
    bedrock: '/icons/bedrock.svg', sagemaker: '/icons/sagemaker.svg', xray: '/icons/xray.svg',
    generic: '/icons/generic.svg'
};

const GROUP_ORDER = ['Compute','Storage','Database','Messaging','Containers','Networking','Integration','Security','CI/CD','Analytics','Observability','AI/ML','IAM','Other'];

// Primary (important) resource types per group - shown by default when "Show All" is unchecked
const PRIMARY_RESOURCE_TYPES = {
    'Compute': ['ec2:instance', 'lambda:function'],
    'Storage': ['s3:bucket', 'efs:file-system'],
    'Containers': ['ecs:cluster', 'eks:cluster', 'ecr:repository'],
    'Networking': ['ec2:internet-gateway', 'ec2:natgateway', 'ec2:subnet', 'ec2:vpc-endpoint', 'route53:hostedzone'],
    'Database': ['rds:db', 'rds:cluster', 'dynamodb:table', 'dynamodb:global-table'],
    'Messaging': ['sqs:queue', 'sns:topic', 'events:rule', 'events:event-bus'],
    'Integration': ['states:stateMachine', 'appsync:graphqlapi', 'apigateway:restapi', 'apigateway:api', 'apigateway:websocket-api'],
    'Security': ['kms:key', 'acm:certificate', 'ssm:parameter', 'secretsmanager:secret'],
    'CI/CD': ['cloudformation:stack', 'cloudformation:stackset', 'codedeploy:application', 'codepipeline:pipeline', 'codebuild:project'],
    'IAM': ['iam:group', 'iam:user', 'iam:instance-profile'],
    'Observability': ['logs:log-group', 'cloudtrail:trail'],
    'AI/ML': ['bedrock:agent', 'bedrock:knowledge-base', 'bedrock:guardrail', 'bedrock-agentcore:runtime', 'sagemaker:endpoint', 'sagemaker:model'],
    'Analytics': [],
    'Other': []
};

// Track "Show All" checkbox state per group per region
let showAllStates = {};

// AWS indexes global resources (IAM, CloudFront, Route 53) in this region only,
// so it is both where they are fetched from and the pane that shows them when
// selected. Must match GLOBAL_INDEX_REGION on the server.
const GLOBAL_INDEX_REGION = 'us-east-1';

let selectedRegions = ['us-east-1'];
let resourceData = {}; // paneKey -> { groups, totalResources, availableTags, accountId, partial }
let setupNeeded = {};  // paneKey -> { profile, region, message } when RE needs enabling
let currentView = 'matrix';
let selectedTagFilters = []; // [{key: 'env', value: 'prod'}, {key: 'team', value: undefined}]
let nameSearchFilter = ''; // resource name filter string
let availableTagsCache = {}; // key -> [values]

// ─── AWS profiles ──────────────────────────────────────────────────────────────
// There is no application login. The user picks AWS CLI profiles, and nothing
// is discovered until at least one is selected.

let availableProfiles = [];   // [{ name, region, type, source }]
let selectedProfiles = [];    // profile names, in selection order

/** Human label for the credential type reported by lib/profiles.js. */
function profileTypeLabel(type) {
    switch (type) {
        case 'sso': return 'IAM Identity Center / SSO';
        case 'process': return 'credential_process';
        case 'static': return 'access keys';
        case 'role': return 'assumed role';
        case 'web-identity': return 'web identity';
        // A profile that only sets e.g. region has no credential source of its
        // own; say so rather than showing the raw "unknown".
        default: return 'inherits from environment';
    }
}

async function loadProfiles() {
    try {
        const res = await fetch('/api/profiles', { headers: { 'Accept': 'application/json' } });
        if (!res.ok) throw new Error('Could not read AWS CLI configuration');
        const data = await res.json();
        availableProfiles = data.profiles || [];
        renderProfileList(data);
    } catch (e) {
        availableProfiles = [];
        // Re-render rather than overwriting the container: blowing away its
        // innerHTML would delete the <select> and chip holder that the rest of
        // this code looks up by id, so a transient read failure would leave the
        // picker permanently inert.
        renderProfileList();
        const src = document.getElementById('profile-source');
        if (src) src.textContent = e.message;
    }
}

/** True when a profile's credentials could not be resolved server-side. */
function handleProfileError(err) {
    if (!err) return false;
    if (err.code === 'PROFILE_REAUTH' || err.code === 'PROFILE_UNUSABLE' ||
        err.code === 'UNKNOWN_PROFILE' || err.code === 'NO_PROFILE') {
        // The server's message names the exact fix (e.g. aws sso login --profile X).
        showToast(err.error || 'Profile credentials unavailable');
        return true;
    }
    return false;
}

/**
 * Render the profile picker in the settings drawer.
 *
 * A dropdown of unselected profiles plus a removable chip per selected one -
 * the same shape as the region picker, so multi-select works the same way in
 * both places. The meta argument is only supplied by loadProfiles(); calls made
 * after a selection change omit it, so the source line is left as it is rather
 * than being blanked.
 */
function renderProfileList(meta) {
    const chips = document.getElementById('profile-selected');
    const select = document.getElementById('profile-add-select');
    if (!chips || !select) return;

    // Selected profiles, each removable.
    chips.innerHTML = '';
    if (selectedProfiles.length === 0) {
        chips.innerHTML = '<span class="profile-none">No profile selected</span>';
    } else {
        selectedProfiles.forEach(name => {
            const p = availableProfiles.find(x => x.name === name);
            const chip = document.createElement('span');
            chip.className = 'profile-sel-tag';

            const label = document.createElement('span');
            label.className = 'pst-name';
            label.textContent = name;
            chip.appendChild(label);

            if (p) {
                const type = document.createElement('span');
                type.className = 'pst-type';
                type.textContent = profileTypeLabel(p.type);
                chip.appendChild(type);
            }

            // addEventListener rather than an inline onclick string. A profile
            // name is arbitrary text from the operator's own ~/.aws files, and
            // one containing a quote would break out of an inline handler's
            // attribute - the region chips can get away with it because their
            // values come from a fixed list, but these cannot.
            const x = document.createElement('span');
            x.className = 'remove-tag';
            x.title = 'Remove ' + name;
            x.textContent = '\u00d7';
            x.addEventListener('click', () => toggleProfile(name));
            chip.appendChild(x);

            chips.appendChild(chip);
        });
    }

    // Dropdown offers only what is not already selected, so it never lets you
    // pick the same profile twice.
    select.innerHTML = '';
    const remaining = availableProfiles.filter(p => !selectedProfiles.includes(p.name));

    if (!availableProfiles.length) {
        const none = document.createElement('option');
        none.value = '';
        none.textContent = 'No AWS CLI profiles found';
        select.appendChild(none);
        select.disabled = true;
        const src = document.getElementById('profile-source');
        if (src) {
            src.innerHTML = 'Configure one with <code>aws configure</code> or ' +
                            '<code>aws configure sso</code>, then reopen this panel.';
        }
        return;
    }

    select.disabled = remaining.length === 0;
    const first = document.createElement('option');
    first.value = '';
    first.textContent = remaining.length === 0
        ? 'Profile selected'
        : (selectedProfiles.length === 0 ? 'Select a profile...' : 'Change profile...');
    select.appendChild(first);

    remaining.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.name;
        // textContent, not innerHTML: an <option> renders no markup, so an HTML
        // entity here would show up literally as "&middot;".
        opt.textContent = p.name + ' \u2014 ' + profileTypeLabel(p.type) +
                          (p.region ? ' \u00b7 ' + p.region : '');
        select.appendChild(opt);
    });

    if (meta && meta.configFile) {
        const src = document.getElementById('profile-source');
        // Name both files: a profile can come from either, so showing only the
        // config path makes a credentials-only profile look unexplained.
        if (src) {
            src.textContent = 'Read from ' + meta.configFile +
                (meta.credentialsFile ? ' and ' + meta.credentialsFile : '');
        }
    }
}

/** Selecting from the profile dropdown adds it, then resets the control. */
function addProfileFromDropdown(name) {
    if (!name) return;
    document.getElementById('profile-add-select').value = '';
    if (selectedProfiles.includes(name)) return;
    toggleProfile(name);
}

function toggleProfile(name) {
    const i = selectedProfiles.indexOf(name);
    if (i >= 0) {
        selectedProfiles.splice(i, 1);
        // Drop any data that came from this profile so the view cannot show
        // resources for a profile that is no longer selected.
        Object.keys(resourceData).forEach(k => { if (k.startsWith(name + '|')) delete resourceData[k]; });
        Object.keys(setupNeeded).forEach(k => { if (k.startsWith(name + '|')) delete setupNeeded[k]; });
        rebuildTagCache();
    } else {
        // One profile at a time, by design. Selecting another replaces it rather
        // than adding, so there is never more than one account on screen.
        //
        // The alternative was profiles x regions, which produced up to 8 panels
        // and, more importantly, an ambiguous control scheme: regions are chosen
        // in the top bar and profiles in this drawer, so adding a region silently
        // applied it to every selected account with nothing on screen saying so.
        // Panels stay keyed by profile (see paneKey) so the data model still
        // separates them correctly - only the selection is capped.
        selectedProfiles.forEach(prev => {
            Object.keys(resourceData).forEach(k => { if (k.startsWith(prev + '|')) delete resourceData[k]; });
            Object.keys(setupNeeded).forEach(k => { if (k.startsWith(prev + '|')) delete setupNeeded[k]; });
        });
        selectedProfiles.length = 0;
        rebuildTagCache();
        selectedProfiles.push(name);
    }
    renderProfileList();
    updateAccountLabel();
    renderDisplay();
    updateStats();
    updateFetchButton();
}

/** Top-bar label reflects the current profile selection. */
function updateAccountLabel() {
    const el = document.getElementById('account-label');
    if (!el) return;
    // Only ever none or one - toggleProfile replaces rather than appends.
    el.textContent = selectedProfiles.length === 0 ? 'No profile' : selectedProfiles[0];
}

/** Discovery requires at least one profile; reflect that in the button. */
function updateFetchButton() {
    const btn = document.getElementById('fetch-btn');
    if (!btn) return;
    const ready = selectedProfiles.length > 0 && selectedRegions.length > 0;
    btn.disabled = !ready;
    btn.textContent = selectedProfiles.length === 0
        ? 'Select a profile first'
        : (selectedRegions.length === 0 ? 'Select a region first' : 'Discover Resources');
}

async function init() {
    renderRegionDropdown();
    document.addEventListener('keydown', e => { if (e.key === 'Escape') { hidePopup(); closeRegionDropdown(); closeTagDropdown(); closeDependencyGraph(); } });
    document.addEventListener('click', e => {
        if (!e.target.closest('.region-dropdown-wrapper')) closeRegionDropdown();
        if (!e.target.closest('.tag-filter-wrapper')) closeTagDropdown();
        if (!e.target.closest('.detail-popup') && !e.target.closest('.icon-matrix-item') && !e.target.closest('.resource-card-item')) hidePopup();
    });

    // Load the profile list, but do NOT discover anything: credentials belong to
    // whichever profile the user chooses, so nothing is fetched until they pick
    // one. The settings drawer opens automatically when there is no selection so
    // the required next step is visible rather than hidden behind the gear icon.
    await loadProfiles();
    updateFetchButton();
    renderDisplay();

    if (selectedProfiles.length === 0) {
        document.getElementById('settings-drawer').classList.add('open');
        document.getElementById('settings-overlay').classList.add('open');
    }
}

// ─── Theme ─────────────────────────────────────────────────────────────────────
// Dark is the default (matches the palette the app ships with).
// The preference persists in localStorage.
//
// Note this runs from the inline script near the end of <body>, so the dark
// base CSS has already painted. A user whose saved preference is light sees a
// brief dark flash on load. Fixing that properly needs a tiny blocking script
// in <head> that sets data-theme before first paint; it is not done here to
// keep the page a single script block.
//
// Every localStorage access is wrapped: the API throws SecurityError outright
// when storage is denied (Safari private-browsing variants, sandboxed iframes,
// hardened cookie policies). An unguarded throw at this top level would abort
// the remainder of this script - including the init() call at the very bottom -
// while hoisted function declarations kept the inline on* handlers working. The
// page would look alive and simply never load any data.
function readStoredTheme() {
    try {
        return localStorage.getItem('arv-theme');
    } catch (e) {
        return null;
    }
}

function storeTheme(theme) {
    try {
        localStorage.setItem('arv-theme', theme);
    } catch (e) {
        // Preference cannot persist; the toggle still works for this page view.
    }
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const icon = document.getElementById('theme-toggle-icon');
    if (icon) icon.innerHTML = theme === 'light' ? '&#9790;' : '&#9728;';
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    const next = current === 'light' ? 'dark' : 'light';
    storeTheme(next);
    applyTheme(next);
}

(function initTheme() {
    applyTheme(readStoredTheme() === 'light' ? 'light' : 'dark');
})();

function setView(view) {
    currentView = view;
    document.getElementById('vt-matrix').className = 'view-toggle-option' + (view === 'matrix' ? ' active' : '');
    document.getElementById('vt-cards').className = 'view-toggle-option' + (view === 'cards' ? ' active' : '');
    renderDisplay();
}

// ─── Region Dropdown ───────────────────────────────────────────────────────────
function toggleRegionDropdown(e) { e.stopPropagation(); document.getElementById('region-dropdown-panel').classList.toggle('open'); }
function closeRegionDropdown() { document.getElementById('region-dropdown-panel').classList.remove('open'); }

function renderRegionDropdown() {
    const tagsContainer = document.getElementById('region-selected-tags');
    tagsContainer.innerHTML = '';
    if (selectedRegions.length === 0) {
        tagsContainer.innerHTML = '<span style="font-size:11px;color:#a0aec0;">No regions selected</span>';
    } else {
        selectedRegions.forEach(r => {
            const tag = document.createElement('span');
            tag.className = 'region-sel-tag';
            tag.innerHTML = r + ' <span class="remove-tag" onclick="removeRegion(\\'' + r + '\\')">&times;</span>';
            tagsContainer.appendChild(tag);
        });
    }
    const select = document.getElementById('region-add-select');
    select.innerHTML = '<option value="">+ Add a region...</option>';
    AWS_REGIONS.forEach(r => {
        if (!selectedRegions.includes(r)) {
            const opt = document.createElement('option');
            opt.value = r; opt.textContent = r;
            select.appendChild(opt);
        }
    });
}

function addRegionFromDropdown(region) {
    if (!region) return;
    if (selectedRegions.length >= 2) { showToast('Maximum 2 regions. Remove one first.'); document.getElementById('region-add-select').value = ''; return; }
    selectedRegions.push(region);
    document.getElementById('region-add-select').value = '';
    renderRegionDropdown();
    // Discover the newly added region's pane if the profile's other panes are
    // already loaded, so adding a region does not require pressing Discover again.
    fillMissingPanes();
}

function removeRegion(region) {
    selectedRegions = selectedRegions.filter(r => r !== region);
    // Drop the pane(s) for this region. Matching on the "|region" suffix rather
    // than the selected profile keeps this correct regardless of how panes are
    // keyed.
    Object.keys(resourceData).forEach(k => { if (k.endsWith('|' + region)) delete resourceData[k]; });
    Object.keys(setupNeeded).forEach(k => { if (k.endsWith('|' + region)) delete setupNeeded[k]; });
    // Rebuild the tag cache from the panes that remain. Leaving it populated
    // kept tag keys selectable in the filter that belonged only to the removed
    // region, so the filter offered values it could no longer match.
    rebuildTagCache();
    renderRegionDropdown();
    renderDisplay();
    updateStats();
    updateFetchButton();
}

/**
 * Discover any pane that does not exist yet, for the selected profile.
 *
 * Used when a region is added, so the new pane fills itself in for every
 * selected profile rather than staying blank until the next manual Discover.
 * Panes that reported NO_INDEX are left alone rather than re-hammering a region
 * that is not set up.
 *
 * Every pane fetches the account's global resources independently, so adding or
 * removing a region no longer has to move anything between panes.
 */
async function fillMissingPanes() {
    if (selectedProfiles.length === 0 || selectedRegions.length === 0) return;
    for (const profile of selectedProfiles) {
        for (const region of selectedRegions) {
            const key = paneKey(profile, region);
            if (resourceData[key] || setupNeeded[key]) continue;
            await discoverRegion(profile, region);
        }
    }
}

function rebuildTagCache() {
    availableTagsCache = {};
    Object.values(resourceData).forEach(data => {
        Object.entries(data.availableTags || {}).forEach(([key, values]) => {
            if (!availableTagsCache[key]) availableTagsCache[key] = new Set();
            values.forEach(v => availableTagsCache[key].add(v));
        });
    });
    // Drop any active filter whose key no longer exists in the cache.
    selectedTagFilters = selectedTagFilters.filter(f => availableTagsCache[f.key]);
}

// ─── Discovery ─────────────────────────────────────────────────────────────────
//
// Panes are keyed "profile|region" rather than region alone. Selection is capped
// at one profile today, so the profile prefix is effectively constant - but
// keeping it in the key means the data model does not have to change if
// per-profile selection ever returns, and it costs nothing.
function paneKey(profile, region) { return profile + '|' + region; }

async function discoverAllResources() {
    if (selectedProfiles.length === 0) {
        showToast('Select an AWS profile first');
        document.getElementById('settings-drawer').classList.add('open');
        document.getElementById('settings-overlay').classList.add('open');
        return;
    }
    if (selectedRegions.length === 0) { showToast('Please select at least one region'); return; }
    // Collapse the settings drawer once discovery begins
    document.getElementById('settings-drawer').classList.remove('open');
    document.getElementById('settings-overlay').classList.remove('open');
    // Show loading spinner in main content
    const container = document.getElementById('main-content');
    const hasExistingData = Object.keys(resourceData).some(r => resourceData[r]?.totalResources > 0);
    if (!hasExistingData) {
        const lines = Array.from({length: 12}, (_, i) =>
            '<div class="spinner-line" style="transform:rotate(' + (i * 30) + 'deg);animation-delay:' + (-1 + i * (1/12)).toFixed(3) + 's;"></div>'
        ).join('');
        container.innerHTML = '<div class="loading-spinner-container">' +
            '<div class="loading-spinner">' + lines + '</div>' +
            '<div class="loading-spinner-text">Discovering resources...</div>' +
            '</div>';
    }
    for (const profile of selectedProfiles) {
        for (const region of selectedRegions) {
            await discoverRegion(profile, region);
        }
    }
}

async function discoverRegion(profile, region) {
    const key = paneKey(profile, region);
    document.getElementById('loading-bar').classList.add('active');
    document.getElementById('fetch-btn').disabled = true;

    try {
        const response = await fetch('/api/discover-resources', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            // includeGlobal is left to the server default (true): every pane
            // shows the account's global resources, so IAM is present whichever
            // region you are looking at. updateStats() de-duplicates by ARN so
            // showing them in more than one pane does not inflate the total.
            body: JSON.stringify({ region, profile })
        });
        if (!response.ok) {
            const err = await response.json();
            if (handleProfileError(err)) return;
            if (err.code === 'NO_INDEX') { renderSetupNeeded(profile, region, err.error); return; }
            throw new Error(err.error || 'Server error');
        }
        resourceData[key] = await response.json();
        resourceData[key].profile = profile;
        resourceData[key].region = region;
        // A previous attempt may have flagged this pane as needing setup.
        delete setupNeeded[key];
        // Merge available tags from this pane into cache
        if (resourceData[key].availableTags) {
            Object.entries(resourceData[key].availableTags).forEach(([tkey, values]) => {
                if (!availableTagsCache[tkey]) availableTagsCache[tkey] = new Set();
                values.forEach(v => availableTagsCache[tkey].add(v));
            });
        }
        renderDisplay();
        updateStats();
        closeRegionDropdown();
    } catch (e) {
        showToast('Error: ' + e.message);
    } finally {
        document.getElementById('loading-bar').classList.remove('active');
        updateFetchButton();
    }
}

/**
 * Record that a region needs Resource Explorer set up, then re-render.
 *
 * This used to overwrite #main-content directly, which had two consequences
 * when more than one region was selected: a region that had already rendered
 * successfully was wiped from the DOM even though its data was still held in
 * resourceData, and conversely this message disappeared on the next
 * renderDisplay() (any tag-filter change) because renderDisplay only iterates
 * regions present in resourceData. State and DOM diverged in both directions.
 *
 * Storing the condition as state and letting renderDisplay draw it keeps the
 * two in step, and leaves other regions' panels intact.
 */
function renderSetupNeeded(profile, region, message) {
    const key = paneKey(profile, region);
    document.getElementById('loading-bar').classList.remove('active');
    setupNeeded[key] = { profile, region, message };
    delete resourceData[key];
    renderDisplay();
    updateStats();
    updateFetchButton();
}

/** Panel body for a region whose Resource Explorer index or view is missing. */
function setupNeededPanel(profile, region, message) {
    const panel = document.createElement('div');
    panel.className = 'region-panel';
    panel.innerHTML =
        // No account id here: this panel exists precisely because the region
        // returned nothing, so there is no ARN to read one from.
        '<div class="region-panel-header"><span>' + escHtml(region) +
        ' <span class="hdr-profile">(' + escHtml(profile) + ')</span></span>' +
        '<span class="resource-count">setup required</span></div>' +
        '<div class="region-panel-body"><div class="empty-main">' +
        '<div style="max-width:520px;text-align:center;">' +
        '<div style="font-size:44px;opacity:0.3;">&#128269;</div>' +
        '<h3 style="margin:12px 0 8px;font-size:16px;">No Resource Explorer index in ' + escHtml(region) + '</h3>' +
        '<p style="font-size:13px;line-height:1.6;">' + escHtml(message) + '</p>' +
        '<p style="font-size:12px;opacity:0.75;margin-top:12px;line-height:1.6;">' +
        'Each region you want to view needs its own Resource Explorer index. Create one for ' +
        escHtml(region) + ' in the console below (a few minutes to populate), or run ' +
        '<code style="padding:1px 5px;border-radius:3px;">aws resource-explorer-2 create-index --region ' +
        escHtml(region) + '</code> and then set a default view for that region. ' +
        'This index is needed for ' + escHtml(region) + '\u2019s own resources. Global resources ' +
        '(IAM, CloudFront, Route 53) are indexed only in us-east-1 and are pulled in from there ' +
        'automatically, so they are not affected by this.</p>' +
        '<a href="https://console.aws.amazon.com/resource-explorer/home?region=' + encodeURIComponent(region) +
        '#/settings" target="_blank" rel="noopener" ' +
        'style="display:inline-block;margin-top:16px;padding:8px 16px;background:#ff9900;color:#232f3e;' +
        'border-radius:4px;font-size:13px;font-weight:600;text-decoration:none;">Open Resource Explorer console</a>' +
        '</div></div></div>';
    return panel;
}

// ─── Rendering ─────────────────────────────────────────────────────────────────
function updateStats() {
    const incomplete = [];
    // Counted by unique ARN, not by summing panes.
    //
    // Global resources (IAM, CloudFront, Route 53) belong to the account rather
    // than to a region, so every region pane lists them - that is what makes IAM
    // visible whichever region you are looking at. Summing pane totals would then
    // count those hundreds of roles once per selected region and report a number
    // larger than the account actually holds, so the total is a set of ARNs.
    const seen = new Set();
    const seenFiltered = new Set();
    Object.entries(resourceData).forEach(([key, d]) => {
        Object.values(d.groups || {}).forEach(resources => {
            resources.forEach(r => seen.add(r.arn));
            filterByName(filterByTags(resources)).forEach(r => seenFiltered.add(r.arn));
        });
        if (d.partial) incomplete.push(key.replace('|', ' / ') + ': ' + d.partial);
    });
    const total = seen.size;
    const filtered = seenFiltered.size;
    const totalLabel = (selectedTagFilters.length > 0 || nameSearchFilter) ? filtered + ' / ' + total : total;
    document.getElementById('stat-total').textContent = totalLabel;
    document.getElementById('stats-bar').style.display = total > 0 ? 'flex' : 'none';

    // A count the user cannot trust is worse than a visible caveat. When the
    // server reports the inventory was incomplete, say so next to the number
    // instead of letting it read as the full account.
    const warn = document.getElementById('stat-partial');
    if (warn) {
        if (incomplete.length) {
            warn.textContent = 'incomplete';
            warn.title = incomplete.join('\\n');
            warn.style.display = 'inline';
        } else {
            warn.style.display = 'none';
        }
    }
}

function renderDisplay() {
    const container = document.getElementById('main-content');
    const hasData = Object.keys(resourceData).some(r => resourceData[r]?.totalResources > 0);
    const hasSetupNotice = Object.keys(setupNeeded).length > 0;

    // No profile selected is the app's resting state, not an error: say what to
    // do rather than implying discovery failed.
    if (selectedProfiles.length === 0) {
        container.innerHTML = '<div class="empty-main" id="empty-state"><div>' +
            '<div class="empty-icon">&#128273;</div>' +
            '<p>Select an AWS profile to begin</p>' +
            '<p class="empty-sub">Open the settings panel (top right) and choose a profile from your AWS CLI configuration.</p>' +
            '<p class="empty-sub">Credentials stay on the server; nothing is read until you pick a profile.</p>' +
            '</div></div>';
        return;
    }

    if (!hasData && !hasSetupNotice) {
        // A profile is selected by this point, and us-east-1 is selected by
        // default, so telling the operator to "select a region" is usually
        // instructing them to do something already done. Say which step is
        // actually outstanding, and name where the button is: it lives in the
        // settings panel footer, which closes itself once discovery starts, so
        // "click Discover Resources" alone points at something not on screen.
        const needsRegion = selectedRegions.length === 0;
        container.innerHTML = '<div class="empty-main" id="empty-state"><div>' +
            '<div class="empty-icon">&#9729;</div>' +
            '<p>' + (needsRegion ? 'Select a region to discover resources'
                                 : 'Ready to discover resources') + '</p>' +
            '<p class="empty-sub">' +
            (needsRegion
                ? 'Profile ' + escHtml(selectedProfiles[0]) + ' is selected. Pick a region from the Region menu in the top bar.'
                : 'Profile ' + escHtml(selectedProfiles[0]) + ', region ' +
                  escHtml(selectedRegions.join(' and ')) + '.') +
            '</p>' +
            '<p class="empty-sub">Inventory comes from AWS Resource Explorer, which needs an index in each region you view.</p>' +
            // Offer the action here rather than only describing where it lives.
            // Everything it needs is already chosen at this point, so making the
            // operator reopen the settings panel to press a button is a step with
            // no purpose. Opens the panel instead when a region is still missing,
            // since that choice has to be made there.
            '<button class="btn-fetch empty-action" onclick="' +
            (needsRegion ? 'toggleRegionDropdown(event)' : 'discoverAllResources()') + '">' +
            (needsRegion ? 'Choose a region' : 'Discover Resources') + '</button>' +
            '</div></div>';
        return;
    }

    container.innerHTML = '';
    // One panel per profile x region. Selection is capped at a single profile, so
    // in practice this is one panel per selected region; the loop stays because
    // panes are keyed by profile and the data model still separates them.
    selectedProfiles.forEach(profile => {
    selectedRegions.forEach(region => {
        const key = paneKey(profile, region);
        // A pane needing setup renders its own panel alongside any pane that
        // succeeded, instead of replacing the whole view.
        if (setupNeeded[key]) {
            const s = setupNeeded[key];
            container.appendChild(setupNeededPanel(s.profile, s.region, s.message));
            return;
        }
        if (!resourceData[key]) return;
        const data = resourceData[key];
        const panel = document.createElement('div');
        panel.className = 'region-panel';

        const header = document.createElement('div');
        header.className = 'region-panel-header';
        // profile comes from the server's validated profile list and region from
        // the fixed AWS_REGIONS list, so neither is account-controlled - but every
        // innerHTML site in this file escapes, so none of them reads as the
        // exception that was forgotten.
        // "<account id> - <region> (<profile>)". The account id is omitted only
        // when the region returned nothing to read one from, in which case the
        // region and profile still identify the panel rather than leaving a gap
        // where the account should be.
        header.innerHTML = '<span>' +
            (data.accountId ? '<span class="hdr-account">' + escHtml(data.accountId) + '</span> - ' : '') +
            escHtml(region) +
            ' <span class="hdr-profile">(' + escHtml(profile) + ')</span>' +
            '</span>' +
            '<span class="resource-count">' + (data.totalResources || 0) + ' resources</span>';
        panel.appendChild(header);

        const body = document.createElement('div');
        body.className = 'region-panel-body';

        // Render groups in order
        GROUP_ORDER.forEach(groupName => {
            const resources = (data.groups || {})[groupName];
            if (!resources || resources.length === 0) return;
            const filtered = filterByName(filterByTags(resources));
            if (filtered.length === 0) return;
            body.appendChild(renderGroup(groupName, filtered, region, profile));
        });

        // Any remaining groups not in ORDER
        Object.keys(data.groups || {}).forEach(groupName => {
            if (GROUP_ORDER.includes(groupName)) return;
            const resources = data.groups[groupName];
            if (!resources || resources.length === 0) return;
            const filtered = filterByName(filterByTags(resources));
            if (filtered.length === 0) return;
            body.appendChild(renderGroup(groupName, filtered, region, profile));
        });

        panel.appendChild(body);
        container.appendChild(panel);
    });
    });
}

function renderGroup(groupName, resources, region, profile) {
    const section = document.createElement('div');
    const groupHeaderAccentClass = 'group-header-accent-' + groupName.replace(/[^a-zA-Z]/g, '');
    const groupBodyAccentClass = 'group-body-accent-' + groupName.replace(/[^a-zA-Z]/g, '');
    section.className = 'group-section';

    // Collapse state is per profile+region+group so two panes do not share it.
    const groupKey = profile + ':' + region + ':' + groupName;
    const showAll = showAllStates[groupKey] || false;

    const header = document.createElement('div');
    header.className = 'group-header ' + groupHeaderAccentClass;

    const headerLeft = document.createElement('div');
    headerLeft.style.cssText = 'display:flex;align-items:center;gap:8px;flex:1;';
    headerLeft.innerHTML = '<span class="group-name">' + groupName + '</span><span class="group-count">' + resources.length + '</span>';

    const showAllLabel = document.createElement('label');
    showAllLabel.className = 'show-all-label';
    showAllLabel.onclick = (e) => e.stopPropagation();
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = showAll;
    checkbox.className = 'show-all-checkbox';
    checkbox.onclick = (e) => e.stopPropagation();
    checkbox.onchange = (e) => {
        showAllStates[groupKey] = e.target.checked;
        renderDisplay();
    };
    showAllLabel.appendChild(checkbox);
    showAllLabel.appendChild(document.createTextNode(' Show All Resource types'));

    const toggle = document.createElement('span');
    toggle.className = 'group-toggle';
    toggle.innerHTML = '&#9660;';

    header.appendChild(headerLeft);
    if (groupName !== 'Other') {
        header.appendChild(showAllLabel);
    }
    header.appendChild(toggle);
    header.onclick = (e) => {
        if (e.target.closest('.show-all-label')) return;
        section.classList.toggle('collapsed');
    };
    section.appendChild(header);

    const body = document.createElement('div');
    body.className = 'group-body ' + groupBodyAccentClass;

    // Sub-group resources by resourceType
    const subTypes = {};
    resources.forEach(r => {
        const st = r.resourceType || 'unknown';
        if (!subTypes[st]) subTypes[st] = [];
        subTypes[st].push(r);
    });

    // Filter sub-types: if "Show All" is unchecked, only show primary types
    const primaryTypes = PRIMARY_RESOURCE_TYPES[groupName] || [];
    let sortedSubTypes = Object.keys(subTypes).sort((a, b) => getSubtypeLabel(a).localeCompare(getSubtypeLabel(b)));

    if (!showAll && primaryTypes.length > 0 && groupName !== 'Other') {
        sortedSubTypes = sortedSubTypes.filter(st => {
            const stLower = st.toLowerCase();
            return primaryTypes.some(pt => pt.toLowerCase() === stLower);
        });
    }

    sortedSubTypes.forEach(subType => {
        const items = subTypes[subType];
        const row = document.createElement('div');
        row.className = 'subtype-row';

        // Determine if scrolling is needed: >30 items or would take >3 lines
        // Each icon is ~46px wide (40px + 6px gap). Estimate available width ~600px => ~13 per line
        // 3 lines => ~39 items. Use 30 as the threshold.
        const needsScroll = items.length > 30;

        const label = document.createElement('div');
        label.className = 'subtype-label';
        label.textContent = getSubtypeLabel(subType);
        label.title = subType + ' (' + items.length + ')';
        const countEl = document.createElement('div');
        countEl.className = 'subtype-count';
        countEl.textContent = items.length;
        label.appendChild(countEl);
        row.appendChild(label);

        const content = document.createElement('div');
        content.className = 'subtype-content';
        if (needsScroll && currentView === 'matrix') content.classList.add('subtype-content-scrollable');
        const needsListScroll = items.length > 10;

        if (currentView === 'matrix') {
            const matrix = document.createElement('div');
            matrix.className = 'icon-matrix';
            items.forEach(r => {
                const item = document.createElement('div');
                item.className = 'icon-matrix-item';
                item.title = r.name + ' (' + r.resourceType + ')';
                item.onclick = (e) => showResourceDetail(e, r, region, profile);
                const iconSrc = r.icon && AWS_ICONS[r.icon] ? AWS_ICONS[r.icon] : null;
                // Truncate first, then escape: escaping first would let the
                // slice cut an entity in half (&amp; -> &am).
                if (iconSrc) {
                    item.innerHTML = '<img src="' + iconSrc + '" alt="' + escHtml(r.resourceType) + '"><span class="icon-label">' + escHtml(truncate(r.name, 8)) + '</span>';
                } else {
                    item.innerHTML = '<span style="font-size:9px;font-weight:600;color:#718096;">' + escHtml((r.service || '?').substring(0,3).toUpperCase()) + '</span><span class="icon-label">' + escHtml(truncate(r.name, 8)) + '</span>';
                }
                matrix.appendChild(item);
            });
            content.appendChild(matrix);
        } else {
            const grid = document.createElement('div');
            grid.className = 'card-grid';
            if (needsListScroll) grid.classList.add('subtype-content-list-scrollable');
            items.forEach(r => {
                const item = document.createElement('div');
                item.className = 'resource-card-item';
                item.onclick = (e) => showResourceDetail(e, r, region, profile);
                const iconSrc = r.icon && AWS_ICONS[r.icon] ? AWS_ICONS[r.icon] : null;
                const imgHtml = iconSrc ? '<img src="' + iconSrc + '" alt="">' : '<span style="width:20px;height:20px;display:flex;align-items:center;justify-content:center;font-size:8px;font-weight:700;color:#718096;background:#edf2f7;border-radius:3px;">' + escHtml((r.service||'?').substring(0,3).toUpperCase()) + '</span>';
                item.innerHTML = imgHtml + '<span class="rc-name">' + escHtml(r.name) + '</span><span class="rc-type">' + escHtml(r.resourceType) + '</span>';
                grid.appendChild(item);
            });
            content.appendChild(grid);
        }

        row.appendChild(content);
        body.appendChild(row);
    });

    // If no primary types matched and showAll is off, show a hint
    if (sortedSubTypes.length === 0 && !showAll) {
        const hint = document.createElement('div');
        hint.style.cssText = 'padding:8px;font-size:11px;color:#a0aec0;text-align:center;';
        hint.textContent = 'No primary resource types found. Check "Show All Resource types" to see all ' + resources.length + ' resources.';
        body.appendChild(hint);
    }

    section.appendChild(body);
    return section;
}

/** Convert a resourceType string like "ecs:service" to a friendly label */
function getSubtypeLabel(resourceType) {
    const labels = {
        'ec2:instance': 'Instances',
        'ec2:volume': 'Volumes',
        'ec2:vpc': 'VPCs',
        'ec2:subnet': 'Subnets',
        'ec2:security-group': 'Security Groups',
        'ec2:elastic-ip': 'Elastic IPs',
        'ec2:internet-gateway': 'Internet Gateways',
        'ec2:route-table': 'Route Tables',
        'ec2:natgateway': 'NAT Gateways',
        'ec2:launch-template': 'Launch Templates',
        'lambda:function': 'Functions',
        'autoscaling:autoScalingGroup': 'Auto Scaling Groups',
        'elasticbeanstalk:environment': 'Environments',
        'batch:job-queue': 'Job Queues',
        'ecs:cluster': 'Clusters',
        'ecs:service': 'Services',
        'ecs:task': 'Tasks',
        'ecs:task-definition': 'Task Definitions',
        'eks:cluster': 'Clusters',
        'ecr:repository': 'Repositories',
        'rds:db': 'DB Instances',
        'rds:cluster': 'Clusters',
        'dynamodb:table': 'Tables',
        'elasticache:cluster': 'Clusters',
        'opensearch:domain': 'Domains',
        's3:bucket': 'Buckets',
        'efs:file-system': 'File Systems',
        'elasticloadbalancing:loadbalancer': 'Load Balancers',
        'elasticloadbalancing:targetgroup': 'Target Groups',
        'cloudfront:distribution': 'Distributions',
        'apigateway:restapi': 'REST APIs',
        'apigateway:api': 'HTTP APIs',
        'route53:hostedzone': 'Hosted Zones',
        'sqs:queue': 'Queues',
        'sns:topic': 'Topics',
        'sns:subscription': 'Subscriptions',
        'events:rule': 'Rules',
        'kinesis:stream': 'Streams',
        'secretsmanager:secret': 'Secrets',
        'ssm:parameter': 'Parameters',
        'kms:key': 'Keys',
        'acm:certificate': 'Certificates',
        'states:stateMachine': 'State Machines',
        'codebuild:project': 'Projects',
        'codedeploy:application': 'Applications',
        'codedeploy:deploymentgroup': 'Deployment Groups',
        'codepipeline:pipeline': 'Pipelines',
        'cloudformation:stack': 'Stacks',
        'cloudformation:stackset': 'Stack Sets',
        'sagemaker:endpoint': 'Endpoints',
        'sagemaker:notebook-instance': 'Notebooks',
        'sagemaker:model': 'Models',
        'iam:role': 'Roles',
        'iam:policy': 'Policies',
        'iam:user': 'Users',
        'iam:group': 'Groups',
        'iam:instance-profile': 'Instance Profiles',
        'logs:log-group': 'Log Groups',
        'cloudtrail:trail': 'Trails',
        'cloudwatch:alarm': 'Alarms',
        'dynamodb:global-table': 'Global Tables',
        'ec2:vpc-endpoint': 'VPC Endpoints',
        'events:event-bus': 'Event Buses',
        'apigateway:websocket-api': 'WebSocket APIs',
        'appsync:graphqlapi': 'GraphQL APIs'
    };
    if (labels[resourceType]) return labels[resourceType];
    // Fallback: take the part after the colon and capitalize
    const parts = resourceType.split(':');
    const typePart = parts[parts.length - 1] || resourceType;
    return typePart.charAt(0).toUpperCase() + typePart.slice(1).replace(/-/g, ' ');
}

function truncate(str, max) { return str.length > max ? str.substring(0, max) + '..' : str; }

/**
 * Popup header markup. Extracted because it is rendered three times (loading,
 * loaded, error) and duplicated escaping is the kind of thing that drifts -
 * one copy losing escHtml would silently reopen the XSS hole.
 * imgTag is built from the AWS_ICONS allowlist, so it is already trusted.
 */
/**
 * The conventional "opens in a new window" mark: a frame with its top-right
 * corner open and an arrow leaving through it.
 *
 * Inline SVG rather than a glyph or a vendored file. stroke="currentColor" makes
 * it inherit .popup-link's colour and its hover state for free, so it stays
 * visually identical to the close button beside it without a second set of
 * colour rules - and it needs no round trip to /icons, which only serves the
 * vendored AWS service icons.
 */
const EXTERNAL_LINK_ICON =
    '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"' +
    ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"' +
    ' focusable="false">' +
    '<path d="M13 5H7a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-6"/>' +
    '<path d="M14 4h6v6"/>' +
    '<path d="M20 4l-8 8"/>' +
    '</svg>';

/**
 * Dependency graph icon: a simple sitemap/hierarchy icon.
 */
const DEP_GRAPH_ICON =
    '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"' +
    ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"' +
    ' focusable="false">' +
    '<rect x="9" y="2" width="6" height="4" rx="1"/>' +
    '<rect x="2" y="18" width="6" height="4" rx="1"/>' +
    '<rect x="16" y="18" width="6" height="4" rx="1"/>' +
    '<path d="M12 6v4"/>' +
    '<path d="M5 14v4"/>' +
    '<path d="M19 14v4"/>' +
    '<path d="M5 14h14"/>' +
    '<path d="M12 10v4"/>' +
    '</svg>';

/** Resource types that support dependency graph viewing. */
const DEP_ELIGIBLE_TYPES = new Set([
    'ec2:instance', 'lambda:function', 'ecs:cluster', 'eks:cluster',
    'rds:db', 'elasticache:cluster', 'opensearch:domain'
]);

function popupHeader(imgTag, name, consoleHref, resource, region, profile) {
    const rt = resource ? (resource.resourceType || '').toLowerCase() : '';
    const showDeps = DEP_ELIGIBLE_TYPES.has(rt);
    // Store current resource context for the dependency graph button
    if (showDeps && resource) {
        window._depResource = resource;
        window._depRegion = region;
        window._depProfile = profile;
    }
    return '<div class="popup-header">' + imgTag +
           '<span class="popup-title">' + escHtml(name) + '</span>' +
           (showDeps
               ? '<button class="popup-deps-btn"' +
                 ' title="View dependency graph"' +
                 ' aria-label="View dependency graph"' +
                 ' onclick="showDependencyGraph()">' +
                 DEP_GRAPH_ICON + '</button>'
               : '') +
           (consoleHref
               ? '<a class="popup-link" href="' + escHtml(consoleHref) + '"' +
                 ' target="_blank" rel="noopener noreferrer"' +
                 ' title="Open in the AWS console"' +
                 ' aria-label="Open in the AWS console">' + EXTERNAL_LINK_ICON + '</a>'
               : '') +
           '<span class="popup-close" onclick="hidePopup()">&times;</span></div>';
}

/**
 * Link to this resource in the AWS console.
 *
 * Uses the console's own ARN resolver rather than a per-service URL table. That
 * table would need an entry for every one of the ~90 resource types Resource
 * Explorer returns, would be wrong for any type added after it was written, and
 * would rot as service consoles are redesigned. The resolver is the same
 * mechanism the Resource Explorer console uses for "navigate directly to your
 * resources", so it tracks those changes for us.
 *
 * Measured against one real ARN per discovered type: the resolver deep-links the
 * large majority. Where it only reaches a service's console home, an entry in
 * CONSOLE_URL_OVERRIDES takes precedence - so the table carries the exceptions
 * rather than the whole surface.
 *
 * Note the resolver is not a documented API, which is the trade for not
 * maintaining ~90 URL patterns; if it ever stops redirecting, links degrade to an
 * AWS console page rather than breaking the popup.
 */
/**
 * Console URLs for the resource types AWS's ARN resolver does not deep-link,
 * keyed by resourceType and given the ARN plus the console host region.
 *
 * Only add an entry once the URL has been confirmed by opening it. A wrong deep
 * link is worse than the resolver's fallback, which at least lands on the right
 * service console - so a type staying absent from this table is a deliberate
 * "not verified yet", not an oversight.
 */
const CONSOLE_URL_OVERRIDES = {
    // The resolver returns /bedrock-agentcore/home with no gateway selected.
    'bedrock-agentcore:gateway': (arn, host) =>
        'https://' + host + '.console.aws.amazon.com/bedrock-agentcore/toolsAndGateways/' +
        encodeURIComponent(arnTail(arn))
};

/** Last path segment of an ARN, which for most services is the resource id. */
function arnTail(arn) {
    const s = String(arn);
    return s.slice(Math.max(s.lastIndexOf('/'), s.lastIndexOf(':')) + 1);
}

function consoleUrl(resource, paneRegion) {
    if (!resource || !resource.arn) return null;
    // Which console host to enter through. 'global' is not a region, so those go
    // through us-east-1 rather than whichever pane happens to be showing them -
    // the resolver lands on the global console page either way, but the pane's
    // region is not a property of the resource and should not leak into its link.
    let host;
    if (resource.region === 'global') host = GLOBAL_INDEX_REGION;
    else if (resource.region) host = resource.region;
    else host = (paneRegion && paneRegion !== 'global') ? paneRegion : GLOBAL_INDEX_REGION;

    const override = CONSOLE_URL_OVERRIDES[resource.resourceType];
    if (override) return override(resource.arn, host);

    return 'https://' + host + '.console.aws.amazon.com/go/view?arn=' +
           encodeURIComponent(resource.arn) + '&source=resourceExplorer';
}

/** One key/value row in the detail popup. Both sides are account-controlled. */
function popupRow(key, val, style) {
    return '<div class="popup-row"><span class="popup-key">' + escHtml(key) + '</span>' +
           '<span class="popup-val"' + (style ? ' style="' + style + '"' : '') + '>' +
           escHtml(val) + '</span></div>';
}

// ─── Detail Popup (on-demand fetch) ───────────────────────────────────────────
async function showResourceDetail(event, resource, region, profile) {
    event.stopPropagation();
    const popup = document.getElementById('detail-popup');
    const iconSrc = resource.icon && AWS_ICONS[resource.icon] ? AWS_ICONS[resource.icon] : '';
    const imgTag = iconSrc ? '<img src="' + iconSrc + '" alt="" style="width:24px;height:24px;">' : '';
    // Computed once: the header is rebuilt three times below (loading, loaded,
    // fallback) and the link must survive all three, not just the first paint.
    const consoleHref = consoleUrl(resource, region);

    popup.innerHTML = popupHeader(imgTag, resource.name, consoleHref, resource, region, profile) +
        '<div class="popup-loading">Loading details...</div>';
    positionPopup(event);
    popup.classList.add('visible');

    // Claim this popup. Two things went wrong without a token:
    //
    //  1. Click A then B. If A's response arrives last it overwrote the body
    //     while B's header was showing, so the popup attributed one resource's
    //     ARN and details to another. In an inventory tool that is a data
    //     integrity bug, not a cosmetic one.
    //  2. Close the popup mid-fetch. The resolving handler called
    //     repositionPopup(), which re-adds .visible, so a dismissed popup
    //     reopened on its own.
    //
    // Both are fixed by checking we are still the current request before
    // touching the DOM.
    const requestId = ++popupRequestId;
    const isStale = () => requestId !== popupRequestId || !popup.classList.contains('visible');

    // Fetch details on-demand
    try {
        const response = await fetch('/api/resource-details', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                // A global resource carries region 'global', which is not a
                // valid region for an API call. Send GLOBAL_INDEX_REGION rather
                // than the pane's region: globals can now be pulled into any
                // pane, and describing a CloudFront distribution or Route 53
                // zone against us-east-2 is not where those services live.
                region: (resource.region && resource.region !== 'global')
                    ? resource.region
                    : GLOBAL_INDEX_REGION,
                arn: resource.arn,
                resourceType: resource.resourceType,
                service: resource.service,
                lastReported: resource.lastReported,
                // Detail must be fetched with the same profile that discovered
                // the resource, or it would resolve against the wrong account.
                profile: profile
            })
        });
        if (!response.ok) {
            const err = await response.json();
            if (handleProfileError(err)) return;
            throw new Error(err.error || 'Server error');
        }
        const data = await response.json();
        if (data.error) throw new Error(data.error);
        if (isStale()) return;

        let detailHtml = popupHeader(imgTag, resource.name, consoleHref, resource, region, profile);
        const details = data.details || {};
        Object.entries(details).forEach(([key, val]) => {
            detailHtml += popupRow(key, (val === null || val === undefined || val === '') ? '-' : val);
        });
        popup.innerHTML = detailHtml;
        repositionPopup();
    } catch (e) {
        if (isStale()) return;
        let fallbackHtml = popupHeader(imgTag, resource.name, consoleHref, resource, region, profile);
        fallbackHtml += popupRow('ARN', resource.arn);
        fallbackHtml += popupRow('Type', resource.resourceType);
        fallbackHtml += popupRow('Region', resource.region || region);
        fallbackHtml += popupRow('Note', e.message, 'color:#e53e3e;');
        popup.innerHTML = fallbackHtml;
        repositionPopup();
    }
}

let lastPopupClickX = 0, lastPopupClickY = 0;

// Incremented on every detail request so a late response can tell it has been
// superseded. Declared with var-like hoisting semantics in mind: showResourceDetail
// runs only from a click handler, long after this module-level statement.
let popupRequestId = 0;

function positionPopup(event) {
    lastPopupClickX = event.clientX;
    lastPopupClickY = event.clientY;
    repositionPopup();
}

function repositionPopup() {
    const popup = document.getElementById('detail-popup');
    // Temporarily position off-screen to measure
    popup.style.left = '-9999px';
    popup.style.top = '-9999px';
    popup.classList.add('visible');

    const rect = popup.getBoundingClientRect();
    const popupWidth = Math.max(rect.width, 300);
    const popupHeight = Math.max(rect.height, 200);

    let x = lastPopupClickX + 12;
    let y = lastPopupClickY + 12;

    // If popup would overflow the right edge, position it to the left of the click
    if (x + popupWidth > window.innerWidth - 16) {
        x = lastPopupClickX - popupWidth - 12;
    }
    // If still off-screen on the left, clamp to left edge
    if (x < 8) x = 8;

    // If popup would overflow the bottom, move it up
    if (y + popupHeight > window.innerHeight - 16) {
        y = window.innerHeight - popupHeight - 16;
    }
    if (y < 8) y = 8;

    popup.style.left = x + 'px';
    popup.style.top = y + 'px';
}

function hidePopup() { document.getElementById('detail-popup').classList.remove('visible'); }

// ─── Dependency Graph ──────────────────────────────────────────────────────────

async function showDependencyGraph() {
    const resource = window._depResource;
    const region = window._depRegion;
    const profile = window._depProfile;
    if (!resource) return;

    const overlay = document.getElementById('dep-graph-overlay');
    const content = document.getElementById('dep-graph-content');
    const title = document.getElementById('dep-graph-title');

    title.textContent = 'Dependencies: ' + (resource.name || 'Resource');
    content.innerHTML = '<div class="dep-loading">Loading dependency graph...</div>';
    overlay.style.display = 'flex';

    try {
        const response = await fetch('/api/resource-dependencies', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                region: (resource.region && resource.region !== 'global')
                    ? resource.region
                    : GLOBAL_INDEX_REGION,
                arn: resource.arn,
                resourceType: resource.resourceType,
                service: resource.service,
                profile: profile
            })
        });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Server error');
        }
        const graph = await response.json();
        content.innerHTML = '<div class="dep-tree">' + renderDepTree(graph) + '</div>';
        // Attach double-click handler to open dependency in AWS Console
        content.addEventListener('dblclick', function(e) {
            const node = e.target.closest('.dep-node-link');
            if (node && node.dataset.url) {
                window.open(node.dataset.url, '_blank', 'noopener,noreferrer');
            }
        });
    } catch (e) {
        content.innerHTML = '<div class="dep-error">Failed to load dependencies: ' + escHtml(e.message) + '</div>';
    }
}

function renderDepTree(node) {
    if (!node) return '';
    let html = '<ul><li>';
    html += '<span class="dep-node' + (node.consoleUrl ? ' dep-node-link' : '') + '"';
    if (node.consoleUrl) html += ' data-url="' + escHtml(node.consoleUrl) + '"';
    html += '>';
    html += '<span class="dep-node-type">' + escHtml(node.type) + '</span>';
    html += '<span class="dep-node-name">' + escHtml(node.name) + '</span>';
    html += '</span>';
    if (node.children && node.children.length > 0) {
        html += '<ul>';
        for (const child of node.children) {
            html += renderDepNode(child);
        }
        html += '</ul>';
    }
    html += '</li></ul>';
    return html;
}

function renderDepNode(node) {
    let html = '<li>';
    html += '<span class="dep-node' + (node.consoleUrl ? ' dep-node-link' : '') + '"';
    if (node.consoleUrl) html += ' data-url="' + escHtml(node.consoleUrl) + '" title="Double-click to open in AWS Console"';
    html += '>';
    html += '<span class="dep-node-type">' + escHtml(node.type) + '</span>';
    html += '<span class="dep-node-name">' + escHtml(node.name) + '</span>';
    if (node.consoleUrl) html += '<span class="dep-node-link-hint">⧉</span>';
    html += '</span>';
    if (node.children && node.children.length > 0) {
        html += '<ul>';
        for (const child of node.children) {
            html += renderDepNode(child);
        }
        html += '</ul>';
    }
    html += '</li>';
    return html;
}

function closeDependencyGraph(event) {
    if (event && event.target !== event.currentTarget) return;
    document.getElementById('dep-graph-overlay').style.display = 'none';
}

// ─── Tag Filter ────────────────────────────────────────────────────────────────

function openTagDropdown(e) {
    e.stopPropagation();
    const panel = document.getElementById('tag-dropdown-panel');
    panel.classList.add('open');
    renderTagDropdown(document.getElementById('tag-search-input').value);
}

function closeTagDropdown() {
    document.getElementById('tag-dropdown-panel').classList.remove('open');
}

function onTagSearchInput(query) {
    const panel = document.getElementById('tag-dropdown-panel');
    if (!panel.classList.contains('open')) panel.classList.add('open');
    renderTagDropdown(query);
}

function renderTagDropdown(query) {
    const list = document.getElementById('tag-dropdown-list');
    const q = (query || '').toLowerCase().trim();

    // Build flat list of tag options: key=value pairs
    const options = [];
    Object.entries(availableTagsCache).forEach(([key, valuesSet]) => {
        const values = valuesSet instanceof Set ? [...valuesSet] : (Array.isArray(valuesSet) ? valuesSet : []);
        // Add key-only option
        options.push({ key, value: undefined, display: key + ' (any value)' });
        // Add key=value options
        values.forEach(v => {
            options.push({ key, value: v, display: key + ' = ' + v });
        });
    });

    // Filter by search query
    const filtered = q ? options.filter(o => o.display.toLowerCase().includes(q)) : options;

    // Check which are already selected
    const isSelected = (opt) => selectedTagFilters.some(f =>
        f.key === opt.key && f.value === opt.value
    );

    if (filtered.length === 0) {
        list.innerHTML = '<div class="tag-dropdown-empty">No matching tags</div>';
        return;
    }

    // Limit to 50 for performance
    const shown = filtered.slice(0, 50);
    list.innerHTML = '';
    shown.forEach(opt => {
        const item = document.createElement('div');
        item.className = 'tag-dropdown-item' + (isSelected(opt) ? ' selected' : '');
        if (opt.value !== undefined) {
            item.innerHTML = '<span class="tag-key">' + escHtml(opt.key) + '</span><span class="tag-val">= ' + escHtml(opt.value) + '</span>';
        } else {
            item.innerHTML = '<span class="tag-key">' + escHtml(opt.key) + '</span><span class="tag-val">(any value)</span>';
        }
        item.onclick = (e) => {
            e.stopPropagation();
            toggleTagFilter(opt);
        };
        list.appendChild(item);
    });
    if (filtered.length > 50) {
        const more = document.createElement('div');
        more.className = 'tag-dropdown-empty';
        more.textContent = '... ' + (filtered.length - 50) + ' more. Type to narrow.';
        list.appendChild(more);
    }
}

function toggleTagFilter(opt) {
    const idx = selectedTagFilters.findIndex(f => f.key === opt.key && f.value === opt.value);
    if (idx >= 0) {
        selectedTagFilters.splice(idx, 1);
    } else {
        selectedTagFilters.push({ key: opt.key, value: opt.value });
    }
    renderTagPills();
    renderTagDropdown(document.getElementById('tag-search-input').value);
    renderDisplay();
    updateStats();
}

function removeTagFilter(index) {
    selectedTagFilters.splice(index, 1);
    renderTagPills();
    renderDisplay();
    updateStats();
}

function renderTagPills() {
    const container = document.getElementById('tag-pills');
    container.innerHTML = '';
    selectedTagFilters.forEach((f, i) => {
        const pill = document.createElement('span');
        pill.className = 'tag-pill';
        const label = f.value !== undefined ? f.key + '=' + f.value : f.key + ' (any)';
        const textSpan = document.createElement('span');
        textSpan.className = 'tag-pill-text';
        textSpan.textContent = label;
        textSpan.title = label;
        pill.appendChild(textSpan);
        const removeBtn = document.createElement('span');
        removeBtn.className = 'tag-pill-remove';
        removeBtn.innerHTML = '&times;';
        removeBtn.onclick = function(e) {
            e.stopPropagation();
            e.preventDefault();
            removeTagFilter(i);
        };
        pill.appendChild(removeBtn);
        container.appendChild(pill);
    });
    // Add "Clear all" button when there are multiple filters
    if (selectedTagFilters.length > 1) {
        const clearBtn = document.createElement('span');
        clearBtn.className = 'tag-pill';
        clearBtn.style.cssText = 'background:#fed7d7;border-color:#feb2b2;color:#c53030;cursor:pointer;';
        clearBtn.textContent = 'Clear all';
        clearBtn.onclick = function(e) {
            e.stopPropagation();
            e.preventDefault();
            clearAllTagFilters();
        };
        container.appendChild(clearBtn);
    }
}

function clearAllTagFilters() {
    selectedTagFilters = [];
    renderTagPills();
    renderDisplay();
    updateStats();
}

function filterByTags(resources) {
    if (selectedTagFilters.length === 0) return resources;
    return resources.filter(r => {
        const tags = r.tags || [];
        return selectedTagFilters.every(filter => {
            return tags.some(t => {
                if (filter.value !== undefined) {
                    return t.key === filter.key && t.value === filter.value;
                }
                return t.key === filter.key;
            });
        });
    });
}

function filterByName(resources) {
    if (!nameSearchFilter) return resources;
    const q = nameSearchFilter.toLowerCase();
    return resources.filter(r => (r.name || '').toLowerCase().includes(q));
}

function onNameSearchInput(value) {
    nameSearchFilter = value.trim();
    renderDisplay();
    updateStats();
}

/**
 * Escape text for interpolation into HTML, including both quote characters so
 * it is safe in an attribute value as well as in element content.
 *
 * Everything this page renders is account-controlled: resource names and ARNs
 * come from Resource Explorer, and describe-API fields like an IAM role's
 * Description, a KMS key's Description, an SNS DisplayName, and any Name tag
 * value are free-form strings that permit < and >. Anyone able to create or tag
 * a resource in a viewed account would otherwise be able to store script that
 * runs on this page - and this page can call /api/*, which reaches every AWS
 * profile configured on this machine. Escape at every interpolation site; there
 * is no data on this page trusted enough to skip it.
 */
function escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ─── Settings ──────────────────────────────────────────────────────────────────
function toggleSettings() {
    document.getElementById('settings-drawer').classList.toggle('open');
    document.getElementById('settings-overlay').classList.toggle('open');
}

function showToast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('visible');
    setTimeout(() => t.classList.remove('visible'), 4000);
}

// ─── Export & Compare ───────────────────────────────────────────────────────────

function exportResources() {
    const allResources = [];
    Object.entries(resourceData).forEach(([key, data]) => {
        if (!data || !data.groups) return;
        Object.entries(data.groups).forEach(([group, items]) => {
            items.forEach(r => {
                allResources.push({
                    arn: r.arn || '',
                    name: r.name || '',
                    type: r.resourceType || '',
                    service: r.service || '',
                    region: data.region || '',
                    profile: data.profile || '',
                    group: group,
                    tags: r.tags || []
                });
            });
        });
    });
    const payload = {
        exportedAt: new Date().toISOString(),
        totalResources: allResources.length,
        resources: allResources
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'aws-resources-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Resources exported to JSON');
}

function openCompareModal() {
    document.getElementById('compare-overlay').classList.add('visible');
    document.getElementById('compare-results').innerHTML = '';
    document.getElementById('compare-file-a').value = '';
    document.getElementById('compare-file-b').value = '';
}

function closeCompareModal(e) {
    if (e && e.target !== e.currentTarget) return;
    document.getElementById('compare-overlay').classList.remove('visible');
}

function runCompare() {
    const fileA = document.getElementById('compare-file-a').files[0];
    const fileB = document.getElementById('compare-file-b').files[0];
    if (!fileA || !fileB) { showToast('Please select both JSON files'); return; }
    Promise.all([readJsonFile(fileA), readJsonFile(fileB)]).then(([a, b]) => {
        const result = diffSnapshots(a, b);
        renderCompareResults(result);
    }).catch(err => {
        showToast('Error reading files: ' + err.message);
    });
}

function readJsonFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => { try { resolve(JSON.parse(reader.result)); } catch(e) { reject(e); } };
        reader.onerror = () => reject(new Error('Failed to read file'));
        reader.readAsText(file);
    });
}

function diffSnapshots(older, newer) {
    const olderMap = new Map();
    const newerMap = new Map();
    (older.resources || []).forEach(r => olderMap.set(r.arn, r));
    (newer.resources || []).forEach(r => newerMap.set(r.arn, r));

    const added = [];
    const removed = [];
    const modified = [];

    newerMap.forEach((r, arn) => {
        if (!olderMap.has(arn)) {
            added.push(r);
        } else {
            const old = olderMap.get(arn);
            if (JSON.stringify(old) !== JSON.stringify(r)) {
                modified.push({ arn, name: r.name || old.name, type: r.type || old.type });
            }
        }
    });
    olderMap.forEach((r, arn) => {
        if (!newerMap.has(arn)) removed.push(r);
    });

    return { added, removed, modified };
}

function renderCompareResults({ added, removed, modified }) {
    const container = document.getElementById('compare-results');
    let html = '';

    html += '<h4>Modified Resources</h4>';
    if (modified.length > 0) {
        html += '<ul>' + modified.map(r => '<li>' + escHtml(r.name || r.arn) + ' <span style="color:#718096;">[' + escHtml(r.type) + ']</span></li>').join('') + '</ul>';
    } else {
        html += '<p class="diff-none">-</p>';
    }

    html += '<h4>Newly Added Resources</h4>';
    if (added.length > 0) {
        html += '<ul>' + added.map(r => '<li>' + escHtml(r.name || r.arn) + ' <span style="color:#718096;">[' + escHtml(r.type) + ']</span></li>').join('') + '</ul>';
    } else {
        html += '<p class="diff-none">-</p>';
    }

    html += '<h4>Removed Resources</h4>';
    if (removed.length > 0) {
        html += '<ul>' + removed.map(r => '<li>' + escHtml(r.name || r.arn) + ' <span style="color:#718096;">[' + escHtml(r.type) + ']</span></li>').join('') + '</ul>';
    } else {
        html += '<p class="diff-none">-</p>';
    }

    container.innerHTML = html;
}

function escHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

init();
</script>
</body>
</html>`;
