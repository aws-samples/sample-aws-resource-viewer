'use strict';

/**
 * Supplemental resource sources: a scoped, reversible way to show resource
 * types that AWS Resource Explorer does not index yet.
 *
 * Resource Explorer is the app's only discovery mechanism - one query covers
 * everything it indexes. Not every service is covered on day one, though
 * (e.g. Bedrock AgentCore's Gateway, Memory, and Identity resources are not
 * indexed as of this writing, only Runtime is). Rather than build a second,
 * parallel discovery/render/detail path for those gaps, each source here
 * returns items shaped EXACTLY like a Resource Explorer item
 * (arn/name/resourceType/service/lastReported), so they merge into the same
 * array and flow through the existing classify/icon/tag/detail pipeline
 * unmodified. Nothing downstream needs to know where an item came from.
 *
 * Onboarding a new one:
 *   1. Copy an existing file in this directory (e.g. bedrock-agentcore-gateway.js).
 *   2. Implement list(config) and, optionally, detail(config, item).
 *   3. List the IAM actions it calls in its iamActions field, so operators can
 *      tell whether the profile they select is permitted to call them.
 *   4. Done - no other file needs to change.
 *
 * Retiring one once Resource Explorer adds native support:
 *   Delete the file (or set `enabled: false` in it). Nothing else references
 *   it by name.
 */

const fs = require('fs');
const path = require('path');

let cachedSources = null;

/**
 * Load every supplemental source module in this directory (excluding this
 * index file itself). Cached after first load; sources are static code, not
 * runtime state.
 */
function loadSources() {
    if (cachedSources) return cachedSources;

    const dir = __dirname;
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.js') && f !== 'index.js');

    const sources = [];
    for (const file of files) {
        const mod = require(path.join(dir, file));
        if (mod.enabled === false) continue;

        const missing = ['service', 'resourceType', 'group', 'icon', 'list']
            .filter(key => !mod[key]);
        if (missing.length) {
            console.warn('supplemental source ' + file + ' is missing required field(s): ' +
                         missing.join(', ') + ' - skipping it.');
            continue;
        }
        sources.push(Object.assign({ _file: file }, mod));
    }
    cachedSources = sources;
    return sources;
}

/**
 * `config` is the AWS SDK client config ({ region, credentials }) plus
 * `accountId` for the account being inventoried. That last field matters: some
 * services' List* responses omit the resource ARN, so the source has to build
 * one, and it must use the real account rather than a placeholder - a wildcard
 * or hardcoded account propagates straight into what the UI reports.
 *
 * Run every enabled source's list(config) and return a flat array of items in
 * AWS Resource Explorer's RAW shape (Arn, Service, ResourceType, Region,
 * LastReportedAt, Properties) - the same shape ListResources returns. That
 * lets the caller concat this straight onto its own ListResources output
 * *before* the existing dedup/classify/icon/tag loop runs, so supplemental
 * items get every bit of that logic for free with zero special-casing.
 *
 * One source failing (e.g. a permission not yet added, or a transient API
 * error) never blocks Resource Explorer's own results or any other source -
 * it's logged and skipped.
 */
async function collectAll(config) {
    const sources = loadSources();
    const results = await Promise.allSettled(
        sources.map(src => src.list(config).then(items => ({ src, items })))
    );

    const out = [];
    for (let i = 0; i < results.length; i++) {
        const r = results[i];
        if (r.status === 'fulfilled') {
            for (const item of r.value.items) {
                out.push({
                    Arn: item.arn,
                    Service: item.service || r.value.src.service,
                    ResourceType: item.resourceType || r.value.src.resourceType,
                    Region: item.region || config.region,
                    LastReportedAt: item.lastReported,
                    Properties: []
                });
            }
        } else {
            console.warn('supplemental source ' + sources[i]._file + ' failed: ' +
                         (r.reason && r.reason.message || r.reason));
        }
    }
    return out;
}

/** Find the source that declared a given resourceType, if any. */
function findSourceForType(resourceType) {
    const rt = (resourceType || '').toLowerCase();
    return loadSources().find(s => s.resourceType.toLowerCase() === rt) || null;
}

module.exports = { loadSources, collectAll, findSourceForType };
