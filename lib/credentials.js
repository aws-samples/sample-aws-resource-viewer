'use strict';

/**
 * Resolve AWS credentials for a named AWS CLI profile.
 *
 * The app runs as a local tool using the operator's own AWS CLI configuration,
 * so credentials come from the same place the `aws` command gets them. Whatever
 * already works on the command line works here: SSO sessions, credential_process
 * helpers, static keys, and role chaining via source_profile.
 *
 * SECURITY NOTES
 *
 * There is no application-level authentication in this model. The tool acts with
 * the full permissions of whichever profile is selected, and it can see every
 * profile on the machine - so it is bound to loopback and must stay there. See
 * the host check in server-v1.js.
 *
 * Resolved credentials are cached in this process's memory only. They are never
 * written to disk and never serialised into a response: the browser receives
 * profile NAMES and resource data, never a key, secret, session token, or SSO
 * token.
 */

const { fromNodeProviderChain } = require('@aws-sdk/credential-providers');

// Re-resolve slightly before expiry so a request never starts with credentials
// that lapse mid-flight.
const EXPIRY_SKEW_MS = 5 * 60 * 1000;

/**
 * profileName -> { accessKeyId, secretAccessKey, sessionToken, expiration }
 *
 * Only credentials that actually expire are cached. Static keys are not, and
 * that is deliberate rather than an oversight:
 *
 *  - Resolving them is two small file reads, so caching buys almost nothing. The
 *    expensive cases - SSO, credential_process, role chaining - all return a
 *    real expiration and so are cached.
 *  - It makes freshness absolute. Rotating or fixing keys in ~/.aws takes effect
 *    on the very next request, with no window in which the tool keeps failing
 *    with credentials the operator has already replaced.
 *
 * An earlier version gave static keys a synthetic five-minute expiry, but the
 * TTL and EXPIRY_SKEW_MS were both five minutes, so `expiration - now > skew`
 * was never true and they were never served from cache anyway. This states the
 * real behaviour instead of implying one that never happened.
 */
const cache = new Map();

/**
 * Resolve credentials for `profile`, cached until they near expiry.
 *
 * Returns a plain credentials object rather than a provider function: each
 * detail fetcher constructs its own SDK client, and a shared resolved object
 * avoids re-running the provider chain (which for an SSO or credential_process
 * profile can mean disk reads or spawning a helper) once per client.
 *
 * @param {string} profile  A profile name already validated by
 *                          lib/profiles.js#isKnownProfile. Never pass an
 *                          unvalidated caller-supplied string.
 * @param {string} [region] Region for any STS call the chain needs (role
 *                          chaining, SSO). Not the region resources are queried
 *                          in - that is per-request.
 */
async function resolveCredentials(profile, region) {
    const cached = cache.get(profile);
    if (cached && cached.expiration - Date.now() > EXPIRY_SKEW_MS) {
        return {
            accessKeyId: cached.accessKeyId,
            secretAccessKey: cached.secretAccessKey,
            sessionToken: cached.sessionToken
        };
    }

    // fromNodeProviderChain honours the profile's own configuration, so one call
    // covers every credential style the AWS CLI supports. Passing the profile
    // explicitly (rather than setting AWS_PROFILE) keeps concurrent requests for
    // different profiles from interfering with each other.
    // ignoreCache is essential, not an optimisation knob. The SDK memoises the
    // parsed contents of ~/.aws/config and ~/.aws/credentials for the lifetime
    // of the process and never invalidates them, so without this a new provider
    // still hands back the file as it looked at first read. An operator who
    // refreshes expired credentials would keep getting the dead ones until the
    // process restarted - and the cache above cannot help, because the staleness
    // is below it. With this set, our own cache is the only one, and clearing it
    // genuinely re-reads the files.
    const provider = fromNodeProviderChain({
        profile,
        ignoreCache: true,
        ...(region ? { clientConfig: { region } } : {})
    });

    let creds;
    try {
        creds = await provider();
    } catch (err) {
        throw describeProfileFailure(err, profile);
    }

    if (!creds || !creds.accessKeyId) {
        throw Object.assign(
            new Error('Profile "' + profile + '" did not yield credentials. ' +
                      'Check it with: aws sts get-caller-identity --profile ' + profile),
            { code: 'PROFILE_UNUSABLE', profile }
        );
    }

    if (creds.expiration) {
        cache.set(profile, {
            accessKeyId: creds.accessKeyId,
            secretAccessKey: creds.secretAccessKey,
            sessionToken: creds.sessionToken,
            expiration: new Date(creds.expiration).getTime()
        });
    }

    return {
        accessKeyId: creds.accessKeyId,
        secretAccessKey: creds.secretAccessKey,
        sessionToken: creds.sessionToken
    };
}

/**
 * Profile credential failures are usually a stale SSO login or a misconfigured
 * profile, and the SDK's messages rarely name the fix. Translate the common ones
 * into the command that resolves them.
 */
function describeProfileFailure(err, profile) {
    const name = err.name || '';
    const msg = err.message || String(err);

    if (/sso/i.test(msg) && /(expired|invalid|refresh|token)/i.test(msg)) {
        return wrap(err, 'The SSO session for profile "' + profile + '" has expired.\n' +
                         '  Refresh it with:  aws sso login --profile ' + profile,
                    'PROFILE_REAUTH', profile);
    }
    if (/ExpiredToken|token.*expired/i.test(msg) || name === 'ExpiredTokenException') {
        return wrap(err, 'Credentials for profile "' + profile + '" have expired.\n' +
                         '  Refresh them (e.g. aws sso login --profile ' + profile + ') and try again.',
                    'PROFILE_REAUTH', profile);
    }
    if (/credential_process|Process returned|ENOENT/i.test(msg)) {
        return wrap(err, 'The credential_process for profile "' + profile + '" failed to run.\n' +
                         '  Verify the command in ~/.aws/config resolves and is executable.',
                    'PROFILE_UNUSABLE', profile);
    }
    if (/Could not find|not found|does not exist/i.test(msg)) {
        return wrap(err, 'Profile "' + profile + '" could not be resolved from ~/.aws/config ' +
                         'or ~/.aws/credentials.', 'PROFILE_UNUSABLE', profile);
    }
    return wrap(err, 'Could not resolve credentials for profile "' + profile + '": ' + msg,
                'PROFILE_UNUSABLE', profile);
}

function wrap(original, message, code, profile) {
    const e = new Error(message);
    e.cause = original;
    e.code = code;
    e.profile = profile;
    return e;
}

/**
 * Forget the cached credentials for one profile.
 *
 * Needed because resolution succeeding does not mean the credentials WORK. A
 * profile resolves fine and is cached, then AWS rejects it at call time with
 * UnrecognizedClientException or ExpiredToken - rotated, deactivated, or lapsed
 * since it was cached. Without eviction the cache keeps serving those dead
 * credentials until their nominal expiry, so an operator who has already fixed
 * the problem still sees failures and reasonably concludes the fix did not work.
 *
 * Callers evict on an auth failure, so the next request re-resolves. Harmless
 * for a profile that was never cached.
 */
function invalidateCredentials(profile) {
    cache.delete(profile);
}

module.exports = { resolveCredentials, invalidateCredentials };
