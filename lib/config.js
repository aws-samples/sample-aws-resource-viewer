'use strict';

/**
 * Environment configuration, validated once at startup.
 *
 * This app is a LOCAL tool. It uses the operator's own AWS CLI profiles rather
 * than its own identity provider, so there is nothing to configure for
 * authentication - the profile list comes from ~/.aws/config and
 * ~/.aws/credentials at runtime, and the user picks which profile to use in the
 * UI. Consequently nothing here is required; every value has a sane default.
 *
 * The one thing this module DOES enforce is the loopback bind. Because there is
 * no application-level authentication, anyone who can reach the port can use
 * every AWS profile on this machine - including production ones. Binding to a
 * routable interface would expose that to the network, so a non-loopback HOST
 * is refused unless the operator explicitly acknowledges it via
 * ALLOW_NON_LOOPBACK=true. That flag exists for someone who genuinely fronts
 * this with their own auth; it is not a convenience switch.
 */

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '0:0:0:0:0:0:0:1']);

function isLoopback(host) {
    if (!host) return false;
    const h = String(host).trim().toLowerCase().replace(/^\[|\]$/g, '');
    if (LOOPBACK_HOSTS.has(h)) return true;
    // Any 127.0.0.0/8 address is loopback.
    return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

function loadConfig(env = process.env) {
    const port = Number(env.PORT || 3000);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error('PORT must be an integer between 1 and 65535, got: ' + env.PORT);
    }

    const host = env.HOST || '127.0.0.1';
    const allowNonLoopback = env.ALLOW_NON_LOOPBACK === 'true';

    if (!isLoopback(host) && !allowNonLoopback) {
        throw new Error(
            'Refusing to bind to "' + host + '".\n\n' +
            'This tool has no authentication of its own: it exposes every AWS profile\n' +
            'configured on this machine to anyone who can reach the port. It is meant to\n' +
            'run on loopback only.\n\n' +
            'Either set HOST=127.0.0.1 (default), or - if you are deliberately putting\n' +
            'your own authentication in front of it - set ALLOW_NON_LOOPBACK=true to\n' +
            'acknowledge the risk.'
        );
    }

    // Region used for the STS/SSO calls the credential chain may need, and as
    // the default region offered in the UI. Resource queries use the regions
    // picked per request, not this.
    const region = env.AWS_REGION || env.AWS_DEFAULT_REGION || 'us-east-1';

    return Object.freeze({
        port,
        host,
        region,
        // Reported so the startup banner can warn loudly when the bind is
        // reachable from the network. allowNonLoopback itself is not exposed:
        // it only gates the throw above, and nothing downstream needs it.
        isLoopbackBind: isLoopback(host)
    });
}

module.exports = { loadConfig, isLoopback };
