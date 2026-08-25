'use strict';

/**
 * Discover the AWS CLI profiles configured on this machine.
 *
 * The app uses the operator's own AWS CLI credentials rather than its own
 * identity provider, so the profile list is the equivalent of a sign-in menu:
 * the user picks which profile(s) to view, and the server resolves credentials
 * for those profiles through the standard AWS credential chain.
 *
 * SECURITY: this module returns profile NAMES and non-sensitive metadata only -
 * never an access key, secret, session token, or SSO token. Credentials are
 * resolved server-side in lib/credentials.js and never serialised to the
 * browser. Keep it that way: the profile list is served over HTTP to the local
 * page, and leaking secrets into it would put long-lived keys in a response
 * body and in any browser cache or devtools log.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

/**
 * Section names that appear in ~/.aws/config but are NOT profiles. Treating
 * these as profiles would offer the user entries that cannot resolve
 * credentials (an sso-session is referenced BY a profile, not used directly).
 */
const NON_PROFILE_SECTIONS = new Set(['sso-session', 'services', 'preview', 'plugins']);

function configPath() {
    return process.env.AWS_CONFIG_FILE || path.join(os.homedir(), '.aws', 'config');
}

function credentialsPath() {
    return process.env.AWS_SHARED_CREDENTIALS_FILE || path.join(os.homedir(), '.aws', 'credentials');
}

/**
 * Minimal INI parse of an AWS config file.
 *
 * Returns { sectionName: { key: value } } for TOP-LEVEL keys only. Indented
 * lines are nested sub-properties (e.g. the `s3 = ` block) and are skipped:
 * nothing here needs them, and folding them into the parent would produce
 * misleading keys.
 */
function parseIni(text) {
    const out = {};
    let section = null;

    for (const rawLine of text.split(/\r?\n/)) {
        // Strip comments. AWS accepts both # and ;.
        const line = rawLine.replace(/\s+[#;].*$/, '').trimEnd();
        if (!line.trim()) continue;

        const sectionMatch = line.trim().match(/^\[(.+)\]$/);
        if (sectionMatch) {
            section = sectionMatch[1].trim();
            if (!out[section]) out[section] = {};
            continue;
        }

        // Indented => sub-property of the previous key, not a profile setting.
        if (/^\s/.test(rawLine)) continue;
        if (!section) continue;

        const eq = line.indexOf('=');
        if (eq === -1) continue;
        const key = line.slice(0, eq).trim();
        const value = line.slice(eq + 1).trim();
        if (key) out[section][key] = value;
    }
    return out;
}

function readIniFile(file) {
    try {
        return parseIni(fs.readFileSync(file, 'utf8'));
    } catch (err) {
        // Missing file is normal (a machine may have only one of the two).
        if (err.code !== 'ENOENT') {
            console.warn('Could not read ' + file + ': ' + err.message);
        }
        return {};
    }
}

/**
 * Classify how a profile obtains credentials. Metadata only - useful in the UI
 * so a user can tell an SSO profile (which may need `aws sso login`) from a
 * static-key one, without exposing anything sensitive.
 */
function credentialType(settings) {
    if (settings.sso_session || settings.sso_start_url) return 'sso';
    if (settings.credential_process) return 'process';
    if (settings.web_identity_token_file) return 'web-identity';
    if (settings.role_arn) return 'role';
    if (settings.aws_access_key_id) return 'static';
    return 'unknown';
}

/**
 * List available profiles, merging ~/.aws/config and ~/.aws/credentials.
 *
 * Section naming differs between the two files, which is the usual source of
 * bugs here:
 *   ~/.aws/config       [profile foo]  and  [default]
 *   ~/.aws/credentials  [foo]          and  [default]
 *
 * Returns [{ name, region, source, type }] sorted with `default` first, then
 * alphabetically.
 */
function listProfiles() {
    const cfg = readIniFile(configPath());
    const creds = readIniFile(credentialsPath());
    const merged = new Map();

    const upsert = (name, settings, source) => {
        const existing = merged.get(name);
        if (existing) {
            // A profile can appear in both files; config supplies region, and
            // either can supply credentials. Merge rather than overwrite.
            existing.settings = Object.assign({}, existing.settings, settings);
            if (!existing.sources.includes(source)) existing.sources.push(source);
            return;
        }
        merged.set(name, { settings: Object.assign({}, settings), sources: [source] });
    };

    for (const [section, settings] of Object.entries(cfg)) {
        const prefix = section.split(/\s+/)[0];
        if (NON_PROFILE_SECTIONS.has(prefix)) continue;
        if (section === 'default') {
            upsert('default', settings, 'config');
        } else if (prefix === 'profile') {
            const name = section.slice('profile'.length).trim();
            if (name) upsert(name, settings, 'config');
        }
        // A bare [foo] in config is not a valid profile per AWS docs; ignore it
        // rather than offering something the SDK will not resolve.
    }

    for (const [section, settings] of Object.entries(creds)) {
        const prefix = section.split(/\s+/)[0];
        if (NON_PROFILE_SECTIONS.has(prefix)) continue;
        // In the credentials file the section name IS the profile name.
        upsert(section, settings, 'credentials');
    }

    const profiles = [...merged.entries()].map(([name, { settings, sources }]) => ({
        name,
        region: settings.region || null,
        type: credentialType(settings),
        source: sources.join('+')
    }));

    profiles.sort((a, b) => {
        if (a.name === 'default') return -1;
        if (b.name === 'default') return 1;
        return a.name.localeCompare(b.name);
    });

    return profiles;
}

/**
 * True if `name` is a profile that actually exists on this machine.
 *
 * Every request carries a caller-supplied profile name, and that name is fed to
 * the AWS SDK. Validating against the real list keeps an arbitrary string out
 * of credential resolution and file paths.
 */
function isKnownProfile(name) {
    if (typeof name !== 'string' || !name) return false;
    return listProfiles().some(p => p.name === name);
}

module.exports = { listProfiles, isKnownProfile, configPath, credentialsPath };
