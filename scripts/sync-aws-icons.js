#!/usr/bin/env node
/**
 * Sync the official AWS Architecture Icons into public/icons/.
 *
 * Icons are vendored at build time rather than hotlinked at runtime, so the
 * browser only ever talks to this app's own origin. That keeps a Content
 * Security Policy of `img-src 'self'` viable, removes a third-party
 * availability and privacy dependency, and makes every icon change show up as
 * a reviewable diff instead of mutating silently in production.
 *
 * AWS publishes no icon CDN or API. The icons ship as a dated ZIP linked from
 * https://aws.amazon.com/architecture/icons/ and revised a few times a year,
 * so a sync step matches the real cadence.
 *
 * Usage:
 *   node scripts/sync-aws-icons.js            # use pinned release from lockfile
 *   node scripts/sync-aws-icons.js --latest   # discover and pin newest release
 *   node scripts/sync-aws-icons.js --check    # verify local files match lockfile
 *   node scripts/sync-aws-icons.js --url=URL  # pin an explicit package URL
 *   node scripts/sync-aws-icons.js --zip=PATH # use an already-downloaded ZIP
 *
 * Runs on Windows, macOS and Linux with nothing but Node >= 18. It previously
 * shelled out to the `unzip` binary, which does not exist on Windows and is
 * absent from minimal Linux images, so the ZIP is read here with a small
 * reader built on Node's own zlib. Still zero npm dependencies.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

const ICONS_PAGE = 'https://aws.amazon.com/architecture/icons/';
const ZIP_LINK_RE = /https?:\/\/[^"'\s]*architecture-icon-release\/Icon-package_[^"'\s]*\.zip/;

const ROOT = path.join(__dirname, '..');
const MANIFEST_PATH = path.join(__dirname, 'aws-icons.manifest.json');
const SERVER_PATH = path.join(ROOT, 'server-v1.js');
const OUT_DIR = path.join(ROOT, 'public', 'icons');
// Kept outside public/ so the static mount only ever exposes .svg files.
const LOCK_PATH = path.join(__dirname, 'aws-icons.lock.json');

const args = process.argv.slice(2);
const flag = name => args.some(a => a === '--' + name);
const value = name => {
    const hit = args.find(a => a.startsWith('--' + name + '='));
    return hit ? hit.slice(name.length + 3) : null;
};

function fail(msg, detail) {
    console.error('\nERROR: ' + msg);
    if (detail) console.error(detail);
    process.exit(1);
}

function sha256(buf) {
    return crypto.createHash('sha256').update(buf).digest('hex');
}

// ─── Minimal ZIP reader ───────────────────────────────────────────────────────
// Enough of PKZIP to list entries and extract them, and no more. Only the two
// compression methods that occur in practice are supported: 0 (stored) and 8
// (deflate), the latter handled by zlib.inflateRawSync - "raw" because a ZIP
// member carries a bare deflate stream with no zlib wrapper.
//
// Sizes and offsets are read from the CENTRAL DIRECTORY rather than from each
// local file header. Local headers are allowed to carry zeroes and defer the
// real sizes to a trailing data descriptor (general-purpose bit 3), so trusting
// them yields empty files for archives written in streaming mode.

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const SIG_ZIP64_EOCD = 0x06064b50;

const EOCD_MIN_SIZE = 22;
const MAX_ZIP_COMMENT = 0xffff;

/**
 * Locate the end-of-central-directory record.
 *
 * It sits at the very end of the file, but a trailing comment of up to 64 KiB
 * may follow it, so the signature has to be searched for backwards rather than
 * read at a fixed offset.
 */
function findEndOfCentralDirectory(buf) {
    const earliest = Math.max(0, buf.length - (EOCD_MIN_SIZE + MAX_ZIP_COMMENT));
    for (let i = buf.length - EOCD_MIN_SIZE; i >= earliest; i--) {
        if (buf.readUInt32LE(i) === SIG_EOCD) return i;
    }
    return -1;
}

/** List every entry in the archive: { name, method, compressedSize, localOffset }. */
function readZipEntries(buf) {
    const eocd = findEndOfCentralDirectory(buf);
    if (eocd < 0) {
        fail('Not a ZIP archive (no end-of-central-directory record found).',
             'The download may be truncated or an HTML error page. Delete it and retry.');
    }

    let count = buf.readUInt16LE(eocd + 10);
    let cdOffset = buf.readUInt32LE(eocd + 16);

    // A ZIP64 archive stores sentinel values here and the real ones in a
    // separate record. The icon package is far below the 4 GiB / 65535-entry
    // thresholds today, but reading the sentinels literally would silently
    // produce a nonsense entry list rather than an error, so handle it.
    if (count === 0xffff || cdOffset === 0xffffffff) {
        const locator = eocd - 20;
        if (locator < 0 || buf.readUInt32LE(locator) !== SIG_ZIP64_LOCATOR) {
            fail('Archive claims ZIP64 but has no ZIP64 locator record.');
        }
        const z64 = Number(buf.readBigUInt64LE(locator + 8));
        if (z64 < 0 || z64 + 56 > buf.length || buf.readUInt32LE(z64) !== SIG_ZIP64_EOCD) {
            fail('ZIP64 end-of-central-directory record is missing or malformed.');
        }
        count = Number(buf.readBigUInt64LE(z64 + 32));
        cdOffset = Number(buf.readBigUInt64LE(z64 + 48));
    }

    const entries = [];
    let p = cdOffset;
    for (let i = 0; i < count; i++) {
        if (p + 46 > buf.length || buf.readUInt32LE(p) !== SIG_CENTRAL) {
            fail('Corrupt ZIP: central directory entry ' + (i + 1) + ' of ' + count + ' is invalid.');
        }
        const method = buf.readUInt16LE(p + 10);
        const compressedSize = buf.readUInt32LE(p + 20);
        const nameLen = buf.readUInt16LE(p + 28);
        const extraLen = buf.readUInt16LE(p + 30);
        const commentLen = buf.readUInt16LE(p + 32);
        const localOffset = buf.readUInt32LE(p + 42);
        // ZIP filenames are always '/'-separated by specification, on every
        // platform, so downstream splitting on '/' is correct on Windows too.
        const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
        entries.push({ name, method, compressedSize, localOffset });
        p += 46 + nameLen + extraLen + commentLen;
    }
    return entries;
}

/** Extract one entry's bytes. */
function readZipEntry(buf, entry) {
    if (entry.compressedSize === 0xffffffff || entry.localOffset === 0xffffffff) {
        fail('Entry uses ZIP64 per-entry sizes, which this reader does not support: ' + entry.name);
    }
    const p = entry.localOffset;
    if (p + 30 > buf.length || buf.readUInt32LE(p) !== SIG_LOCAL) {
        fail('Corrupt ZIP: no local file header for ' + entry.name);
    }
    const nameLen = buf.readUInt16LE(p + 26);
    const extraLen = buf.readUInt16LE(p + 28);
    const start = p + 30 + nameLen + extraLen;
    const end = start + entry.compressedSize;
    if (end > buf.length) fail('Corrupt ZIP: ' + entry.name + ' extends past end of file.');

    const raw = buf.subarray(start, end);
    if (entry.method === 0) return Buffer.from(raw);
    if (entry.method === 8) {
        try {
            return zlib.inflateRawSync(raw);
        } catch (e) {
            fail('Could not inflate ' + entry.name + ': ' + e.message);
        }
    }
    fail('Unsupported ZIP compression method ' + entry.method + ' for ' + entry.name,
         'Only stored (0) and deflate (8) are handled. Re-download the package.');
}

/**
 * The AWS_ICONS map in server-v1.js and this manifest must describe the same
 * set of resource types. If they drift, some service silently renders no icon,
 * so treat any difference as a hard failure.
 */
function assertNoDrift(manifestIds) {
    const src = fs.readFileSync(SERVER_PATH, 'utf8');
    const block = src.match(/const AWS_ICONS = \{([\s\S]*?)\n\};/);
    if (!block) fail('Could not locate the AWS_ICONS map in server-v1.js.');

    // Match every `key: '/icons/....svg'` entry, including several per line.
    const serverIds = (block[1].match(/([A-Za-z0-9_]+)\s*:\s*'\/icons\//g) || [])
        .map(s => s.replace(/\s*:\s*'\/icons\/$/, '').trim());

    const missing = serverIds.filter(id => !manifestIds.includes(id));
    const extra = manifestIds.filter(id => !serverIds.includes(id));
    if (missing.length || extra.length) {
        fail('Manifest and server-v1.js AWS_ICONS are out of sync.',
             (missing.length ? '  in server-v1.js but not the manifest: ' + missing.join(', ') + '\n' : '') +
             (extra.length ? '  in the manifest but not server-v1.js: ' + extra.join(', ') : ''));
    }
    return serverIds;
}

async function discoverLatestUrl() {
    const res = await fetch(ICONS_PAGE);
    if (!res.ok) fail('Could not load ' + ICONS_PAGE + ' (HTTP ' + res.status + ')');
    const html = await res.text();
    const hit = html.match(ZIP_LINK_RE);
    if (!hit) {
        fail('No Icon-package ZIP link found on the AWS icons page.',
             'AWS may have changed the page layout. Download the package manually and\n' +
             'pass --url= or --zip= instead.');
    }
    return hit[0];
}

function readLock() {
    if (!fs.existsSync(LOCK_PATH)) return null;
    try {
        return JSON.parse(fs.readFileSync(LOCK_PATH, 'utf8'));
    } catch (e) {
        fail('aws-icons.lock.json is not valid JSON: ' + e.message);
    }
}

/** --check: confirm the committed SVGs still match the lockfile hashes. */
function runCheck(lock) {
    if (!lock) fail('No aws-icons.lock.json found. Run with --latest first.');
    let bad = 0;
    for (const [id, entry] of Object.entries(lock.icons)) {
        const p = path.join(OUT_DIR, id + '.svg');
        if (!fs.existsSync(p)) {
            console.error('MISSING  ' + id + '.svg');
            bad++;
            continue;
        }
        const actual = sha256(fs.readFileSync(p));
        if (actual !== entry.sha256) {
            console.error('MODIFIED ' + id + '.svg');
            bad++;
        }
    }
    if (bad) fail(bad + ' icon file(s) differ from aws-icons.lock.json.');
    console.log('OK: all ' + Object.keys(lock.icons).length +
                ' icons match aws-icons.lock.json (release ' + lock.release + ').');
}

async function main() {
    const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
    const wanted = manifest.icons;
    const ids = Object.keys(wanted);

    assertNoDrift(ids);
    console.log('Manifest and AWS_ICONS agree on ' + ids.length + ' resource types.');

    const lock = readLock();
    if (flag('check')) return runCheck(lock);

    // Resolve which package to use. Pinned by default so repeat runs are
    // reproducible; --latest is the deliberate act of moving the pin forward.
    let zipPath = value('zip');
    let sourceUrl = value('url');
    // The archive is read from memory rather than re-opened per entry: it is
    // ~30 MB, and the previous implementation spawned one `unzip -p` process per
    // icon, which is both slower and the part that needed a shell to exist.
    let zipBuffer;
    if (!zipPath) {
        if (!sourceUrl) {
            const pinned = lock && /^https?:\/\//.test(lock.sourceUrl || '') ? lock.sourceUrl : null;
            if (flag('latest') || !pinned) {
                if (lock && !pinned) {
                    console.log('Lockfile has no fetchable source URL (previous sync used a local\n' +
                                'ZIP), so falling back to discovery.');
                }
                sourceUrl = await discoverLatestUrl();
                console.log('Discovered latest package:\n  ' + sourceUrl);
            } else {
                sourceUrl = pinned;
                console.log('Using pinned package from aws-icons.lock.json:\n  ' + sourceUrl);
                console.log('  (pass --latest to move to the newest release)');
            }
        }
        const res = await fetch(sourceUrl);
        if (!res.ok) fail('Download failed (HTTP ' + res.status + ') for ' + sourceUrl);
        zipBuffer = Buffer.from(await res.arrayBuffer());
        // Kept on disk as well so a failure after this point does not cost
        // another 30 MB download - the path is printed for --zip= on retry.
        zipPath = path.join(os.tmpdir(), 'aws-icon-package-' + sha256(zipBuffer).slice(0, 12) + '.zip');
        fs.writeFileSync(zipPath, zipBuffer);
        console.log('Downloaded ' + (zipBuffer.length / 1048576).toFixed(1) + ' MB to ' + zipPath);
    } else {
        if (!fs.existsSync(zipPath)) fail('No such file: ' + zipPath);
        zipBuffer = fs.readFileSync(zipPath);
        console.log('Using local package: ' + zipPath);
    }

    // Index the archive by basename, ignoring macOS resource-fork entries.
    const allEntries = readZipEntries(zipBuffer);
    const svgEntries = allEntries.filter(e => e.name.endsWith('.svg') && !e.name.includes('__MACOSX'));
    const entries = svgEntries.map(e => e.name);
    if (!entries.length) fail('No .svg entries found in the package.');

    const byBase = new Map();
    const entryByPath = new Map();
    for (const e of svgEntries) {
        byBase.set(e.name.split('/').pop(), e.name);
        entryByPath.set(e.name, e);
    }

    const release = (entries.find(p => /^Architecture-Service-Icons_(\d+)\//.test(p)) || '')
        .split('/')[0].replace('Architecture-Service-Icons_', '') || 'unknown';

    // Resolve every id before writing anything, so a rename upstream fails the
    // whole run instead of leaving a half-updated icon set behind.
    const resolved = {};
    const missing = [];
    for (const [id, base] of Object.entries(wanted)) {
        const hit = byBase.get(base);
        if (hit) resolved[id] = hit;
        else missing.push(id + ' -> ' + base);
    }
    if (missing.length) {
        const hint = missing.map(m => {
            const base = m.split(' -> ')[1];
            const stem = base.replace(/^(Arch|Res)_/, '').replace(/_\d+\.svg$/, '').split(/[-_]/)[1] || '';
            const near = [...byBase.keys()].filter(k => stem && k.includes(stem)).slice(0, 3);
            return '  ' + m + (near.length ? '\n      candidates: ' + near.join(' | ') : '');
        }).join('\n');
        fail(missing.length + ' icon(s) not found in package release ' + release + '.',
             'AWS likely renamed them. Update scripts/aws-icons.manifest.json:\n' + hint);
    }

    fs.mkdirSync(OUT_DIR, { recursive: true });

    const lockIcons = {};
    let changed = 0;
    for (const [id, entryPath] of Object.entries(resolved)) {
        const svg = readZipEntry(zipBuffer, entryByPath.get(entryPath));
        const text = svg.toString('utf8');

        if (!/<svg[\s>]/i.test(text)) {
            fail('Extracted ' + entryPath + ' does not look like SVG.');
        }
        // AWS icons contain no scripting; refuse anything that does rather than
        // vendoring active content into the repo.
        if (/<script[\s>]|javascript:/i.test(text)) {
            fail('Refusing ' + entryPath + ': contains script content.');
        }

        const dest = path.join(OUT_DIR, id + '.svg');
        const before = fs.existsSync(dest) ? sha256(fs.readFileSync(dest)) : null;
        const after = sha256(svg);
        if (before !== after) changed++;
        fs.writeFileSync(dest, svg);

        lockIcons[id] = { source: entryPath, sha256: after, bytes: svg.length };
    }

    fs.writeFileSync(LOCK_PATH, JSON.stringify({
        _comment: 'Generated by scripts/sync-aws-icons.js. Commit this file. Do not edit by hand.',
        release,
        sourceUrl: sourceUrl || ('local:' + path.basename(zipPath)),
        syncedAt: new Date().toISOString(),
        iconCount: Object.keys(lockIcons).length,
        icons: lockIcons
    }, null, 2) + '\n');

    console.log('\nRelease   ' + release);
    console.log('Written   ' + Object.keys(lockIcons).length + ' icons to public/icons/');
    console.log('Changed   ' + changed + ' file(s) this run');
    console.log('Lockfile  scripts/aws-icons.lock.json');
    if (changed) console.log('\nReview the diff before committing.');
}

main().catch(e => fail(e.message, e.stack));
