#!/usr/bin/env node
// Verify the PUBLIC, owner-signed manifest and the EXACT released assets.
// Does not download executables, sign manifests, publish releases, or use private keys.
import { readFileSync } from 'node:fs';
import { createPublicKey, verify } from 'node:crypto';

const REPOSITORY = 'jimenemy/nova-wallet-redder-updates';
const PUBLIC_KEY_B64 = 'P0hdjvZa55wvb2JPR3zHfyn+pkfhKaUL2xt1oiySzrQ=';
const ASSETS = { windows: 'NovaWalletRedder.exe', android: 'NovaWalletRedder.apk' };
const abort = (message) => { throw new Error(message); };

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === 'object')
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])]));
  return value;
}

async function main() {
  const manifest = JSON.parse(readFileSync(new URL('../latest.json', import.meta.url), 'utf8'));
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest))
    abort('Manifest must be an object');
  if (manifest.schema !== 1 || manifest.channel !== 'stable')
    abort('Unexpected signed manifest schema/channel');
  if (!Number.isFinite(Date.parse(manifest.released_at || '')))
    abort('Missing or invalid signed release time');

  const signature = Buffer.from(manifest.signature || '', 'base64');
  const rawPublicKey = Buffer.from(PUBLIC_KEY_B64, 'base64');
  if (signature.length !== 64 || rawPublicKey.length !== 32)
    abort('Malformed Ed25519 public key or signature');
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'), rawPublicKey
  ]);
  const publicKey = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  const signed = Object.fromEntries(
    Object.entries(manifest).filter(([name]) => name !== 'signature')
  );
  const canonical = Buffer.from(JSON.stringify(sorted(signed)), 'utf8');
  if (!verify(null, canonical, publicKey, signature))
    abort('Ed25519 manifest signature does not match the embedded app public key');

  const headers = {
    'User-Agent': 'NovaWalletRedder-release-integrity-CI',
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (process.env.GITHUB_TOKEN) headers.Authorization = 'Bearer ' + process.env.GITHUB_TOKEN;
  const seen = new Map();

  for (const [platform, filename] of Object.entries(ASSETS)) {
    const data = manifest[platform];
    if (!data || typeof data !== 'object')
      abort('Missing signed platform: ' + platform);
    if (!/^\\d+\\.\\d+\\.\\d+$/.test(data.version || ''))
      abort('Invalid signed version: ' + platform);
    if (!/^[a-f0-9]{64}$/.test(data.sha256 || ''))
      abort('Invalid signed SHA-256: ' + platform);
    if (!Number.isSafeInteger(data.size) || data.size <= 0)
      abort('Invalid signed byte size: ' + platform);
    const tag = 'v' + data.version;
    const expectedUrl = 'https://github.com/' + REPOSITORY
      + '/releases/download/' + tag + '/' + filename;
    if (data.url !== expectedUrl)
      abort('Unexpected release URL for ' + platform + '; refusal to follow arbitrary link');
    let release = seen.get(tag);
    if (!release) {
      const endpoint = 'https://api.github.com/repos/' + REPOSITORY
        + '/releases/tags/' + encodeURIComponent(tag);
      const response = await fetch(endpoint, { headers, signal: AbortSignal.timeout(15000) });
      if (!response.ok)
        abort('GitHub Release metadata unavailable for ' + tag + ': HTTP ' + response.status);
      release = await response.json();
      if (release.draft || release.prerelease || release.tag_name !== tag)
        abort('Signed manifest references a draft/prerelease or mismatched tag: ' + tag);
      seen.set(tag, release);
    }
    const assets = (release.assets || []).filter(asset => asset.name === filename && asset.state === 'uploaded');
    if (assets.length !== 1)
      abort('Published release asset is missing or ambiguous: ' + tag + '/' + filename);
    const [asset] = assets;
    if (asset.size !== data.size || asset.digest !== 'sha256:' + data.sha256)
      abort('Release asset size/digest differs from signed manifest: ' + tag + '/' + filename);
    console.log('VERIFIED ' + platform + ' ' + tag + ' signed SHA-256/size/release asset');
  }
  console.log('PASS: Ed25519 signed stable manifest and both existing release binaries agree');
}

main().catch(error => { console.error('FAIL:', error.message); process.exitCode = 1; });
