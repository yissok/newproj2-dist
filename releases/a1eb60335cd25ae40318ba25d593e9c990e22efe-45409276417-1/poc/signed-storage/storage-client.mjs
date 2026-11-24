export const PROTOCOL = 'factory-storage-poc-1';
export const WORKBOOK = '1nSHha2wp0cF3k_71AXgY-5bgxvx46XrahNkBFLyuj5E';
export const APP = 'newproj2';
const DEVICE_KEY = 'factory-storage-poc-device-v1';
const LAST_KEY = 'factory-storage-poc-last-v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const VAULTS = ['0700cdc9-a6ae-4631-92ea-5dc122a749ce', '129afcf7-52e8-4020-96bd-6adff70cbb7d'];
const encoder = new TextEncoder();
export class StoragePocError extends Error {
  constructor(code, message) { super(message); this.name = 'StoragePocError'; this.code = code; }
}
const fail = (code, message) => new StoragePocError(code, message);
export function base64(bytes) {
  let text = '';
  for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(text);
}
export function unbase64(text) {
  if (typeof text !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) {
    throw fail('INTEGRITY', 'Malformed encrypted data.');
  }
  return Uint8Array.from(atob(text), c => c.charCodeAt(0));
}
export async function messageHash(message) {
  return base64(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(message))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function parseRows(text) {
  const match = /^\s*(?:\/\*[\s\S]*?\*\/\s*)?google\.visualization\.Query\.setResponse\(([\s\S]*)\);?\s*$/.exec(text);
  const data = JSON.parse(match ? match[1] : text);
  if (data.status !== 'ok' || !Array.isArray(data.table?.rows)) throw fail('UNAVAILABLE', 'Google did not return a readable Sheet table.');
  return data.table.rows.map(row => row.c?.map(cell => cell?.v ?? '') ?? []);
}
export function normalizeConfig(value) {
  if (!value || value.protocol !== PROTOCOL || value.databaseId !== WORKBOOK ||
      value.app !== APP || !UUID.test(value.installationId) || Number(value.schemaVersion) !== 1 ||
      !/^entry\.[0-9]+$/.test(value.commandEntry) ||
      !/^\d+$/.test(String(value.receiptSheetId)) || !/^\d+$/.test(String(value.dataSheetId))) {
    throw fail('SETUP', 'The owner has not finished the signed-storage POC setup.');
  }
  let url;
  try { url = new URL(value.formUrl); } catch { throw fail('SETUP', 'The command Form is not ready.'); }
  if (url.origin !== 'https://docs.google.com' || url.username || url.password || url.search || url.hash ||
      !/^\/forms\/d\/e\/[A-Za-z0-9_-]+\/formResponse$/.test(url.pathname)) {
    throw fail('SETUP', 'Unexpected command Form address.');
  }
  return { protocol: PROTOCOL, databaseId: WORKBOOK, app: APP, installationId: value.installationId,
    formUrl: url.href, commandEntry: value.commandEntry, receiptSheetId: String(value.receiptSheetId),
    dataSheetId: String(value.dataSheetId), schemaVersion: 1 };
}
export async function loadConfig(fetcher = fetch) {
  const url = new URL('https://docs.google.com/spreadsheets/d/' + WORKBOOK + '/gviz/tq');
  url.search = new URLSearchParams({ sheet: '_storage_poc_config', headers: '1', tqx: 'out:json', _poc: Date.now() }).toString();
  const response = await fetcher(url, { credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(20000) });
  if (!response.ok) throw fail('SETUP', 'The shared POC configuration is not readable yet.');
  const rows = parseRows(await response.text());
  const config = {};
  for (const row of rows) {
    if (row.length !== 2 || typeof row[0] !== 'string' || Object.hasOwn(config, row[0]) ||
        !['protocol', 'databaseId', 'app', 'installationId', 'formUrl', 'commandEntry',
          'receiptSheetId', 'dataSheetId', 'schemaVersion'].includes(row[0])) {
      throw fail('INTEGRITY', 'Invalid shared configuration rows.');
    }
    config[row[0]] = row[1];
  }
  return normalizeConfig(config);
}
export async function createIdentity(vaultId) {
  if (!UUID.test(vaultId)) throw fail('IDENTITY', 'Invalid dummy vault ID.');
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { vaultId, keyId: crypto.randomUUID(),
    publicKey: base64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))),
    privateKey: await crypto.subtle.exportKey('jwk', pair.privateKey),
    encryptionKey: base64(crypto.getRandomValues(new Uint8Array(32))) };
}
export async function deviceIdentities(storage = globalThis.localStorage) {
  const stored = storage.getItem(DEVICE_KEY);
  if (stored !== null) {
    let values;
    try { values = JSON.parse(stored); } catch { throw fail('IDENTITY', 'Stored POC identities are damaged; do not replace their keys.'); }
    if (!Array.isArray(values) || values.length !== 2 || values.some((value, index) =>
      value.vaultId !== VAULTS[index] || !UUID.test(value.keyId) ||
      value.privateKey?.kty !== 'EC' || value.privateKey?.crv !== 'P-256' ||
      typeof value.privateKey?.d !== 'string' || unbase64(value.publicKey).length !== 65 ||
      unbase64(value.encryptionKey).length !== 32)) {
      throw fail('IDENTITY', 'Stored POC identities are damaged; do not replace their keys.');
    }
    // Import now, so damaged keys fail before any signed command is sent.
    for (const value of values) await crypto.subtle.importKey('jwk', value.privateKey,
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    return values;
  }
  const values = await Promise.all(VAULTS.map(createIdentity));
  // Persist before returning. A failed write must not present disposable keys as remembered access.
  storage.setItem(DEVICE_KEY, JSON.stringify(values));
  return values;
}
export function publicIdentities(identities) {
  return identities.map(({ vaultId, keyId, publicKey }) => ({ vaultId, keyId, publicKey }));
}
function context(config, identity, id, revision) {
  return encoder.encode(JSON.stringify([PROTOCOL, config.databaseId, config.installationId, APP, identity.vaultId, id, revision]));
}
export async function encryptValue(config, identity, id, revision, value) {
  if (!UUID.test(id) || !UUID.test(revision)) throw fail('INVALID', 'Invalid record identity.');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', unbase64(identity.encryptionKey), 'AES-GCM', false, ['encrypt']);
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: context(config, identity, id, revision) },
    key, encoder.encode(JSON.stringify(value)));
  const result = 'b64:' + base64(iv) + '.' + base64(new Uint8Array(data));
  if (result.length > 4096) throw fail('LIMIT', 'This bounded POC accepts small dummy records only.');
  return result;
}
export async function decryptValue(config, identity, record) {
  try {
    if (record.app !== APP || record.vaultId !== identity.vaultId || !UUID.test(record.id) ||
        !UUID.test(record.revision) || record.deleted || !record.ciphertext.startsWith('b64:')) throw Error();
    const parts = record.ciphertext.slice(4).split('.');
    if (parts.length !== 2 || unbase64(parts[0]).length !== 12) throw Error();
    const key = await crypto.subtle.importKey('raw', unbase64(identity.encryptionKey), 'AES-GCM', false, ['decrypt']);
    const bytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unbase64(parts[0]),
      additionalData: context(config, identity, record.id, record.revision) }, key, unbase64(parts[1]));
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch { throw fail('INTEGRITY', 'The encrypted record did not match this vault and record revision.'); }
}
export async function signCommand(config, identity, command, options = {}) {
  const request = { protocol: PROTOCOL, databaseId: config.databaseId, installationId: config.installationId,
    issuedAt: options.issuedAt ?? Date.now(), keyId: identity.keyId,
    requestId: options.requestId ?? crypto.randomUUID(), command };
  const message = JSON.stringify(request);
  const key = await crypto.subtle.importKey('jwk', identity.privateKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const signature = base64(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, encoder.encode(message))));
  return { message, signature };
}
export function transport(value, identity, options = {}) {
  const config = normalizeConfig(value), fetcher = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 45000, pollMs = options.pollMs ?? 1000;
  async function send(envelope) {
    const request = JSON.parse(envelope.message), command = request.command;
    if (!UUID.test(request.requestId)) throw fail('INVALID', 'Invalid request ID.');
    const expectedHash = await messageHash(envelope.message);
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeoutMs);
    const body = new FormData(); body.append(config.commandEntry, JSON.stringify(envelope));
    try {
      try {
        await fetcher(config.formUrl, { method: 'POST', body, mode: 'no-cors', credentials: 'omit',
          referrerPolicy: 'no-referrer', signal: controller.signal });
      } catch { /* Google may receive an opaque/failed POST. Only the matching receipt decides. */ }
      while (!controller.signal.aborted) {
        const url = new URL('https://docs.google.com/spreadsheets/d/' + config.databaseId + '/gviz/tq');
        url.search = new URLSearchParams({ gid: config.receiptSheetId, headers: '1', tqx: 'out:json',
          tq: "SELECT A,B,C WHERE A = '" + request.requestId + "'", _poc: request.requestId + '-' + Date.now() }).toString();
        try {
          const response = await fetcher(url, { credentials: 'omit', cache: 'no-store',
            referrerPolicy: 'no-referrer', signal: controller.signal });
          if (response.ok) for (const row of parseRows(await response.text())) {
            if (row[0] !== request.requestId) continue;
            const receipt = JSON.parse(row[2]);
            if (row[1] !== expectedHash || receipt.protocol !== PROTOCOL || receipt.databaseId !== config.databaseId ||
                receipt.installationId !== config.installationId || receipt.requestId !== request.requestId ||
                receipt.requestHash !== expectedHash || receipt.app !== command.app || receipt.vaultId !== command.vaultId ||
                receipt.op !== command.op || receipt.id !== command.id ||
                Object.hasOwn(receipt, 'result') === Object.hasOwn(receipt, 'error')) {
              throw fail('INTEGRITY', 'The Sheet receipt did not match this exact signed command.');
            }
            if (receipt.error) {
              if (typeof receipt.error.code !== 'string' || typeof receipt.error.message !== 'string') throw fail('INTEGRITY', 'Malformed error receipt.');
              throw fail(receipt.error.code, receipt.error.message);
            }
            const record = command.op === 'get' ? receipt.result?.record : receipt.result;
            if (command.op === 'get' && record === null) {
              return { result: receipt.result, receiptId: receipt.requestId, requestHash: expectedHash };
            }
            if (!record || record.app !== command.app || record.vaultId !== command.vaultId || record.id !== command.id ||
                !UUID.test(record.revision) || typeof record.deleted !== 'boolean' ||
                !Number.isFinite(Date.parse(record.updatedAt)) ||
                command.op !== 'get' && (record.revision !== command.revision || record.deleted !== (command.op === 'delete')) ||
                command.op === 'get' && typeof record.ciphertext !== 'string') {
              throw fail('INTEGRITY', 'The receipt result did not match the requested record operation.');
            }
            return { result: receipt.result, receiptId: receipt.requestId, requestHash: expectedHash };
          }
        } catch (error) { if (error instanceof StoragePocError) throw error; }
        await new Promise(resolve => {
          const finish = () => { clearTimeout(wait); controller.signal.removeEventListener('abort', finish); resolve(); };
          const wait = setTimeout(finish, pollMs); controller.signal.addEventListener('abort', finish, { once: true });
          if (controller.signal.aborted) finish();
        });
      }
      throw fail('WRITE_UNCONFIRMED', 'No matching Sheet receipt arrived. Keep the local draft; retry the same operation.');
    } finally { clearTimeout(timer); }
  }
  return { config, send, async request(command) {
    return send(await signCommand(config, identity, { app: APP, vaultId: identity.vaultId, ...command }));
  } };
}
export async function runLiveChecks(config, identities, report, storage = globalThis.localStorage, options = {}) {
  const [a, b] = identities, ta = transport(config, a, options), tb = transport(config, b, options);
  const id = crypto.randomUUID(), initialRevision = crypto.randomUUID();
  const value = { item: 'POC apples ' + crypto.randomUUID(), checked: false };
  const ciphertext = await encryptValue(config, a, id, initialRevision, value);
  let saved = await ta.request({ op: 'put', id, revision: initialRevision, expectedRevision: null, ciphertext });
  if (saved.result.revision !== initialRevision || saved.result.deleted) throw fail('INTEGRITY', 'Initial save receipt did not match.');
  report('Encrypted write confirmed by Sheet receipt', saved.receiptId);
  let read = await ta.request({ op: 'get', id });
  if (!read.result.record || JSON.stringify(await decryptValue(config, a, read.result.record)) !== JSON.stringify(value)) throw fail('INTEGRITY', 'Readback mismatch.');
  report('Signed read decrypted the dummy record', read.receiptId);
  const isolated = await tb.request({ op: 'get', id });
  if (isolated.result.record !== null) throw fail('ISOLATION', 'The other vault unexpectedly saw a record.');
  report('Second vault could not read the first vault record', isolated.receiptId);
  value.checked = true;
  const revision = crypto.randomUUID(), updated = await encryptValue(config, a, id, revision, value);
  const command = { app: APP, vaultId: a.vaultId, op: 'put', id, revision, expectedRevision: initialRevision, ciphertext: updated };
  const envelope = await signCommand(config, a, command);
  const pendingKey = 'factory-storage-poc-outbox-' + a.vaultId;
  // The encrypted operation, not a passphrase or plaintext item, is retained before upload.
  storage.setItem(pendingKey, JSON.stringify(command));
  saved = await ta.send(envelope);
  const retried = await ta.send(envelope);
  if (JSON.stringify(retried) !== JSON.stringify(saved)) throw fail('INTEGRITY', 'Exact retry changed its receipt.');
  report('Exact signed retry reused the same receipt', retried.receiptId);
  const resumed = await ta.request({ op: 'put', id, revision, expectedRevision: initialRevision, ciphertext: updated });
  if (resumed.result.revision !== revision) throw fail('INTEGRITY', 'Immutable revision retry failed.');
  storage.removeItem(pendingKey);
  report('A fresh request safely resumed the same immutable revision', resumed.receiptId);
  try {
    const staleRevision = crypto.randomUUID();
    await ta.request({ op: 'put', id, revision: staleRevision, expectedRevision: initialRevision,
      ciphertext: await encryptValue(config, a, id, staleRevision, { item: 'unused stale dummy' }) });
    throw fail('TEST', 'The stale revision was unexpectedly accepted.');
  } catch (error) {
    if (error.code !== 'CONFLICT') throw error;
    report('Stale update rejected with a conflict receipt');
  }
  const deleted = await ta.request({ op: 'delete', id, revision: crypto.randomUUID(), expectedRevision: revision });
  if (!deleted.result.deleted) throw fail('INTEGRITY', 'Delete was not confirmed.');
  const tombstone = await ta.request({ op: 'get', id });
  if (!tombstone.result.record?.deleted || tombstone.result.record.ciphertext !== '') throw fail('INTEGRITY', 'Delete readback failed.');
  report('Delete and its readback confirmed', deleted.receiptId);
  // Leave one encrypted dummy record for the separate real page-reload check.
  const finalRevision = crypto.randomUUID();
  const final = await ta.request({ op: 'put', id, revision: finalRevision, expectedRevision: deleted.result.revision,
    ciphertext: await encryptValue(config, a, id, finalRevision, value) });
  storage.setItem(LAST_KEY, JSON.stringify({ id, revision: finalRevision, value }));
  report('Encrypted dummy record left ready for a page reload', final.receiptId);
  return { id, revision: finalRevision };
}
export async function checkAfterReload(config, identities, storage = globalThis.localStorage, options = {}) {
  const saved = JSON.parse(storage.getItem(LAST_KEY) || 'null');
  if (!saved) throw fail('TEST', 'Run the live checks before reloading.');
  const response = await transport(config, identities[0], options).request({ op: 'get', id: saved.id });
  if (!response.result.record || response.result.record.revision !== saved.revision ||
      JSON.stringify(await decryptValue(config, identities[0], response.result.record)) !== JSON.stringify(saved.value)) {
    throw fail('INTEGRITY', 'The record did not survive page reload.');
  }
  return { receiptId: response.receiptId, id: saved.id, checked: saved.value.checked };
}
