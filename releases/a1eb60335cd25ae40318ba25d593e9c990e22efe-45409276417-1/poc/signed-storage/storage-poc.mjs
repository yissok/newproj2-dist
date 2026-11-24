import { deviceIdentities, publicIdentities, loadConfig, runLiveChecks, checkAfterReload } from './storage-client.mjs';
const prepare = document.querySelector('#prepare'), run = document.querySelector('#run'),
  reload = document.querySelector('#reload-check'), registration = document.querySelector('#registration'),
  identityStatus = document.querySelector('#identity-status'), status = document.querySelector('#status'),
  results = document.querySelector('#results');
let identities, busy = false;
const allowedOrigin = location.origin === 'https://scout-38aa2.web.app';
function report(message, receipt) {
  const li = document.createElement('li');
  li.textContent = 'PASS — ' + message + (receipt ? ' · receipt ' + receipt : '');
  results.append(li);
}
function controls(value) {
  busy = value; prepare.disabled = value;
  run.disabled = value || !identities || !allowedOrigin;
  reload.disabled = value || !identities || !allowedOrigin;
}
async function getIdentities() {
  identities = await deviceIdentities();
  registration.value = JSON.stringify(publicIdentities(identities), null, 2);
  identityStatus.textContent = 'Two test identities are remembered locally. Public registration is ready.';
  controls(false);
  status.textContent = allowedOrigin ? 'Ready to load the shared setup and run the checks.'
    : 'Open this probe on the live Scout origin to send test commands.';
}
prepare.addEventListener('click', async () => {
  controls(true);
  try { await getIdentities(); } catch (error) {
    identityStatus.textContent = error.message; identityStatus.className = 'error'; controls(false);
  }
});
run.addEventListener('click', async () => {
  if (busy || !allowedOrigin) return;
  controls(true); results.replaceChildren(); status.className = ''; document.body.dataset.testState = 'running';
  status.textContent = 'Running. Waiting for each exact Sheet receipt before reporting confirmation…';
  try {
    const config = await loadConfig();
    const result = await runLiveChecks(config, identities, report);
    status.textContent = 'All signed storage checks passed. Reload this page, then use “Check after page reload”. Record: ' + result.id;
    document.body.dataset.testState = 'passed';
  } catch (error) {
    status.className = 'error'; status.textContent = (error.code ? error.code + ': ' : '') + error.message;
    document.body.dataset.testState = 'failed';
  } finally { controls(false); }
});
reload.addEventListener('click', async () => {
  if (busy || !allowedOrigin) return;
  controls(true); status.className = ''; document.body.dataset.reloadState = 'running';
  status.textContent = 'Reading the encrypted record using the remembered browser identity…';
  try {
    const result = await checkAfterReload(await loadConfig(), identities);
    report('Page reload retained the identity and encrypted checked record', result.receiptId);
    status.textContent = 'Reload check passed. The checked dummy record survived. Record: ' + result.id;
    document.body.dataset.reloadState = 'passed';
  } catch (error) {
    status.className = 'error'; status.textContent = (error.code ? error.code + ': ' : '') + error.message;
    document.body.dataset.reloadState = 'failed';
  } finally { controls(false); }
});
try {
  if (localStorage.getItem('factory-storage-poc-device-v1') !== null) await getIdentities();
} catch (error) { identityStatus.textContent = error.message; identityStatus.className = 'error'; }
