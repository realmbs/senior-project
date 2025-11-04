// API test functionality
import { searchThreats, collectThreats, enrichIndicator, detectIocType } from './lib/api';

// Helper function to update status and data
function updateStatus(statusEl: HTMLElement, dataEl: HTMLElement, isLoading: boolean, error?: string, data?: any) {
  if (isLoading) {
    statusEl.innerHTML = '<div class="loading">⏳ Loading...</div>';
    dataEl.textContent = '';
  } else if (error) {
    statusEl.innerHTML = `<div class="error">❌ Error: ${error}</div>`;
    dataEl.textContent = '';
  } else if (data) {
    statusEl.innerHTML = '<div class="success">✅ Success!</div>';
    dataEl.textContent = JSON.stringify(data, null, 2);
  }
}

// Search threats test
const searchBtn = document.getElementById('searchBtn') as HTMLButtonElement;
const searchStatus = document.getElementById('searchStatus') as HTMLDivElement;
const searchData = document.getElementById('searchData') as HTMLPreElement;

searchBtn.addEventListener('click', async () => {
  searchBtn.disabled = true;
  updateStatus(searchStatus, searchData, true);

  try {
    const query = (document.getElementById('searchQuery') as HTMLInputElement).value.trim() || undefined;
    const type = (document.getElementById('searchType') as HTMLSelectElement).value || undefined;
    const limit = parseInt((document.getElementById('searchLimit') as HTMLInputElement).value) || 5;

    const result = await searchThreats(limit, query, type);
    updateStatus(searchStatus, searchData, false, undefined, result);
  } catch (e) {
    updateStatus(searchStatus, searchData, false, e instanceof Error ? e.message : String(e));
  }

  searchBtn.disabled = false;
});

// Collect threats test
const collectBtn = document.getElementById('collectBtn') as HTMLButtonElement;
const collectStatus = document.getElementById('collectStatus') as HTMLDivElement;
const collectData = document.getElementById('collectData') as HTMLPreElement;

collectBtn.addEventListener('click', async () => {
  collectBtn.disabled = true;
  updateStatus(collectStatus, collectData, true);

  try {
    const result = await collectThreats(['otx'], 10, 'automated', {
      ioc_types: ['domain', 'ip'],
      confidence: 70
    });
    updateStatus(collectStatus, collectData, false, undefined, result);
  } catch (e) {
    const errorMsg = e instanceof Error ? e.message : String(e);
    if (errorMsg.includes('timeout') || errorMsg.includes('timed out')) {
      updateStatus(collectStatus, collectData, false, 'Collection timed out (this is normal - collection jobs run for 30+ seconds)', undefined);
    } else {
      updateStatus(collectStatus, collectData, false, errorMsg);
    }
  }

  collectBtn.disabled = false;
});

// Enrich indicator test
const enrichBtn = document.getElementById('enrichBtn') as HTMLButtonElement;
const indicatorInput = document.getElementById('indicatorInput') as HTMLInputElement;
const enrichStatus = document.getElementById('enrichStatus') as HTMLDivElement;
const enrichData = document.getElementById('enrichData') as HTMLPreElement;

enrichBtn.addEventListener('click', async () => {
  const indicator = indicatorInput.value.trim();
  if (!indicator) {
    updateStatus(enrichStatus, enrichData, false, 'Please enter an indicator (IP or domain)');
    return;
  }

  enrichBtn.disabled = true;
  updateStatus(enrichStatus, enrichData, true);

  try {
    const iocType = detectIocType(indicator);
    const result = await enrichIndicator(indicator, iocType);
    updateStatus(enrichStatus, enrichData, false, undefined, result);
  } catch (e) {
    updateStatus(enrichStatus, enrichData, false, e instanceof Error ? e.message : String(e));
  }

  enrichBtn.disabled = false;
});

// IOC type detection and display
const detectedTypeEl = document.getElementById('detectedType') as HTMLSpanElement;

function updateDetectedType() {
  const value = indicatorInput.value.trim();
  if (value) {
    const type = detectIocType(value);
    detectedTypeEl.textContent = `Detected type: ${type}`;
  } else {
    detectedTypeEl.textContent = '';
  }
}

indicatorInput.addEventListener('input', updateDetectedType);

// Set default test value
indicatorInput.value = '1.1.1.1';
updateDetectedType();