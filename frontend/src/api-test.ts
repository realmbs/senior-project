// API test functionality
import { searchThreats, collectThreats, enrichIndicator } from './lib/api';

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
    const result = await searchThreats(5);
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
    const result = await collectThreats(['otx']);
    updateStatus(collectStatus, collectData, false, undefined, result);
  } catch (e) {
    updateStatus(collectStatus, collectData, false, e instanceof Error ? e.message : String(e));
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
    const result = await enrichIndicator(indicator);
    updateStatus(enrichStatus, enrichData, false, undefined, result);
  } catch (e) {
    updateStatus(enrichStatus, enrichData, false, e instanceof Error ? e.message : String(e));
  }

  enrichBtn.disabled = false;
});

// Set default test value
indicatorInput.value = '1.1.1.1';