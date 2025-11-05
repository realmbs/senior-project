console.log('Simple main.ts loading...');

// Simple test without complex dashboard
document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <div style="padding: 20px; color: white; background: linear-gradient(to br, #1f2937, #3b82f6, #1f2937); min-height: 100vh;">
    <h1>🛡️ Threat Intelligence Platform</h1>
    <p>Dashboard loading test...</p>
    <div style="margin: 20px 0;">
      <button id="test-api" style="padding: 10px 20px; background: #3b82f6; color: white; border: none; border-radius: 8px; cursor: pointer;">
        Test API Connection
      </button>
    </div>
    <div id="status" style="margin: 20px 0; padding: 10px; background: rgba(0,0,0,0.3); border-radius: 8px;">
      Ready to test...
    </div>
  </div>
`;

// Simple API test
document.getElementById('test-api')?.addEventListener('click', async () => {
  const statusDiv = document.getElementById('status')!;
  statusDiv.innerHTML = 'Testing API...';

  try {
    const response = await fetch('https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev/search?limit=1', {
      headers: {
        'X-Api-Key': 'mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf'
      }
    });

    if (response.ok) {
      const data = await response.json();
      statusDiv.innerHTML = `✅ API Connected! Found ${data.results?.results?.length || 0} threats`;
    } else {
      statusDiv.innerHTML = `❌ API Error: ${response.status}`;
    }
  } catch (error) {
    statusDiv.innerHTML = `❌ Connection Error: ${error}`;
  }
});

console.log('Simple dashboard loaded');