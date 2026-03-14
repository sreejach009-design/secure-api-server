async function testProxy() {
    try {
        const id = '67ced9a09376662998a44214'; // Real ID from my check
        const res = await fetch(`http://localhost:5000/api/external-usage/proxy/${id}?targetUrl=https://httpbin.org/get`);
        console.log('Proxy status (expect 401/403 since no token):', res.status);
    } catch (err) {
        console.error('Test Failed:', err.message);
    }
}

testProxy();
