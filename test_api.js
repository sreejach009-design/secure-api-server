
const BASE_URL = 'http://localhost:5000/api';
let token = '';
let apiKey = '';
let credentialId = '';

async function testAuth() {
    console.log('\n--- Testing Auth ---');
    try {
        const registerRes = await fetch(`${BASE_URL}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: 'testuser_' + Date.now(),
                email: 'test' + Date.now() + '@example.com',
                password: 'password123',
                role: 'admin'
            })
        });
        const registerData = await registerRes.json();
        console.log('Register status:', registerRes.status);
        if (registerRes.status !== 200) console.log('Register Error:', registerData);

        const loginRes = await fetch(`${BASE_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: registerData.user.email,
                password: 'password123'
            })
        });
        const loginData = await loginRes.json();
        console.log('Login status:', loginRes.status);
        token = loginData.token;
        console.log('Token acquired');
    } catch (err) {
        console.error('Auth Test Failed:', err.message);
    }
}

async function testCredentials() {
    console.log('\n--- Testing Credentials ---');
    try {
        // Create
        const createRes = await fetch(`${BASE_URL}/credentials`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ name: 'Test Key' })
        });
        const createData = await createRes.json();
        console.log('Create Credential status:', createRes.status);
        apiKey = createData.apiKey;
        credentialId = createData._id;
        console.log('API Key:', apiKey);

        // List
        const listRes = await fetch(`${BASE_URL}/credentials`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        console.log('List Credentials status:', listRes.status);

        // Rotate
        const rotateRes = await fetch(`${BASE_URL}/credentials/${credentialId}/rotate`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const rotateData = await rotateRes.json();
        console.log('Rotate Key status:', rotateRes.status);
        apiKey = rotateData.apiKey;
        console.log('New API Key:', apiKey);
    } catch (err) {
        console.error('Credentials Test Failed:', err.message);
    }
}

async function testUsageAndSimulation() {
    console.log('\n--- Testing Usage & Simulation ---');
    try {
        // Simple simulation
        const simRes = await fetch(`${BASE_URL}/usage/simulate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ apiKey, endpoint: '/api/test', method: 'GET' })
        });
        const simData = await simRes.json();
        console.log('Simulate status:', simRes.status);
        console.log('Simulate response:', simData.message);

        // Groq simulation
        console.log('Testing Groq Integration...');
        const groqRes = await fetch(`${BASE_URL}/usage/simulate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                apiKey,
                endpoint: '/api/groq',
                method: 'POST',
                prompt: 'Hello, what is the capital of France?'
            })
        });
        const groqData = await groqRes.json();
        console.log('Groq Simulate status:', groqRes.status);
        if (groqRes.status === 200) {
            console.log('Groq Response (Full):', JSON.stringify(groqData.data, null, 2));
            console.log('Groq Response Content:', groqData.data?.choices?.[0]?.message?.content);
        } else {
            console.log('Groq Error Message:', groqData.message);
            console.log('Groq Error Detail:', groqData.error);
        }

        // Stats
        const statsRes = await fetch(`${BASE_URL}/usage/stats`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        console.log('Get Stats status:', statsRes.status);

        // Security Alert Test: Simulate with inactive scenario
        console.log('Testing Security Alert Generation...');
        const inactiveRes = await fetch(`${BASE_URL}/usage/simulate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ apiKey, scenario: 'inactive' })
        });
        console.log('Inactive Sim status (expected 401):', inactiveRes.status);
    } catch (err) {
        console.error('Usage Test Failed:', err.message);
    }
}

async function testSecurity() {
    console.log('\n--- Testing Security Alerts ---');
    try {
        const listRes = await fetch(`${BASE_URL}/security`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const alerts = await listRes.json();
        console.log('List Alerts status:', listRes.status);
        console.log('Alerts count:', Array.isArray(alerts) ? alerts.length : 'N/A');
    } catch (err) {
        console.error('Security Test Failed:', err.message);
    }
}

async function runAllTests() {
    await testAuth();
    if (!token) return;
    await testCredentials();
    await testUsageAndSimulation();
    await testSecurity();
    console.log('\n--- Tests Completed ---');
}

runAllTests();
