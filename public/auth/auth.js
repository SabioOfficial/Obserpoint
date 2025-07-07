const API_BASE_URL = 'http://localhost:4893';

const usernameInput = document.getElementById('usernameInput');
const passwordInput = document.getElementById('passwordInput');
const messageArea = document.getElementById('messageArea');

function displayMessage(message, type = 'info') {
    if (typeof message === 'object') {
        message = JSON.stringify(message, null, 2);
    }
    messageArea.textContent = message;
    messageArea.className = 'message-area ' + type;
}

async function fetchWithAuth(url, options = {}) {
    options.credentials = 'include';
    let response = await fetch(url, options);

    if (response.status === 403 && url !== `${API_BASE_URL}/refresh-token`) {
        displayMessage('Access token expired, attempting refresh...', 'info');
        const refreshRes = await fetch(`${API_BASE_URL}/refresh-token`, {
            method: 'POST',
            credentials: 'include'
        });

        if (refreshRes.ok) {
            displayMessage('Token refreshed. Retrying original request.', 'info');
            response = await fetch(url, options);
        } else {
            displayMessage('Failed to refresh token. Please log in.', 'error');
            await logoutUser();
            throw new Error('Failed to refresh token. Logging out.');
        }
    }

    if (response.status === 401 || (response.status === 403 && url.includes('/protected'))) {
        displayMessage('Not authenticated. Please log in.', 'error');
        await logoutUser();
        throw new Error('Authentication required.');
    }
    
    return response;
}

async function register() {
    const username = usernameInput.value;
    const password = passwordInput.value;
    displayMessage('Registering...', 'info');
    try {
        const res = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        // Handle validation errors from express-validator
        if (data.errors) {
            const errorMsg = data.errors.map(e => e.msg).join('\n');
            displayMessage(errorMsg, 'error');
        } else {
            displayMessage(data.message, res.ok ? 'success' : 'error');
        }
    } catch (err) {
        displayMessage('Network error during registration: ' + err.message, 'error');
    }
}

async function login() {
    const username = usernameInput.value;
    const password = passwordInput.value;
    displayMessage('Logging in...', 'info');
    try {
        const res = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
            credentials: 'include'
        });
        const data = await res.json();
        displayMessage(data.message, res.ok ? 'success' : 'error');
    } catch (err) {
        displayMessage('Network error during login: ' + err.message, 'error');
    }
}

async function logoutUser() {
    displayMessage('Logging out...', 'info');
    try {
        const res = await fetch(`${API_BASE_URL}/logout`, {
            method: 'POST',
            credentials: 'include'
        });
        const data = await res.json();
        displayMessage(data.message, res.ok ? 'success' : 'error');
    } catch (err) {
        displayMessage('Network error during logout: ' + err.message, 'error');
    }
}

async function accessProtected() {
    displayMessage('Accessing protected route...', 'info');
    try {
        const res = await fetchWithAuth(`${API_BASE_URL}/protected`);
        const data = await res.json();
        displayMessage(data, res.ok ? 'success' : 'error');
    } catch (err) {
        displayMessage('Error accessing protected route: ' + err.message, 'error');
    }
}

document.getElementById('registerBtn').addEventListener('click', register);
document.getElementById('loginBtn').addEventListener('click', login);
document.getElementById('logoutBtn').addEventListener('click', logoutUser);
document.getElementById('protectedBtn').addEventListener('click', accessProtected);