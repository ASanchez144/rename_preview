// static/script.js

document.addEventListener('DOMContentLoaded', function() {
    // Get modal elements
    const loginModal = document.getElementById('loginModal');
    const registerModal = document.getElementById('registerModal');

    // Get button elements
    const loginBtn = document.getElementById('loginBtn');
    const registerBtn = document.getElementById('registerBtn');
    const getStartedBtn = document.getElementById('getStartedBtn');

    // Get close elements
    const closeLogin = document.getElementById('closeLogin');
    const closeRegister = document.getElementById('closeRegister');

    // Get switch elements
    const switchToRegister = document.getElementById('switchToRegister');
    const switchToLogin = document.getElementById('switchToLogin');

    // Open Login Modal
    if (loginBtn) {
        loginBtn.onclick = function() {
            loginModal.style.display = 'flex';
        }
    }

    // Open Register Modal
    if (registerBtn) {
        registerBtn.onclick = function() {
            registerModal.style.display = 'flex';
        }
    }

    // Open Rename Tool Page
    if (getStartedBtn) {
        getStartedBtn.onclick = function() {
            window.location.href = '/rename_tool';
        }
    }

    // Close Login Modal
    if (closeLogin) {
        closeLogin.onclick = function() {
            loginModal.style.display = 'none';
        }
    }

    // Close Register Modal
    if (closeRegister) {
        closeRegister.onclick = function() {
            registerModal.style.display = 'none';
        }
    }

    // Switch to Register Modal
    if (switchToRegister) {
        switchToRegister.onclick = function(e) {
            e.preventDefault();
            loginModal.style.display = 'none';
            registerModal.style.display = 'flex';
        }
    }

    // Switch to Login Modal
    if (switchToLogin) {
        switchToLogin.onclick = function(e) {
            e.preventDefault();
            registerModal.style.display = 'none';
            loginModal.style.display = 'flex';
        }
    }

    // Close Modals When Clicking Outside
    window.onclick = function(event) {
        if (event.target == loginModal) {
            loginModal.style.display = 'none';
        }
        if (event.target == registerModal) {
            registerModal.style.display = 'none';
        }
    }
});
