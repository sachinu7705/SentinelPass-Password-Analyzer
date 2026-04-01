// static/register.js

let otpModal;
let timerInterval;
let timeLeft = 60;
let currentEmail = '';
let currentPassword = '';

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap modal
    otpModal = new bootstrap.Modal(document.getElementById('otpModal'), {
        backdrop: 'static',
        keyboard: false
    });
    
    // Set email display
    const emailInput = document.getElementById('email');
    if (emailInput) {
        emailInput.addEventListener('input', function() {
            const emailDisplay = document.getElementById('otpEmailDisplay');
            if (emailDisplay && this.value) {
                emailDisplay.textContent = this.value;
            }
        });
    }
    
    // Add enter key support
    const inputs = document.querySelectorAll('#registerForm input');
    inputs.forEach(input => {
        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                sendOtp();
            }
        });
    });
});

function sendOtp() {
    // Get form values
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    
    // Store for later use
    currentEmail = email;
    currentPassword = password;
    
    // Update email display
    const emailDisplay = document.getElementById('otpEmailDisplay');
    if (emailDisplay) emailDisplay.textContent = email;
    
    // Validation checks
    if (!email) {
        showNotification('Please enter your email address', 'error');
        return;
    }
    
    // Email format validation
    const emailRegex = /^[^\s@]+@([^\s@]+\.)+[^\s@]+$/;
    if (!emailRegex.test(email)) {
        showNotification('Please enter a valid email address', 'error');
        return;
    }
    
    if (!password) {
        showNotification('Please create a password', 'error');
        return;
    }
    
    if (password.length < 6) {
        showNotification('Password must be at least 6 characters long', 'error');
        return;
    }
    
    if (password !== confirmPassword) {
        showNotification('Passwords do not match!', 'error');
        return;
    }
    
    // Disable the send OTP button
    const sendBtn = document.querySelector('button[onclick="sendOtp()"]');
    sendBtn.disabled = true;
    sendBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Sending...';
    
    // Send OTP request
    fetch('/send-otp', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            email: email,
            password: password
        })
    })
    .then(async response => {
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.message || 'Failed to send OTP');
        }
        return data;
    })
    .then(data => {
        if (data.success) {
            showNotification('OTP sent successfully! Check your email.', 'success');
            otpModal.show();
            startTimer();
            setupOtpInputs();
        } else {
            showNotification(data.message || 'Failed to send OTP', 'error');
        }
        sendBtn.disabled = false;
        sendBtn.textContent = 'Send OTP';
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification(error.message || 'Network error. Please try again.', 'error');
        sendBtn.disabled = false;
        sendBtn.textContent = 'Send OTP';
    });
}

function startTimer() {
    timeLeft = 60;
    const timerText = document.getElementById('timerText');
    const timerSection = document.getElementById('timerSection');
    const resendBtn = document.getElementById('resendBtn');
    
    // Clear any existing interval
    if (timerInterval) {
        clearInterval(timerInterval);
    }
    
    // Show timer, hide resend button
    timerSection.style.display = 'inline-flex';
    resendBtn.style.display = 'none';
    timerSection.classList.remove('expired');
    
    timerInterval = setInterval(() => {
        if (timeLeft <= 0) {
            clearInterval(timerInterval);
            timerSection.style.display = 'none';
            resendBtn.style.display = 'inline-flex';
            // Add animation to resend button
            resendBtn.classList.add('animate__animated', 'animate__pulse');
            setTimeout(() => {
                resendBtn.classList.remove('animate__animated', 'animate__pulse');
            }, 1000);
        } else {
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;
            timerText.textContent = `Resend available in ${minutes > 0 ? minutes + ':' : ''}${seconds.toString().padStart(2, '0')}s`;
            timeLeft--;
        }
    }, 1000);
}

function setupOtpInputs() {
    const boxes = document.querySelectorAll('.otp-box');
    
    // Clear all boxes and remove error states
    boxes.forEach(box => {
        box.value = '';
        box.classList.remove('error');
    });
    
    // Add input event listeners
    boxes.forEach((box, index) => {
        // Remove existing listeners to avoid duplicates
        const newBox = box.cloneNode(true);
        box.parentNode.replaceChild(newBox, box);
        
        newBox.addEventListener('input', (e) => {
            // Only allow digits
            e.target.value = e.target.value.replace(/[^0-9]/g, '');
            e.target.classList.remove('error');
            
            if (e.target.value.length === 1 && index < boxes.length - 1) {
                const nextBox = document.querySelectorAll('.otp-box')[index + 1];
                if (nextBox) nextBox.focus();
            }
            
            // Check if all boxes are filled
            const currentBoxes = document.querySelectorAll('.otp-box');
            let allFilled = true;
            currentBoxes.forEach(b => {
                if (!b.value) allFilled = false;
            });
            
            if (allFilled) {
                const otp = getOtpValue();
                verifyOtp(otp);
            }
        });
        
        newBox.addEventListener('keydown', (e) => {
            const currentBoxes = document.querySelectorAll('.otp-box');
            if (e.key === 'Backspace' && !newBox.value && index > 0) {
                const prevBox = currentBoxes[index - 1];
                if (prevBox) {
                    prevBox.focus();
                    prevBox.value = '';
                }
            }
        });
        
        // Add paste support
        newBox.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedData = e.clipboardData.getData('text').slice(0, 6);
            const pastedDigits = pastedData.replace(/[^0-9]/g, '').split('');
            
            const currentBoxes = document.querySelectorAll('.otp-box');
            pastedDigits.forEach((digit, i) => {
                if (currentBoxes[i]) {
                    currentBoxes[i].value = digit;
                }
            });
            
            // Check if all boxes are filled
            let allFilled = true;
            currentBoxes.forEach(b => {
                if (!b.value) allFilled = false;
            });
            
            if (allFilled) {
                const otp = getOtpValue();
                verifyOtp(otp);
            } else {
                // Focus the first empty box
                const firstEmpty = Array.from(currentBoxes).find(b => !b.value);
                if (firstEmpty) firstEmpty.focus();
            }
        });
        
        // Update the boxes reference
        const updatedBoxes = document.querySelectorAll('.otp-box');
        boxes[index] = updatedBoxes[index];
    });
    
    // Focus first box
    const firstBox = document.querySelector('.otp-box');
    if (firstBox) {
        setTimeout(() => firstBox.focus(), 100);
    }
}

function getOtpValue() {
    const boxes = document.querySelectorAll('.otp-box');
    let otp = '';
    boxes.forEach(box => {
        otp += box.value;
    });
    return otp;
}

function verifyOtp(otp) {
    // Show loading indicator
    const loadingIndicator = document.getElementById('otpLoadingIndicator');
    const otpBoxes = document.getElementById('otpBoxes');
    const resendBtn = document.getElementById('resendBtn');
    
    loadingIndicator.style.display = 'block';
    otpBoxes.style.opacity = '0.5';
    if (resendBtn) resendBtn.disabled = true;
    
    fetch('/verify-otp', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            email: currentEmail,
            password: currentPassword,
            otp: otp
        })
    })
    .then(async response => {
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.message || 'Verification failed');
        }
        return data;
    })
    .then(data => {
        if (data.success) {
            // Show success message
            showSuccessAndRedirect();
        } else {
            throw new Error(data.message || 'Invalid OTP');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification(error.message, 'error');
        
        // Clear OTP boxes and show error
        const boxes = document.querySelectorAll('.otp-box');
        boxes.forEach(box => {
            box.value = '';
            box.classList.add('error');
        });
        
        // Remove error class after animation
        setTimeout(() => {
            boxes.forEach(box => {
                box.classList.remove('error');
            });
        }, 500);
        
        const firstBox = document.querySelector('.otp-box');
        if (firstBox) firstBox.focus();
    })
    .finally(() => {
        loadingIndicator.style.display = 'none';
        otpBoxes.style.opacity = '1';
        const resendBtn = document.getElementById('resendBtn');
        if (resendBtn) resendBtn.disabled = false;
    });
}

function showSuccessAndRedirect() {
    const modalContent = document.querySelector('#otpModal .modal-content');
    const originalContent = modalContent.innerHTML;
    
    // Create success animation
    modalContent.innerHTML = `
        <div class="text-center p-5">
            <div class="success-animation mb-4">
                <svg width="80" height="80" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="12" cy="12" r="10" stroke="#10b981" stroke-width="2" fill="white"/>
                    <path d="M8 12L11 15L16 9" stroke="#10b981" stroke-width="2" stroke-linecap="round"/>
                </svg>
            </div>
            <h5 class="fw-bold text-success mb-3">Registration Successful!</h5>
            <p class="text-muted">Redirecting you to login page...</p>
            <div class="spinner-border text-success mt-3" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;
    
    // Add success animation style
    const style = document.createElement('style');
    style.textContent = `
        .success-animation {
            animation: checkmark 0.5s ease-in-out forwards;
        }
        @keyframes checkmark {
            0% {
                transform: scale(0);
                opacity: 0;
            }
            50% {
                transform: scale(1.2);
            }
            100% {
                transform: scale(1);
                opacity: 1;
            }
        }
    `;
    document.head.appendChild(style);
    
    // Close modal after 2 seconds and redirect
    setTimeout(() => {
        otpModal.hide();
        window.location.href = '/login?registered=true';
    }, 2000);
}

function resendOtp() {
    if (!currentEmail) {
        showNotification('Please enter your email first', 'error');
        return;
    }
    
    const resendBtn = document.getElementById('resendBtn');
    const originalText = resendBtn.innerHTML;
    resendBtn.disabled = true;
    resendBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Sending...';
    
    fetch('/resend-otp', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            email: currentEmail
        })
    })
    .then(async response => {
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.message || 'Failed to resend OTP');
        }
        return data;
    })
    .then(data => {
        if (data.success) {
            showNotification('OTP resent successfully! Check your email.', 'success');
            startTimer(); // Reset timer
            setupOtpInputs(); // Reset OTP inputs
        } else {
            throw new Error(data.message || 'Failed to resend OTP');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification(error.message, 'error');
        startTimer(); // Still reset timer
    })
    .finally(() => {
        resendBtn.disabled = false;
        resendBtn.innerHTML = originalText;
    });
}

// Helper function for notifications
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type === 'error' ? 'danger' : 'success'} alert-dismissible fade show position-fixed`;
    notification.style.cssText = `
        top: 20px;
        right: 20px;
        z-index: 9999;
        min-width: 300px;
        animation: slideInRight 0.3s ease-out;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    `;
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after 3 seconds
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Close modal and cleanup when hidden
document.getElementById('otpModal').addEventListener('hidden.bs.modal', function () {
    if (timerInterval) {
        clearInterval(timerInterval);
    }
    
    // Clear OTP inputs
    const boxes = document.querySelectorAll('.otp-box');
    boxes.forEach(box => {
        box.value = '';
    });
    
    // Reset timer display
    const timerSection = document.getElementById('timerSection');
    const resendBtn = document.getElementById('resendBtn');
    if (timerSection) timerSection.style.display = 'inline-flex';
    if (resendBtn) resendBtn.style.display = 'none';
});