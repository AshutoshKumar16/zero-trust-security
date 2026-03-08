/* ============================================
   ZERO TRUST SECURITY — Global JavaScript
   ============================================ */

// ---- SIDEBAR NAVIGATION ----
function showSection(name, el) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('sec-' + name).classList.add('active');
    el.classList.add('active');
}

// ---- PASSWORD STRENGTH METER ----
function initPasswordStrength(inputId, fillId, textId) {
    const input = document.getElementById(inputId);
    const fill  = document.getElementById(fillId);
    const text  = document.getElementById(textId);
    if (!input) return;

    input.addEventListener('input', function () {
        const val = this.value;
        let score = 0;
        if (val.length >= 8)  score++;
        if (val.length >= 12) score++;
        if (/[A-Z]/.test(val)) score++;
        if (/[0-9]/.test(val)) score++;
        if (/[^A-Za-z0-9]/.test(val)) score++;

        const levels = [
            { pct: '0%',   color: '#1e2040', label: 'Enter password to check strength' },
            { pct: '25%',  color: '#f43f5e', label: '🔴 Very Weak' },
            { pct: '50%',  color: '#fb923c', label: '🟠 Weak' },
            { pct: '75%',  color: '#facc15', label: '🟡 Medium' },
            { pct: '90%',  color: '#4ade80', label: '🟢 Strong' },
            { pct: '100%', color: '#22c55e', label: '✅ Very Strong' },
        ];

        const level = val.length === 0 ? levels[0] : levels[Math.min(score, 5)];
        fill.style.width      = level.pct;
        fill.style.background = level.color;
        text.textContent      = level.label;
        text.style.color      = level.color;
    });
}

// ---- TYPING DETECTION ----
function initTypingDetection(passwordInputId, indicatorId, speedInputId, patternInputId, pasteInputId) {
    const passwordInput    = document.getElementById(passwordInputId);
    const typingIndicator  = document.getElementById(indicatorId);
    const typingSpeedInput = document.getElementById(speedInputId);
    const typingPatternInput = document.getElementById(patternInputId);
    const isPasteInput     = document.getElementById(pasteInputId);
    if (!passwordInput) return;

    let intervals = [];
    let lastKeyTime = null;
    let pasteDetected = false;

    // Normal keyboard typing
    passwordInput.addEventListener('keydown', function (e) {
        const now = Date.now();
        if (lastKeyTime !== null) {
            const interval = now - lastKeyTime;
            if (interval < 5000) intervals.push(interval);
        }
        lastKeyTime = now;
        if (intervals.length >= 3) analyzeTyping();
    });

    // Paste detection
    passwordInput.addEventListener('paste', function () {
        pasteDetected = true;
        isPasteInput.value = "1";
        typingSpeedInput.value = "0";
        typingPatternInput.value = JSON.stringify({ avg: 0, min: 0, max: 0, variance: 0, count: 0, paste: true });
        setIndicator('info', '📋 Password pasted (analyzing context...)');
    });

    // Reset on clear
    passwordInput.addEventListener('input', function () {
        if (this.value.length === 0) {
            intervals = []; lastKeyTime = null; pasteDetected = false;
            isPasteInput.value = "0";
            typingSpeedInput.value = '';
            typingPatternInput.value = '';
            setIndicator('', 'Start typing to analyze...');
        }
    });

    function analyzeTyping() {
        if (pasteDetected) return;
        if (intervals.length < 2) return;

        const avg      = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const minI     = Math.min(...intervals);
        const maxI     = Math.max(...intervals);
        const variance = intervals.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / intervals.length;

        typingSpeedInput.value   = Math.round(avg);
        typingPatternInput.value = JSON.stringify({
            avg: Math.round(avg), min: minI, max: maxI,
            variance: Math.round(variance), count: intervals.length, paste: false
        });

        if (avg < 50 || minI < 20) {
            setIndicator('danger', `⚠️ Bot-like speed (${Math.round(avg)}ms)`);
        } else if (avg >= 50 && avg <= 800) {
            setIndicator('safe', `✅ Normal typing (${Math.round(avg)}ms)`);
        } else {
            setIndicator('warning', `⚠️ Slow typing (${Math.round(avg)}ms)`);
        }
    }

    function setIndicator(cls, msg) {
        typingIndicator.className = 'typing-indicator' + (cls ? ' ' + cls : '');
        typingIndicator.querySelector('.typing-text').textContent = msg;
    }
}