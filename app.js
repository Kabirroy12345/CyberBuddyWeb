document.addEventListener("DOMContentLoaded", function () {
    const chatBox = document.getElementById("chat-box");
    const userInput = document.getElementById("user-input");
    const sendBtn = document.getElementById("send-btn");
    const verifyBtn = document.getElementById("verify-link-btn");
    const reportBtn = document.getElementById("report-link-btn");
    const passwordInput = document.getElementById("password-input");
    const checkPasswordBtn = document.getElementById("check-password-btn");
    const strengthFill = document.getElementById("strength-fill");
    const passwordResult = document.getElementById("password-result");
    const passwordFeedback = document.getElementById("password-feedback");
    const historyList = document.getElementById("history-list");

    // Load stats and history on page load
    loadStats();
    loadHistory();

    // Auto-refresh stats every 30 seconds
    setInterval(loadStats, 30000);

    // Handle Enter key in chat input
    userInput.addEventListener("keypress", function (event) {
        if (event.key === "Enter") {
            event.preventDefault();
            sendBtn.click();
        }
    });

    // Handle Enter key in password input
    passwordInput.addEventListener("keypress", function (event) {
        if (event.key === "Enter") {
            event.preventDefault();
            checkPasswordBtn.click();
        }
    });

    function appendMessage(type, message, status = '') {
        const messageDiv = document.createElement("div");
        messageDiv.className = `message ${type === 'user' ? 'user-message' : 'bot-message'}`;
        if (status) {
            messageDiv.classList.add(status.toLowerCase());
        }
        messageDiv.innerHTML = message;
        chatBox.appendChild(messageDiv);
        chatBox.scrollTop = chatBox.scrollHeight;
    }

    function showLoading() {
        const loadingDiv = document.createElement("div");
        loadingDiv.className = "message bot-message loading-message";
        loadingDiv.innerHTML = '<span class="loading">⏳ Analyzing...</span>';
        loadingDiv.id = "loading-indicator";
        chatBox.appendChild(loadingDiv);
        chatBox.scrollTop = chatBox.scrollHeight;
    }

    function hideLoading() {
        const loading = document.getElementById("loading-indicator");
        if (loading) loading.remove();
    }

    // Load Statistics
    function loadStats() {
        fetch("/stats")
            .then(response => response.json())
            .then(data => {
                document.getElementById("total-scans").textContent = data.total_scans || 0;
                document.getElementById("safe-urls").textContent = data.safe_urls || 0;
                document.getElementById("threats-detected").textContent = data.threats_detected || 0;
                document.getElementById("reported-links").textContent = data.reported_links || 0;
                document.getElementById("password-checks").textContent = data.password_checks || 0;
            })
            .catch(err => console.log("Stats error:", err));
    }

    // Load Scan History
    function loadHistory() {
        fetch("/history")
            .then(response => response.json())
            .then(data => {
                if (data.history && data.history.length > 0) {
                    historyList.innerHTML = data.history.map(item => `
                        <div class="history-item">
                            <div class="url">${truncateUrl(item.url)}</div>
                            <div class="meta">
                                <span class="status ${item.result.toLowerCase()}">${item.result}</span>
                                <span>${formatTime(item.timestamp)}</span>
                            </div>
                        </div>
                    `).join('');
                }
            })
            .catch(err => console.log("History error:", err));
    }

    function truncateUrl(url) {
        return url.length > 40 ? url.substring(0, 40) + '...' : url;
    }

    function formatTime(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    // Send Chat Message
    sendBtn.addEventListener("click", function () {
        const message = userInput.value.trim();
        if (message) {
            appendMessage('user', message);
            showLoading();

            fetch("/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message })
            })
                .then(response => response.json())
                .then(data => {
                    hideLoading();
                    // Format the response with proper line breaks
                    const formattedResponse = data.response
                        .replace(/\n/g, '<br>')
                        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                        .replace(/\*(.*?)\*/g, '<em>$1</em>');
                    appendMessage('bot', formattedResponse);
                })
                .catch(() => {
                    hideLoading();
                    appendMessage('bot', "⚠️ Error connecting to server. Please try again.");
                });

            userInput.value = "";
        }
    });

    // Verify URL
    verifyBtn.addEventListener("click", function () {
        const link = prompt("🔍 Enter the URL to scan for threats:");
        if (link) {
            appendMessage('user', `🔍 Scanning: ${link}`);
            showLoading();

            fetch("/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ link })
            })
                .then(response => response.json())
                .then(data => {
                    hideLoading();

                    let status = data.status || 'SAFE';
                    let detailedMessage = `<strong>${data.message}</strong>`;

                    if (data.risk_score !== undefined) {
                        detailedMessage += `<br><br>📊 <strong>Risk Score:</strong> ${data.risk_score}/100`;
                    }

                    if (data.analysis) {
                        // Parse and display key parts of analysis
                        const analysisLines = data.analysis.split('\n').filter(l => l.trim());
                        const relevantLines = analysisLines.filter(l =>
                            l.includes('THREATS:') || l.includes('RECOMMENDATION:')
                        );
                        if (relevantLines.length > 0) {
                            detailedMessage += '<br><br>' + relevantLines.join('<br>');
                        }
                    }

                    appendMessage('bot', detailedMessage, status);
                    loadStats();
                    loadHistory();
                })
                .catch(() => {
                    hideLoading();
                    appendMessage('bot', "⚠️ Error scanning URL. Please try again.");
                });
        }
    });

    // Report Suspicious Link
    reportBtn.addEventListener("click", function () {
        const link = prompt("🚨 Enter the suspicious URL to report:");
        if (link) {
            const username = prompt("👤 Enter your username:");
            if (username) {
                const threatType = prompt("📋 Type of threat (phishing/malware/scam/other):", "phishing");

                appendMessage('user', `🚨 Reporting: ${link}`);
                showLoading();

                fetch("/report", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ link, username, threat_type: threatType })
                })
                    .then(response => response.json())
                    .then(data => {
                        hideLoading();
                        appendMessage('bot', data.message);
                        loadStats();
                    })
                    .catch(() => {
                        hideLoading();
                        appendMessage('bot', "⚠️ Error reporting link. Please try again.");
                    });
            } else {
                appendMessage('bot', "❌ Reporting cancelled: Username is required.");
            }
        }
    });

    // Password Strength Analyzer
    checkPasswordBtn.addEventListener("click", function () {
        const password = passwordInput.value;
        if (!password) {
            passwordResult.innerHTML = '⚠️ Please enter a password';
            return;
        }

        fetch("/analyze-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password })
        })
            .then(response => response.json())
            .then(data => {
                // Update strength meter
                strengthFill.className = 'strength-fill';
                if (data.strength === 'STRONG') {
                    strengthFill.classList.add('strong');
                } else if (data.strength === 'GOOD') {
                    strengthFill.classList.add('good');
                } else if (data.strength === 'MODERATE') {
                    strengthFill.classList.add('moderate');
                } else {
                    strengthFill.classList.add('weak');
                }

                // Update result message
                passwordResult.innerHTML = `${data.message}<br>Score: ${data.score}/100`;

                // Update feedback
                if (data.feedback && data.feedback.length > 0) {
                    passwordFeedback.innerHTML = data.feedback.map(f => `<li>${f}</li>`).join('');
                } else {
                    passwordFeedback.innerHTML = '<li>✅ All requirements met!</li>';
                }

                loadStats();
            })
            .catch(() => {
                passwordResult.innerHTML = '⚠️ Error analyzing password';
            });
    });

    // Real-time password strength preview
    passwordInput.addEventListener("input", function () {
        const password = this.value;
        if (password.length === 0) {
            strengthFill.className = 'strength-fill';
            return;
        }

        // Quick client-side preview
        let score = 0;
        if (password.length >= 8) score += 25;
        if (password.length >= 12) score += 15;
        if (/[a-z]/.test(password)) score += 15;
        if (/[A-Z]/.test(password)) score += 15;
        if (/\d/.test(password)) score += 15;
        if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 15;

        strengthFill.className = 'strength-fill';
        if (score >= 80) {
            strengthFill.classList.add('strong');
        } else if (score >= 60) {
            strengthFill.classList.add('good');
        } else if (score >= 40) {
            strengthFill.classList.add('moderate');
        } else {
            strengthFill.classList.add('weak');
        }
    });
});