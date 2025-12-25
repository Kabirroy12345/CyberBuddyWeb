document.addEventListener("DOMContentLoaded", function () {
    const chatBox = document.getElementById("chat-box");
    const userInput = document.getElementById("user-input");
    const sendBtn = document.getElementById("send-btn");
    const verifyBtn = document.getElementById("verify-link-btn");
    const reportBtn = document.getElementById("report-link-btn");

    // Handle Enter key in input
    userInput.addEventListener("keypress", function(event) {
        if (event.key === "Enter") {
            event.preventDefault();
            sendBtn.click();
        }
    });

    function appendMessage(type, message) {
        const messageDiv = document.createElement("div");
        messageDiv.className = `message ${type === 'user' ? 'user-message' : 'bot-message'}`;
        messageDiv.textContent = message;
        chatBox.appendChild(messageDiv);
        chatBox.scrollTop = chatBox.scrollHeight;
    }

    sendBtn.addEventListener("click", function () {
        const message = userInput.value.trim();
        if (message) {
            appendMessage('user', message);
            fetch("/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message })
            })
            .then(response => response.json())
            .then(data => appendMessage('bot', data.response))
            .catch(() => appendMessage('bot', "Error connecting to server."));
            userInput.value = "";
        }
    });

    verifyBtn.addEventListener("click", function () {
        const link = prompt("Enter the link to verify:");
        if (link) {
            appendMessage('user', `Verifying link: ${link}`);
            fetch("/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ link })
            })
            .then(response => response.json())
            .then(data => appendMessage('bot', data.message))
            .catch(() => appendMessage('bot', "Verification failed."));
        }
    });

    reportBtn.addEventListener("click", function () {
        const link = prompt("Enter the suspicious link:");
        if (link) {
            const username = prompt("Enter your username:");
            if (username) {
                appendMessage('user', `Reporting suspicious link: ${link}`);
                fetch("/report", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ link, username })
                })
                .then(response => response.json())
                .then(data => appendMessage('bot', data.message))
                .catch(() => appendMessage('bot', "Reporting failed."));
            } else {
                appendMessage('bot', "❌ Reporting cancelled: Username is required.");
            }
        }
    });
});