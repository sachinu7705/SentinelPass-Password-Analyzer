document.addEventListener("DOMContentLoaded", function () {

    const passwordInput = document.getElementById("password");
    const strengthBar = document.getElementById("strength-bar");
    const resultsDiv = document.getElementById("results");

    if (!passwordInput) return;

    passwordInput.addEventListener("input", async function () {

        const password = this.value;

        if (!password) {
            strengthBar.style.width = "0%";
            resultsDiv.style.display = "none";
            resultsDiv.innerHTML = "";
            return;
        }

        try {
            const response = await fetch("/check", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password })
            });

            const data = await response.json();

            let percent = Math.min(data.entropy, 100);
            strengthBar.style.width = percent + "%";

            let label = "";
            let colorClass = "";

            if (data.entropy < 30) {
                label = "Very Weak";
                colorClass = "bg-danger";
            }
            else if (data.entropy < 50) {
                label = "Weak";
                colorClass = "bg-warning";
            }
            else if (data.entropy < 70) {
                label = "Good";
                colorClass = "bg-info";
            }
            else if (data.entropy < 90) {
                label = "Better";
                colorClass = "bg-primary";
            }
            else {
                label = "Very Strong";
                colorClass = "bg-success";
            }

            strengthBar.className = "progress-bar " + colorClass;

            resultsDiv.style.display = "block";

            resultsDiv.innerHTML = `
                <p><strong>Password Strength:</strong> ${label}</p>
                <p><strong>Entropy:</strong> ${data.entropy} bits</p>
                <p><strong>Crack Time:</strong> ${Math.round(data.crack_time_seconds)} seconds</p>
            `;

        } catch (error) {
            console.error("Error:", error);
        }

    });

});


// 👁 Show / Hide password
function togglePassword() {

    const input = document.getElementById("password");
    const button = event.target;

    if (!input) return;

    if (input.type === "password") {
        input.type = "text";
        button.innerText = "🙈";
    } else {
        input.type = "password";
        button.innerText = "👁";
    }
}


// 🔑 Generate Secure Password
async function generatePassword() {

    try {
        const response = await fetch("/generate");
        const data = await response.json();

        const input = document.getElementById("password");

        if (!input) return;

        input.value = data.password;

        // trigger strength check
        input.dispatchEvent(new Event("input"));

    } catch (error) {
        console.error("Generate Error:", error);
    }
}