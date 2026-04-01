document.addEventListener("DOMContentLoaded", function () {

    /* ===== Account Dropdown ===== */
    const btn = document.getElementById("accountBtn");
    const menu = document.getElementById("accountMenu");

    if (btn && menu) {
        btn.addEventListener("click", function () {
            menu.style.display =
                menu.style.display === "block" ? "none" : "block";
        });

        window.addEventListener("click", function (e) {
            if (!e.target.closest(".account")) {
                menu.style.display = "none";
            }
        });
    }

    /* ===== Password Strength Bar ===== */
    const passwordInput = document.getElementById("passwordInput");
    const strengthFill = document.getElementById("strengthFill");
    const strengthText = document.getElementById("strengthText");

    if (passwordInput && strengthFill && strengthText) {

        passwordInput.addEventListener("input", function () {

            const value = passwordInput.value;
            let score = 0;

            if (value.length >= 8) score++;
            if (/[A-Z]/.test(value)) score++;
            if (/[0-9]/.test(value)) score++;
            if (/[^A-Za-z0-9]/.test(value)) score++;

            const percent = (score / 4) * 100;
            strengthFill.style.width = percent + "%";

            if (score <= 1) {
                strengthFill.style.background = "red";
                strengthText.innerText = "Weak Password";
            }
            else if (score == 2) {
                strengthFill.style.background = "orange";
                strengthText.innerText = "Medium Password";
            }
            else if (score == 3) {
                strengthFill.style.background = "#3b82f6";
                strengthText.innerText = "Strong Password";
            }
            else {
                strengthFill.style.background = "#10b981";
                strengthText.innerText = "Very Strong Password";
            }

        });
    }

});

function openEditModal(id, service, category, password) {

    document.getElementById("editModal").style.display = "block";

    document.getElementById("editService").value = service;
    document.getElementById("editCategory").value = category;
    document.getElementById("editPassword").value = password;

    document.getElementById("editForm").action = "/edit/" + id;
}

function closeEditModal() {
    document.getElementById("editModal").style.display = "none";
}

window.onclick = function(e) {
    const modal = document.getElementById("editModal");
    if (e.target == modal) {
        modal.style.display = "none";
    }
}
function togglePassword(inputId, element) {

    const input = document.getElementById(inputId);

    if (input.type === "password") {
        input.type = "text";
        element.textContent = "🙈";
    } else {
        input.type = "password";
        element.textContent = "👁";
    }

}

function toggleTablePassword(id, realPassword, element) {

    const span = document.getElementById("pass-" + id);

    if (span.textContent === "••••••••") {
        span.textContent = realPassword;
        element.textContent = "🙈";
    } else {
        span.textContent = "••••••••";
        element.textContent = "👁";
    }
}
document.addEventListener("DOMContentLoaded", function () {

    setTimeout(() => {
        const flash = document.querySelector(".flash-message");
        if (flash) {
            flash.style.transition = "opacity 0.5s ease";
            flash.style.opacity = "0";
            setTimeout(() => flash.remove(), 500);
        }
    }, 3000);

});