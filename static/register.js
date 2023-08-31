const passwordField = document.getElementById("password");
const passwordStatus = document.getElementById("password-status");

passwordField.addEventListener("input", () => {
    const password = passwordField.value;
    if (
        password.length < 6
        || !/[A-Z]/.test(password)
        || !/[0-9!@#$%^&*()_+]/.test(password)
    ) {
        passwordStatus.textContent = "Password must be at least 6 characters long, contain at least one uppercase letter, and one digit or special symbol.";
        passwordStatus.style.color = "red";
    } else {
        passwordStatus.textContent = "";
    }
});
