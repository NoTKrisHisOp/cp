// Function to apply dark mode
function applyDarkMode(isDark) {
  if (isDark) {
    document.body.classList.add("dark");
    const modeToggle = document.getElementById("modeToggle");
    if (modeToggle) {
      modeToggle.textContent = "🌙";
    }
  } else {
    document.body.classList.remove("dark");
    const modeToggle = document.getElementById("modeToggle");
    if (modeToggle) {
      modeToggle.textContent = "☀️";
    }
  }
}

// Check for saved preference on load
const savedDarkMode = localStorage.getItem("darkMode");
if (savedDarkMode === "true") {
  applyDarkMode(true);
} else {
  applyDarkMode(false);
}

// Event listener for the toggle button (if it exists on the page)
document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("modeToggle");
  if (toggle) {
    toggle.addEventListener("click", () => {
      const isDark = document.body.classList.toggle("dark");
      applyDarkMode(isDark);
      localStorage.setItem("darkMode", isDark);
    });
  }
});