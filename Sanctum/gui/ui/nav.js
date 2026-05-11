document.addEventListener("DOMContentLoaded", function() {
    // ── Navigation Loading ──────────────────────────────────
    fetch("nav.html")
        .then(response => response.text())
        .then(data => {
            document.getElementById("nav-placeholder").innerHTML = data;
        })
        .catch(error => console.error("Error loading navigation:", error));

    // ── Theme Management ────────────────────────────────────
    const body = document.body;
    const header = document.getElementById("header");
    
    // SVG Icons
    const dayIcon = `<svg xmlns="http://www.w3.org/2000/svg" height="20px" viewBox="0 -960 960 960" width="20px" fill="currentColor"><path d="M480-28 346-160H160v-186L28-480l132-134v-186h186l134-132 134 132h186v186l132 134-132 134v186H614L480-28Zm141.5-310.5Q680-397 680-480t-58.5-141.5Q563-680 480-680t-141.5 58.5Q280-563 280-480t58.5 141.5Q397-280 480-280t141.5-58.5ZM480-480Zm0 340 100-100h140v-140l100-100-100-100v-140H580L480-820 380-720H240v140L140-480l100 100v140h140l100 100Zm0-340Z"/></svg>`;
    const nightIcon = `<svg xmlns="http://www.w3.org/2000/svg" height="20px" viewBox="0 -960 960 960" width="20px" fill="currentColor"><path d="M380-160q133 0 226.5-93.5T700-480q0-133-93.5-226.5T380-800h-21q-10 0-19 2 57 66 88.5 147.5T460-480q0 89-31.5 170.5T340-162q9 2 19 2h21Zm0 80q-53 0-103.5-13.5T180-134q93-54 146.5-146T380-480q0-108-53.5-200T180-826q46-27 96.5-40.5T380-880q83 0 156 31.5T663-763q54 54 85.5 127T780-480q0 83-31.5 156T663-197q-54 54-127 85.5T380-80Zm80-400Z"/></svg>`;

    // Load theme from localStorage
    const currentTheme = localStorage.getItem("sanctum-theme") || "dark";
    if (currentTheme === "light") {
        body.classList.add("light-theme");
    }

    // Inject Theme Toggle Button into Header
    if (header) {
        const toggleContainer = document.createElement("div");
        toggleContainer.className = "theme-toggle-container";
        toggleContainer.innerHTML = `
            <button class="theme-toggle-btn" id="theme-toggle" title="Toggle Light/Dark Mode">
                ${currentTheme === "light" ? nightIcon : dayIcon}
            </button>
        `;
        header.appendChild(toggleContainer);

        const toggleBtn = document.getElementById("theme-toggle");
        toggleBtn.addEventListener("click", () => {
            const isLight = body.classList.toggle("light-theme");
            const newTheme = isLight ? "light" : "dark";
            
            // Update button icon
            toggleBtn.innerHTML = isLight ? nightIcon : dayIcon;
            
            // Save to localStorage
            localStorage.setItem("sanctum-theme", newTheme);
            
            console.log(`Theme switched to: ${newTheme}`);
        });
    }
});
