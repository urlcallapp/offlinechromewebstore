// Storefront interactivity: theme toggle and live search filtering.
// Everything works without this file too: pages are server-rendered and
// downloads are plain links, so a no-JS browser still gets a usable store.

document.addEventListener("DOMContentLoaded", function () {
    initThemeToggle();
    initSearch();
});

function initThemeToggle() {
    const toggle = document.getElementById("themeToggle");
    if (!toggle) return;

    const applyLabel = function (theme) {
        toggle.setAttribute(
            "aria-label",
            theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
        );
    };
    applyLabel(document.documentElement.getAttribute("data-theme"));

    toggle.addEventListener("click", function () {
        const next =
            document.documentElement.getAttribute("data-theme") === "dark"
                ? "light"
                : "dark";
        document.documentElement.setAttribute("data-theme", next);
        try {
            localStorage.setItem("theme", next);
        } catch (e) {
            /* private mode: theme just won't persist */
        }
        applyLabel(next);
    });
}

function initSearch() {
    const input = document.getElementById("searchInput");
    if (!input) return;

    const grid = document.getElementById("extensionsGrid");

    // Pages without a grid (e.g. the extension detail page): Enter takes the
    // query back to the storefront, which applies it on load.
    if (!grid) {
        input.addEventListener("keydown", function (event) {
            if (event.key === "Enter" && input.value.trim()) {
                window.location.href = "/?q=" + encodeURIComponent(input.value.trim());
            }
        });
        return;
    }

    const cards = Array.prototype.slice.call(grid.querySelectorAll(".extension-card"));
    const visibleCount = document.getElementById("visibleCount");
    const noResults = document.getElementById("noResults");
    const noResultsTerm = document.getElementById("noResultsTerm");

    const applyFilter = function (term) {
        let shown = 0;
        cards.forEach(function (card) {
            const haystack =
                card.getAttribute("data-name") +
                " " +
                card.getAttribute("data-description") +
                " " +
                card.getAttribute("data-id");
            const match = haystack.indexOf(term) !== -1;
            card.hidden = !match;
            if (match) shown += 1;
        });
        if (visibleCount) visibleCount.textContent = shown;
        if (noResults) {
            noResults.hidden = shown !== 0;
            if (shown === 0 && noResultsTerm) noResultsTerm.textContent = input.value;
        }
    };

    input.addEventListener("input", function () {
        applyFilter(input.value.trim().toLowerCase());
    });

    // "/" focuses search from anywhere, mirroring common store UX.
    document.addEventListener("keydown", function (event) {
        if (
            event.key === "/" &&
            document.activeElement !== input &&
            !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)
        ) {
            event.preventDefault();
            input.focus();
        }
    });

    // Deep link: /?q=adblock pre-applies a search (used from detail pages).
    const params = new URLSearchParams(window.location.search);
    const initial = params.get("q");
    if (initial) {
        input.value = initial;
        applyFilter(initial.trim().toLowerCase());
    }
}
