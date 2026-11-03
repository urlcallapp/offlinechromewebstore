"""Regression tests for the redesigned storefront templates."""
from conftest import TAMPERMONKEY_ID, TRANSLATE_ID


def test_homepage_uses_shared_shell(store_client, built_index):
    html = store_client.get("/").text
    # sticky header with labeled search and theme toggle
    assert 'class="site-header"' in html
    assert 'aria-label="Search extensions"' in html
    assert 'aria-label="Switch theme"' in html
    # theme applied before first paint, honoring saved preference / OS theme
    assert "prefers-color-scheme" in html
    assert "localStorage.getItem('theme')" in html
    # keyboard and screen-reader affordances
    assert 'class="skip-link" href="#main"' in html
    assert 'id="main"' in html


def test_homepage_drops_runtime_css_compiler(store_client, built_index):
    """The 400KB in-browser Tailwind compiler must not come back."""
    html = store_client.get("/").text
    assert "tailwindcss" not in html
    assert "cdn.tailwindcss.com" not in html


def test_homepage_cards_carry_search_data(store_client, built_index):
    html = store_client.get("/").text
    assert 'data-name="tampermonkey"' in html
    assert f'data-id="{TAMPERMONKEY_ID}"' in html
    assert 'id="visibleCount"' in html
    assert 'id="noResults"' in html


def test_download_buttons_say_download_not_install(store_client, built_index):
    """Buttons fetch a .crx file; they cannot install it. Say so."""
    for url in ("/", f"/extension/{TAMPERMONKEY_ID}"):
        html = store_client.get(url).text
        assert "Download .crx" in html
        assert "Add to Chrome" not in html


def test_card_primary_action_uses_guarded_download_route(store_client, built_index):
    html = store_client.get("/").text
    assert f'href="/download/{TAMPERMONKEY_ID}"' in html


def test_detail_page_structure(store_client, built_index):
    html = store_client.get(f"/extension/{TAMPERMONKEY_ID}").text
    assert 'class="detail-hero"' in html
    assert 'href="/"' in html  # back link to the storefront
    assert 'class="version-list"' in html
    # the hero badge shows the newest version (versions[0], builder-sorted)
    assert "v5.3.3" in html
    # per-version rows link to the guarded artifact route
    assert (
        f'href="/artifacts/extensions/{TAMPERMONKEY_ID}/5.3.3/'
        f'{TAMPERMONKEY_ID}_Tampermonkey_5.3.3.crx"' in html
    )


def test_detail_page_uses_shared_shell(store_client, built_index):
    html = store_client.get(f"/extension/{TRANSLATE_ID}").text
    assert 'class="site-header"' in html
    assert "tailwindcss" not in html


def test_storefront_scripts_served(store_client, built_index):
    response = store_client.get("/static/js/scripts.js")
    assert response.status_code == 200
    assert "initSearch" in response.text
    assert "initThemeToggle" in response.text


def test_removed_tailwind_runtime_is_gone(store_client, built_index):
    assert store_client.get("/static/js/tailwindcss_3.4.16.js").status_code == 404
