import os

import pytest
from playwright.sync_api import sync_playwright

BASE_URL = os.getenv("PLAYWRIGHT_BASE_URL")


@pytest.mark.skipif(not BASE_URL, reason="Set PLAYWRIGHT_BASE_URL to run browser tests")
def test_one_page_simulation_login_welcome_and_logout() -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(BASE_URL)
        page.get_by_role("heading", name="Sign in to continue").wait_for()
        assert page.locator("#panel-sign-in").is_visible()
        assert page.locator("#panel-dashboard").is_visible()
        assert page.locator("#panel-simulation").is_visible()

        page.get_by_role("link", name="Risk lab").click()
        page.get_by_role("button", name="Headless script").click()
        page.get_by_role("button", name="Evaluate scenario").click()
        page.get_by_role("heading", name="Block this browser request").wait_for()
        page.locator(".trace-entry").filter(has_text="[backend/policy]").wait_for()

        page.get_by_role("link", name="Sign in").click()
        page.get_by_role("button", name="Enter local demo").click()

        page.get_by_role("heading", name="Welcome, Demo User").wait_for()
        page.get_by_role("button", name="Sign out").click()
        page.wait_for_url("**/#sign-in")
        page.goto(f"{BASE_URL}/")
        page.get_by_role("link", name="Sign in").wait_for()
        page.get_by_role("link", name="Dashboard").click()
        page.get_by_role("heading", name="Bot protection").wait_for()

        browser.close()
