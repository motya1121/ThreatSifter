#!/usr/bin/env python3
"""Fetch a web page, falling back to curl_cffi if curl fails."""

import subprocess
import sys

from curl_cffi import requests as cffi_requests

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)


def fetch_with_curl(url: str) -> str | None:
    result = subprocess.run(
        ["curl", "-s", "-L", "-A", UA, "-w", "\n%{http_code}", url],
        capture_output=True,
        text=True,
    )
    *body_lines, status_code = result.stdout.rsplit("\n", 1)
    if result.returncode == 0 and status_code.strip() == "200":
        return "\n".join(body_lines)
    return None


def fetch_with_cffi(url: str) -> str:
    response = cffi_requests.get(url, impersonate="chrome")
    response.raise_for_status()
    return response.text


def fetch(url: str) -> str:
    html = fetch_with_curl(url)
    if html is not None:
        return html
    return fetch_with_cffi(url)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: fetch_page.py <URL>", file=sys.stderr)
        sys.exit(1)
    print(fetch(sys.argv[1]))
