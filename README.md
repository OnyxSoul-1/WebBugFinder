# WebBugFinder (WBF)

Static web-bug scanner. Two delivery modes:
- bookmarklet (`wbf-bm.js`) — click on any page, overlay panel opens
- Chrome MV3 extension (`webbugfinder-ext/`) — toolbar icon, toggles panel
- CLI scanner (`wbf.py` + `trackers.json`) — fetch a URL, JSON report

Flags: no-HTTPS, no CSP, inline scripts, document.write, eval, innerHTML,
HTTP form actions, password on non-HTTPS, target=_blank without rel=noopener,
3rd-party scripts without SRI, redirect-ish URL params, sensitive path links,
comment leaks, exposed source maps.

## Bookmarklet

Bookmark URL (one line):

    javascript:(function(){var s=document.createElement('script');s.src='https://cdn.jsdelivr.net/gh/OnyxSoul-1/WebBugFinder@main/wbf-bm.js';document.body.appendChild(s)})();

Or paste the contents of `wbf-bm.js` inline (fallback when CSP blocks remote load).

## Extension

    chrome://extensions -> Developer mode -> Load unpacked -> webbugfinder-ext/

Click the toolbar icon on any page.

## CLI

    pip install -r requirements.txt
    python3 wbf.py https://example.com --json --out report.json
    python3 wbf.py --file saved_page.html

## Limits

Static analysis of the DOM at click time. Does not intercept fetch/XHR
beacons after load, does not execute new JS, cannot read response CSP headers
from page JS. Devtools Network tab for dynamic fidelity.
