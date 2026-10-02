# IOC Checker

A browser-based tool for SOC and DFIR work. Paste any mix of indicators, even defanged, and it sanitizes them, removes duplicates, labels each one, and opens searches on the threat intelligence platforms you choose. **No API keys. No backend. Nothing leaves your browser until you open a search.**

**Live version:** https://hahashem.github.io/ioc-checker/ *(after enabling GitHub Pages for this repo)*
**Also on my portfolio:** https://hahashem.github.io/intel.html

## What it does

- **Extracts** IPs (v4 and v6), domains, URLs, emails, CVEs, MD5/SHA1/SHA256 hashes, and **JA3, JA4 and JA4S** fingerprints from free text such as emails, reports and alerts
- **Refangs** defanged input (`hxxp`, `[.]`, `[@]`, `(.)`) and **defangs** output so you can share it safely
- **De-duplicates** and counts repeated indicators, and hides private/internal IP addresses by default
- **Searches** many platforms at once: VirusTotal, AbuseIPDB, GreyNoise, Cisco Talos, IBM X-Force, OTX, Shodan, Censys, urlscan, URLhaus, MalwareBazaar, Hybrid Analysis and more. You choose which platforms, per session
- **Saves a watchlist** in your browser, with JSON export and import and CSV export of results

## JA3 and MD5 look the same

A JA3 hash and an MD5 hash are both 32 hex characters, so no program can tell them apart from the text alone. Use the "32-char hex is MD5 / JA3" selector. JA4 has a distinct format and is detected automatically.

## Limits worth knowing

- JA3/JA4 lookups are limited on public platforms. Those links are search entry points, and some platforms need an account or a paid tier for fingerprint search.
- Opening a platform means **that platform sees the indicator**. Don't search confidential indicators on third-party sites.
- Browsers may block several tabs opened at once. Allow pop-ups for the page.
- It does not return verdicts. It takes you to the platforms that do.

## Run it

It is plain HTML, CSS and JavaScript with no build step.

```
python3 -m http.server 8000
# then open http://localhost:8000
```

## Tests

The parsing logic lives in `assets/ioc.js` and is tested with plain Node, no dependencies:

```
node tests/ioc.test.js
```

## Add or change a platform

Platform links are defined in the `pivots()` function in `assets/ioc.js`. Add an entry like `["Name", \`https://example.com/search?q=${e}\`]` under the relevant indicator type, and add the name to the `PREFERRED` list to control its position.

## License

[MIT](LICENSE)
