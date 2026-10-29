# Reynard Authenticator

A Firefox and Chrome extension that stores time-based 2FA (TOTP) secrets and generates codes entirely on your computer.

## Install in Chrome

Open `chrome://extensions`, turn on **Developer mode** (top right), click **Load unpacked** and pick this folder. It stays installed across restarts. Chrome ignores the Firefox-only `browser_specific_settings` key in the manifest and lists it under **Errors**; that warning is harmless. Edge and other Chromium browsers work the same way.

## Install in Firefox

**Try it (until Firefox restarts):** open `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on…** → pick `manifest.json` in this folder.

**Keep it installed:** release Firefox only installs signed add-ons. Either
- sign it for yourself (not publicly listed): `npx web-ext sign --channel=unlisted --api-key=… --api-secret=…` using keys from addons.mozilla.org → Developer Hub → API keys, then open the resulting `.xpi` in Firefox; or
- use Firefox Developer Edition / Nightly, set `xpinstall.signatures.required` to `false` in `about:config`, and install a zip of this folder (`npx web-ext build`).

## Use

- Click the toolbar icon. **+** adds an account: paste the `otpauth://` link, or type the secret key the site shows under "can't scan the QR code?".
- Click a code (or press Enter in the search box) to copy it.
- The sliders button opens settings: set a password to encrypt your secrets, download backups, import backups or `otpauth://` lists.

## Privacy

- The manifest asks for one permission, `storage`, which is this add-on's own private storage area. It grants no access to tabs, pages, history or other data, and neither browser shows a permission prompt for it.
- If you want literally zero permissions, delete the `"permissions"` line from `manifest.json`. The add-on then falls back to its page's `localStorage`. Be aware that the browser wipes that whenever you clear cookies and site data, along with your secrets.
- The Content Security Policy blocks every network connection (`connect-src 'none'`), and there are no third-party libraries.
- With a password set, the vault is encrypted with AES-256-GCM using a PBKDF2-SHA256 key (600,000 iterations). After you unlock it, the key is kept in memory (`storage.session`) until you lock it, quit the browser, or leave it unused longer than the auto-lock time in settings (5 minutes by default).
- Without a password, secrets are stored unencrypted in your browser profile.

## Not currently supported

- Scanning QR codes.
- HOTP (counter-based) codes.

## License

MIT. See [LICENSE](LICENSE).
