# PhishingScope

PhishingScope is a polished static cybersecurity web app for analyzing suspicious emails, texts, and URLs for phishing behavior. It uses deterministic, rule-based logic to produce a risk score, verdict, detected red flags, plain-English explanation, and recommended next action.

## Files

- `index.html` - app structure and content
- `style.css` - dark cybersecurity visual design and responsive layout
- `script.js` - phishing detection logic and UI behavior

## How to Run on a MacBook

No build step is required.

1. Open the project folder.
2. Double-click `index.html`.

You can also open it from Terminal:

```bash
open /Users/lilyan/Documents/Playground/index.html
```

## Features

- Hero section and polished landing experience
- Analyzer for suspicious message text and URLs
- Rule-based risk score from `0` to `100`
- Verdicts: `Low Risk`, `Medium Risk`, `High Risk`
- Detection for:
  - urgent or threatening language
  - password, login, verification, payment, gift card, or personal info requests
  - suspicious link patterns
  - misspelled brand names
  - excessive punctuation and pressure wording
  - fake bank, delivery, and account-provider impersonation
  - possible brand/domain spoofing
- Visual cards for each phishing indicator found
- Sample phishing examples
- Security tips sidebar
- Copy result and JSON export
- Screenshot upload placeholder for future enhancement

## Notes

- This version is plain `HTML`, `CSS`, and `JavaScript` so it runs locally without Node.js.
- The Google Font import in `index.html` uses the internet. If you want the app to work fully offline, I can swap it to a built-in system font stack.
