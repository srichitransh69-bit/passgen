# 🔐 KeyForge — Password Generator

A sleek, cryptographically secure password generator that runs **entirely in your browser**. No server. No tracking. No dependencies.

![KeyForge Preview](https://img.shields.io/badge/status-live-7DF5A0?style=flat-square) ![HTML](https://img.shields.io/badge/HTML-5-orange?style=flat-square) ![CSS](https://img.shields.io/badge/CSS-3-blue?style=flat-square) ![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-yellow?style=flat-square) ![No Dependencies](https://img.shields.io/badge/dependencies-0-7DF5A0?style=flat-square)

## ✨ Features

- **Cryptographically secure** — Uses `crypto.getRandomValues()` (Web Crypto API), never `Math.random()`
- **Zero server communication** — all generation is 100% client-side
- **Flexible character sets** — uppercase, lowercase, numbers, symbols
- **Smart controls** — length (4–64), quantity (1–10), exclude specific characters
- **Ambiguous character exclusion** — optionally remove O, 0, l, 1, I
- **No-duplicate mode** — each character appears at most once
- **Live entropy calculation** — see bits of entropy and crack-time estimate
- **Visual strength meter** — 5-level password strength indicator
- **Bulk generation** — generate up to 10 passwords at once with copy-each support
- **One-click copy** — clipboard API with fallback for older browsers
- **Keyboard shortcuts** — `Space` to generate, `C` to copy
- **Fully responsive** — works great on mobile

## 🚀 Demo

Deploy instantly on GitHub Pages:

1. Fork or clone this repo
2. Go to **Settings → Pages → Source → main branch / root**
3. Your site will be live at `https://yourusername.github.io/password-generator`

Or open `index.html` directly in any modern browser — no server needed.

## 📁 File Structure

```
password-generator/
├── index.html      # App markup and structure
├── style.css       # Dark industrial theme, fully responsive
├── app.js          # Password logic + Web Crypto API
├── favicon.svg     # SVG favicon
└── README.md       # This file
```

## 🔒 Security Notes

- **No `Math.random()`** — all randomness comes from `crypto.getRandomValues()`, which is cryptographically strong
- **Rejection sampling** — eliminates modulo bias in character selection
- **No network requests** — your passwords are never transmitted anywhere
- Open source — audit the code yourself

## 🛠️ How It Works

```js
// Secure random index — no modulo bias
function secureRandom(max) {
  const buffer = new Uint32Array(1);
  const limit = 0x100000000 - (0x100000000 % max);
  let rand;
  do {
    crypto.getRandomValues(buffer);
    rand = buffer[0];
  } while (rand >= limit);
  return rand % max;
}
```

Entropy is calculated as:

```
entropy (bits) = password_length × log₂(charset_size)
```

A password with 80+ bits of entropy is considered very strong by modern standards.

## 📖 Usage

1. Set your desired **password length** using the slider
2. Select **character sets** (uppercase, lowercase, numbers, symbols)
3. Optionally enable **no ambiguous** or **no duplicate** characters
4. Click **Generate Password** or press `Space`
5. Click the copy icon or press `C` to copy to clipboard

## 🌐 Browser Support

Works in all modern browsers that support the Web Crypto API:

| Browser | Version |
|---------|---------|
| Chrome  | 37+     |
| Firefox | 34+     |
| Safari  | 11+     |
| Edge    | 12+     |

## 👤 Author

**Chitransh** — B.Tech CSE 2026, FGIET Raebareli

- GitHub: [@srichitransh69-bit](https://github.com/srichitransh69-bit)

## 📄 License

MIT License — free to use, modify, and distribute.

---

*Built with vanilla HTML, CSS, and JavaScript. Zero frameworks. Zero dependencies. Just pure web.*
