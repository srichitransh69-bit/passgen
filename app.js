/**
 * KeyForge Password Generator
 * Author: Chitransh (github.com/srichitransh69-bit)
 * Uses Web Crypto API (crypto.getRandomValues) — no Math.random()
 * Entirely client-side. No data leaves the browser.
 */

'use strict';

// ─── Character Sets ──────────────────────────────────────────────────────────
const CHAR_SETS = {
  upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower:   'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}|;:,.<>?',
};

const AMBIGUOUS_CHARS = new Set(['O', '0', 'l', '1', 'I']);

// ─── DOM References ───────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const els = {
  display:       $('password-display'),
  copyBtn:       $('copy-btn'),
  refreshBtn:    $('refresh-btn'),
  generateBtn:   $('generate-btn'),
  lengthSlider:  $('length-slider'),
  lengthValue:   $('length-value'),
  quantitySlider:$('quantity-slider'),
  quantityValue: $('quantity-value'),
  useUpper:      $('use-upper'),
  useLower:      $('use-lower'),
  useNumbers:    $('use-numbers'),
  useSymbols:    $('use-symbols'),
  noAmbiguous:   $('no-ambiguous'),
  noDuplicate:   $('no-duplicate'),
  excludeInput:  $('exclude-input'),
  strengthBars:  $('strength-bars'),
  strengthLabel: $('strength-label'),
  entropyValue:  $('entropy-value'),
  entropySub:    $('entropy-sub'),
  toast:         $('toast'),
  bulkSection:   $('bulk-section'),
  bulkList:      $('bulk-list'),
  copyAllBtn:    $('copy-all-btn'),
};

// ─── State ────────────────────────────────────────────────────────────────────
let lastPasswords = [];
let toastTimer = null;

// ─── Cryptographic RNG ────────────────────────────────────────────────────────
/**
 * Returns a cryptographically random integer in [0, max)
 * Uses rejection sampling to eliminate modulo bias.
 */
function secureRandom(max) {
  if (max <= 0) throw new RangeError('max must be positive');
  const buffer = new Uint32Array(1);
  const limit = 0x100000000 - (0x100000000 % max);
  let rand;
  do {
    crypto.getRandomValues(buffer);
    rand = buffer[0];
  } while (rand >= limit);
  return rand % max;
}

// ─── Password Generation ─────────────────────────────────────────────────────
function buildCharset() {
  const excludeSet = new Set(els.excludeInput.value.split(''));
  const noAmbig    = els.noAmbiguous.checked;

  let charset = '';

  const addChars = (chars) => {
    for (const c of chars) {
      if (excludeSet.has(c)) continue;
      if (noAmbig && AMBIGUOUS_CHARS.has(c)) continue;
      charset += c;
    }
  };

  if (els.useUpper.checked)   addChars(CHAR_SETS.upper);
  if (els.useLower.checked)   addChars(CHAR_SETS.lower);
  if (els.useNumbers.checked) addChars(CHAR_SETS.numbers);
  if (els.useSymbols.checked) addChars(CHAR_SETS.symbols);

  // Deduplicate
  return [...new Set(charset)].join('');
}

function generatePassword(length, charset) {
  if (!charset || charset.length === 0) {
    throw new Error('No characters available. Enable at least one character set.');
  }

  const noDup = els.noDuplicate.checked;

  if (noDup && length > charset.length) {
    throw new Error(`Cannot generate ${length}-char no-duplicate password with only ${charset.length} unique characters. Reduce length or enable more character sets.`);
  }

  if (noDup) {
    // Fisher-Yates shuffle subset
    const pool = charset.split('');
    const selected = [];
    for (let i = 0; i < length; i++) {
      const j = secureRandom(pool.length);
      selected.push(pool[j]);
      pool.splice(j, 1);
    }
    return selected.join('');
  } else {
    let result = '';
    for (let i = 0; i < length; i++) {
      result += charset[secureRandom(charset.length)];
    }
    return result;
  }
}

// ─── Entropy Calculation ──────────────────────────────────────────────────────
function calcEntropy(length, charsetSize) {
  if (charsetSize === 0) return 0;
  return Math.floor(length * Math.log2(charsetSize));
}

function entropyLabel(bits) {
  if (bits < 28)  return { level: 'catastrophic', sub: 'trivially cracked in seconds' };
  if (bits < 40)  return { level: 'very weak',    sub: 'cracked in minutes or hours' };
  if (bits < 60)  return { level: 'weak',         sub: 'cracked in days with hardware' };
  if (bits < 80)  return { level: 'fair',         sub: 'cracked in months' };
  if (bits < 100) return { level: 'strong',       sub: 'cracked in years' };
  if (bits < 128) return { level: 'very strong',  sub: 'cracked in centuries' };
  return              { level: 'fortress',        sub: 'effectively uncrackable' };
}

// ─── Strength Scoring ─────────────────────────────────────────────────────────
function strengthScore(password) {
  const has = {
    upper:   /[A-Z]/.test(password),
    lower:   /[a-z]/.test(password),
    number:  /[0-9]/.test(password),
    symbol:  /[^A-Za-z0-9]/.test(password),
  };
  const sets = Object.values(has).filter(Boolean).length;
  const len  = password.length;

  let score = 0;
  if (len >= 8)  score++;
  if (len >= 12) score++;
  if (len >= 16) score++;
  if (sets >= 3) score++;
  if (sets === 4 && len >= 12) score++;

  return Math.min(score, 5);
}

const STRENGTH_LABELS = ['', 'Weak', 'Fair', 'Good', 'Strong', 'Fort'];
const STRENGTH_CLASSES = ['', 's1', 's2', 's3', 's4', 's5'];

// ─── UI Updates ───────────────────────────────────────────────────────────────
function updateStrengthUI(password) {
  if (!password || password === 'Click generate to start') {
    els.strengthBars.className = 'strength-bars';
    els.strengthLabel.className = 'strength-label';
    els.strengthLabel.textContent = '—';
    return;
  }

  const score = strengthScore(password);
  const cls   = STRENGTH_CLASSES[score];

  els.strengthBars.className = `strength-bars ${cls}`;
  els.strengthLabel.className = `strength-label ${cls}`;
  els.strengthLabel.textContent = STRENGTH_LABELS[score] || '—';
}

function updateEntropyUI(password, charsetSize) {
  if (!password || !charsetSize) {
    els.entropyValue.textContent = '—';
    els.entropySub.textContent = '';
    return;
  }
  const bits = calcEntropy(password.length, charsetSize);
  const info = entropyLabel(bits);
  els.entropyValue.textContent = `${bits} bits`;
  els.entropySub.textContent = `· ${info.level}`;
}

function flashPassword(el) {
  el.classList.remove('updated');
  void el.offsetWidth; // reflow
  el.classList.add('updated');
}

// ─── Main Generate Action ─────────────────────────────────────────────────────
function generate() {
  const length   = parseInt(els.lengthSlider.value, 10);
  const quantity = parseInt(els.quantitySlider.value, 10);

  let charset;
  try {
    charset = buildCharset();
  } catch (e) {
    showError(e.message);
    return;
  }

  const passwords = [];
  try {
    for (let i = 0; i < quantity; i++) {
      passwords.push(generatePassword(length, charset));
    }
  } catch (e) {
    showError(e.message);
    return;
  }

  lastPasswords = passwords;

  // Primary display
  const primary = passwords[0];
  els.display.textContent = primary;
  els.display.classList.remove('placeholder');
  flashPassword(els.display);

  // Enable copy
  els.copyBtn.disabled = false;

  // Strength & entropy
  updateStrengthUI(primary);
  updateEntropyUI(primary, charset.length);

  // Bulk
  if (quantity > 1) {
    renderBulk(passwords);
    els.bulkSection.hidden = false;
  } else {
    els.bulkSection.hidden = true;
  }

  // Animate generate button
  els.generateBtn.classList.add('loading');
  setTimeout(() => els.generateBtn.classList.remove('loading'), 600);
}

function renderBulk(passwords) {
  els.bulkList.innerHTML = '';
  passwords.forEach((pw, i) => {
    const li = document.createElement('li');
    const code = document.createElement('code');
    code.textContent = pw;

    const btn = document.createElement('button');
    btn.className = 'bulk-copy-btn';
    btn.setAttribute('aria-label', `Copy password ${i + 1}`);
    btn.title = 'Copy';
    btn.innerHTML = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
    btn.addEventListener('click', () => copyText(pw));

    li.appendChild(code);
    li.appendChild(btn);
    els.bulkList.appendChild(li);
  });
}

// ─── Clipboard ────────────────────────────────────────────────────────────────
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast();
  } catch {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast();
  }
}

function showToast() {
  els.toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => els.toast.classList.remove('show'), 2000);
}

function showError(msg) {
  els.display.textContent = msg;
  els.display.classList.add('placeholder');
  els.copyBtn.disabled = true;
  updateStrengthUI(null);
  els.entropyValue.textContent = '—';
  els.entropySub.textContent = '';
}

// ─── Slider Sync ─────────────────────────────────────────────────────────────
function syncSlider(slider, output) {
  output.textContent = slider.value;
  slider.setAttribute('aria-valuenow', slider.value);
}

// ─── Event Listeners ──────────────────────────────────────────────────────────
els.generateBtn.addEventListener('click', generate);
els.refreshBtn.addEventListener('click',  generate);

els.copyBtn.addEventListener('click', () => {
  if (lastPasswords.length > 0) copyText(lastPasswords[0]);
});

els.copyAllBtn.addEventListener('click', () => {
  const all = lastPasswords.join('\n');
  copyText(all);
});

els.lengthSlider.addEventListener('input', () => {
  syncSlider(els.lengthSlider, els.lengthValue);
});

els.quantitySlider.addEventListener('input', () => {
  syncSlider(els.quantitySlider, els.quantityValue);
});

// Live re-generate on any setting change
const liveUpdateEls = [
  els.useUpper, els.useLower, els.useNumbers, els.useSymbols,
  els.noAmbiguous, els.noDuplicate,
];
liveUpdateEls.forEach(el => el.addEventListener('change', generate));

els.lengthSlider.addEventListener('change', generate);
els.quantitySlider.addEventListener('change', generate);
els.excludeInput.addEventListener('input', debounce(generate, 400));

// Keyboard shortcut: Space to generate, C to copy
document.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT') return;
  if (e.code === 'Space') { e.preventDefault(); generate(); }
  if (e.code === 'KeyC' && !e.ctrlKey && !e.metaKey) {
    if (lastPasswords.length > 0) copyText(lastPasswords[0]);
  }
});

// ─── Utilities ────────────────────────────────────────────────────────────────
function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

// ─── Init ─────────────────────────────────────────────────────────────────────
(function init() {
  syncSlider(els.lengthSlider, els.lengthValue);
  syncSlider(els.quantitySlider, els.quantityValue);
  els.display.classList.add('placeholder');
  // Auto-generate on load
  generate();
})();
