# Cairn Security

How Cairn protects data, what to be careful with, and how to report issues. See `THREAT_MODEL.md` for what is and
isn't in scope, `ARCHITECTURE.md` for the data flow.

## Cryptographic primitives
- **Chunk-key wrapping (envelope):** age X25519. Back up with `--pub-key`, restore with `--priv-key`. The backup host
  never needs the private key.
- **Symmetric (password-only) mode:** without `--pub-key`, chunk keys are wrapped with a random per-archive **KEK**
  (AES-256-GCM, `CKEK1` blob format); the KEK itself is wrapped once with the passphrase (age scrypt envelope, config
  key `wrapped_kek`) — one scrypt per mount, and a wrong password fails at mount time.
  Note the trade-off: symmetric mode has no write-only property — anyone who can write can also read.
- **Chunk encryption:** AES-256-GCM or ChaCha20-Poly1305 (`--crypto-algo`), with a per-chunk symmetric key. The cipher
  used is recorded **per chunk**, so changing the default does not make existing backups unreadable.
- **Deduplication key:** keyed BLAKE3 over the chunk content with a per-archive dedup secret (convergent — identical
  content dedups). The secret is **auto-generated at `init`** and stored in the archive's encrypted config; there is
  no CLI flag to supply it. `init --disable-dedup` uses a fresh random key per chunk instead (no cross-file dedup,
  stronger privacy); the mode is fixed at init.
- **Metadata index:** SQLCipher, unlocked with `--password`.

### Convergent-nonce note (read before touching crypto)
In dedup mode the per-chunk AEAD **nonce is fixed** (`b"convergent_n"` in `crates/cairn-seal/src/lib.rs`). This is
safe **only** because the per-chunk key is unique per encryption: content-derived in convergent mode (unique per
plaintext), freshly random in `--disable-dedup` mode (unique per chunk, so the fixed nonce is equally safe there).
**Do not** add any mode that derives the chunk key from something other than content (e.g. a password) without first
switching to a content-derived or random nonce. Reusing a nonce under a repeated key breaks AES-GCM catastrophically.
See `ROADMAP.md` (symmetric mode).

The deterministic nonce also means that ciphertexts are identical for identical plaintexts — this is the property that
enables server-side deduplication. A side effect is that **compression-oracle attacks** (CRIME/BREACH) across backup
versions are theoretically possible if an attacker can inject chosen plaintext alongside known data and observe chunk
boundaries or compressed sizes. Cairn mitigates this with **fixed-size AEAD padding** (`encrypt_chunk_symmetric` pads
every chunk to the next 4096-byte boundary) and optional **discrete compression ratios** (`--comp-min-ratio`). If your
threat model includes a chosen-plaintext attacker who can repeatedly write to the same archive, create the archive
with `init --disable-dedup`: random per-chunk keys make identical plaintexts produce unrelated ciphertexts, which
eliminates the convergence oracle entirely (at the cost of deduplication; the mode is fixed at init).

## Key custody (the part that matters most)
- The **age private key** is the crown jewel: anyone with it *and* `--password` can read every backup. Generate keys on
  a trusted machine (`cargo run -p cairn-keys --bin gen_keys` → `priv.pem` + `pub.pem`), keep `priv.pem` off backup
  hosts, and back it up separately from the archive.
- `pub.pem` is safe to distribute to any host that only writes backups.
- For shared custody, `cairn-keys` can Shamir-split the master secret into M-of-N shares.

## Operational caveats
- **Secrets in argv.** `--password` on the command line is visible in the process table (`ps`). Prefer
  `--password-file` or the `CAIRN_PASSWORD` env var on shared machines (env is still visible in
  `/proc/PID/environ` to same-uid attackers).
- **Not anti-forensic.** A machine holding the keys can read the data; there is no self-destruct or deniability.
- **Metadata at rest.** File names, sizes and structure are protected only by SQLCipher (`--password`). A leaked
  password exposes them. Backup hosts *hold* this password by design. **Optional:** `init --hide-names` (asymmetric
  archives) makes *names* write-only (keyed hashes + age-encrypted, readable only with the private key); sizes, tree,
  timestamps and xattr values are unaffected. See `HIDE_NAMES.md`.
- **Restore host trust.** Only mount with `--priv-key` on machines you trust — that is where the data becomes readable.
- **`--dangerously-skip-verify`.** Requires `CAIRN_I_ACCEPT_CORRUPTION=1` in addition to the flag; otherwise refused.
- **No external crypto audit yet.** Treat implementation trust accordingly until one is published.

## Транзитивные зависимости: yanked / unmaintained

Ниже таблица известных проблемных транзитивных зависимостей, которые пока не требуют срочного обновления (нет
совместимых версий или обновление ломает сборку). Мониторить обновления на crates.io и RUSTSEC.

| Пакет | Версия в cairn | Статус | Путь зависимости | CVE / RUSTSEC | Действие |
|---|---|---|---|---|---|
| **quick-xml** | 0.41.0 ✅ | Исправлен | opendal → opendal-core → xml → quick-xml | RUSTSEC-2026-0195 (7.5), RUSTSEC-2026-0194 | Обновлён до >=0.41.0 в Cargo.lock |
| **spin** | 0.9.8 ⚠️ | unmaintained (crates.io) | cacache → dashmap → spin | Нет CVE, unmaintained с 2023 | Мониторинг; нет замены без обновления dashmap |
| **async-std** | 1.13.2 ⚠️ | unmaintained (crates.io) | cacache → async-std | Нет CVE, unmaintained с 2024 | Мониторинг; обновление cacache может помочь |
| **bincode** | 1.3.3 ⚠️ | unmaintained (crates.io) | cairn-store → bincode | RUSTSEC-2025-0141 | Мониторинг; нет прямого влияния на безопасность |
| **memmap2** | 0.5.10 ⚠️ | unmaintained (crates.io) | cacache → memmap2 | RUSTSEC-2026-0186 (см. секцию ниже) | Мониторинг; обновление cacache может помочь |
| **fxhash** | 0.2.1 ⚠️ | unmaintained (crates.io) | dashmap → fxhash | Нет CVE, unmaintained с 2023 | Мониторинг; нет замены без обновления dashmap |
| **rustls-pemfile** | 2.x ⚠️ | unmaintained (crates.io) | rproxy → rustls-pemfile | Нет CVE, unmaintained с 2024 | Мониторинг; обновление rustls может помочь |

### Действия при обнаружении новой уязвимости
1. Проверить `cargo audit` (если доступен) или https://rustsec.org/
2. Оценить путь зависимости: достижима ли атакуемая функция в нашем коде?
3. Если критично — обновить пакет и проверить сборку; если нет совместимой версии — задокументировать риск здесь.

## memmap2 через cacache (ШАГ 3)

**Путь:** cairn → cacache → memmap2 (0.5.10)

memmap2 используется cacache для маппинга кэшированных файлов в память.
**RUSTSEC-2026-0186** — unchecked pointer offset, затрагивает версии 0.5.9–<0.9.11.
Пакет unmaintained с 2024 года. Обновление cacache до последней версии (13.1.0) не решает проблему —
memmap2 остаётся зависимостью.

**Обоснование игнора:** См. `.cargo/audit.toml` — RUSTSEC-2026-0186 добавлен в `ignore`, так как
cairn не использует memmap2 напрямую; он используется только внутри cacache для кэширования,
и вектор атаки через эту цепочку в нашем сценарии отсутствует.

**Мониторинг:** Следить за обновлениями memmap2 и cacache на crates.io. При появлении новой версии memmap2
или обновлённого cacache, который использует новую версию memmap2, проверить совместимость с cairn.

## Reporting a vulnerability
Report suspected security issues privately to the maintainer (see the repository's contact/`repository` field in
`Cargo.toml`). Please do not open public issues for undisclosed vulnerabilities.
