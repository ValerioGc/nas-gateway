# Sviluppo di nas-gateway

## Struttura

```text
src/
  main.rs            # Serve il NAS in HTTP o in HTTPS; `account create`, `ca`, `device create`
  lib.rs             # Configurazione dall'ambiente e costruzione del router
  account.rs         # La creazione dell'unico account, per il wizard
  router.rs          # Le rotte /auth e il resto verso entry
  entry.rs           # Cosa passa al launcher, con o senza sessione, e l'interfaccia
  controller.rs      # Accesso, sessione, uscita e regola dei tentativi
  confirm.rs         # La password chiesta di nuovo: codici monouso per ripristino, export e import
  account_controller.rs # Nome, password e indirizzo di recupero dell'account; reset della password
  mailer.rs          # I codici via mail, chiesti al launcher su /internal/mail/code
  certificate_controller.rs # Il certificato HTTPS dal Centro sicurezza: nomi, rinnovo, personalizzato
  pki.rs             # La CA del NAS, il certificato in uso (cambia senza riavvio) e dei dispositivi
  tls.rs             # L'ascolto HTTPS e l'impronta del certificato client di ogni connessione
  device_controller.rs # Le rotte dell'mTLS e dei dispositivi
  client_controller.rs # I computer di NAS Sync: certificato, rotte /client/sync e revoche
  first_device.rs    # Il comando locale di amministrazione dei dispositivi
  base64.rs          # Base64 per PEM e .p12 nel JSON
  proxy.rs           # Il proxy verso il launcher, scritto a mano su hyper, WebSocket compresi
  ui.rs              # I file statici dell'interfaccia
  store.rs           # Il database SQLite e le migrazioni
  auth/              # Account (Argon2id), sessioni, codici via mail, regola, blocco, dispositivi, mTLS
migrations/          # Migrazioni SQL numerate, incluse nel binario
tests/               # Test di integrazione del router; common/ è condiviso
tests/scripts/       # Test degli script di installazione, con `node --test`
system/packages/gateway_installation/   # Installer, verifica, rimozione e unità systemd
scripts/release/     # Cancello locale, pacchetto, rilascio e note della release
```

## Regole

- `cargo fmt` e `cargo clippy --all-targets -- -D warnings` restano puliti.
- Gli errori viaggiano come `Result` tipizzati; `unwrap()` ed `expect()` solo dove non può fallire
  per costruzione, mai su un input.
- Nessun I/O bloccante in un handler: equivalenti di tokio o `spawn_blocking` (l'hash Argon2id).
- Una migrazione applicata non si modifica: se ne aggiunge una nuova.
- I test stanno in `tests/` e chiamano il router dall'esterno con `app_with`; ogni gateway di test
  ha un database su file (`tests/common`), perché l'account si crea fuori dal router, come sul NAS.
- Nessuna dipendenza npm: gli script sono Node puro e i loro test usano `node:test`.
- Nessuna nuova dipendenza Rust senza chiederla prima.
- Mai il trattino lungo (U+2014), in nessun file.

## Rilascio

Il rilascio si prova in locale e si pubblica in pipeline, che non esegue test. I test girano su
ogni pull request verso `main` (`.github/workflows/ci.yml`: Rust e script di installazione).

- `npm run release:test` è il cancello locale: formattazione, clippy, test Rust, test degli script,
  binario di rilascio e pacchetto.
- `npm run release:merge -- --type=patch|minor|major --branch=main` sceglie la versione, esegue lo
  stesso cancello, scrive la versione in `package.json`, `Cargo.toml` e
  `sonar-project.properties` e pubblica il tag. `--dry-run` dice solo quale versione uscirebbe.
- Il tag avvia `.github/workflows/build.yml`: verifica tag e versione, compila, costruisce il
  pacchetto, pubblica la release (il pacchetto e il suo `.sha256`) e tiene solo le due più recenti.
  Le note sono la sezione della versione in `CHANGELOG.txt` o, se manca, i commit dal tag
  precedente.

Il pacchetto si chiama `nas-gateway-<versione>-linux-x64.tar.gz`: è il nome che il wizard cerca.

## Qualità

`npm run test:sonar` genera la copertura con `cargo llvm-cov` e il rapporto di clippy, poi avvia lo
scanner con Podman. SonarQube si avvia con `npm run podman:sonar:up`: è la stessa istanza degli
altri progetti di nas-os, con una chiave di progetto diversa (`nas-gateway`).

```bash
cargo install cargo-llvm-cov --locked
rustup component add llvm-tools-preview
```
