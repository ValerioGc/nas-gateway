# nas-gateway

Il gateway di autenticazione di nas-os: sul NAS è l'ingresso dal browser, in HTTPS sulla porta 443
e in HTTP sulla 80, senza redirect automatico. Serve
l'interfaccia compilata, gestisce l'accesso con l'account creato dal wizard e inoltra le API e le
applicazioni al launcher, che ascolta solo sul loopback. È un progetto a sé, con il suo repository
(`ValerioGc/nas-gateway`), la sua versione e la sua release; lo installano il wizard
([../nas-wizard](../nas-wizard/README.md)) e, per gli aggiornamenti, chi riesegue il suo installer.

## Avvio in sviluppo

```bash
cargo run
```

Ascolta su `127.0.0.1:3003` (`GATEWAY_PORT` cambia la porta, `GATEWAY_ADDRESS` l'indirizzo) e tiene
account e sessioni in `data/gateway.db`. Il Vite della UI ([../nas-launcher](../nas-launcher/README.md)) gli inoltra
`/auth`. Per creare l'account di sviluppo, come fa il wizard:

```bash
printf 'admin\nlong enough\n' | cargo run -- account create
```

## Rotte

| Rotta                                          | Risultato                                                                                                                                                                                         |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /auth/login`                             | Controlla l'account e apre una sessione: il cookie `nas_session`, opaco, HttpOnly, SameSite=Strict. 401, 429 o 502.                                                                               |
| `GET /auth/session`                            | `{ authenticated, username }` finché il cookie indica una sessione viva; altrimenti 401.                                                                                                          |
| `POST /auth/logout`                            | Chiude la sessione e fa scadere il cookie.                                                                                                                                                        |
| `GET /auth/policy`                             | Con una sessione, il blocco dopo gli accessi rifiutati: `{ enabled, attempts, lockMinutes }`.                                                                                                     |
| `PUT /auth/policy`                             | Con una sessione, lo cambia: tentativi da 1 a 20, minuti da 1 a 1440, altrimenti 400.                                                                                                             |
| `GET /health`                                  | Controllo locale di prontezza.                                                                                                                                                                    |
| `GET /auth/ca.crt`                             | La CA del NAS, da installare come attendibile. Libera, anche con l'mTLS acceso.                                                                                                                   |
| `GET /auth/mtls`                               | Con una sessione: `{ enabled, available, current }`, dove `current` è il dispositivo della connessione.                                                                                           |
| `PUT /auth/mtls`                               | Con la password confermata, accende o spegne l'mTLS. Accenderlo senza un certificato valido sulla connessione è 409.                                                                              |
| `GET /auth/devices`                            | Con una sessione, i dispositivi con l'ultimo certificato di ciascuno.                                                                                                                             |
| `POST /auth/devices`                           | Con la password confermata, `{ name, icon }`: crea il dispositivo e risponde con il `.p12` (base64) e la sua password.                                                                            |
| `PUT /auth/devices/{id}`                       | Cambia nome e icona.                                                                                                                                                                              |
| `POST /auth/devices/{id}/renew`                | Con la password confermata: revoca i certificati del dispositivo e ne emette uno nuovo.                                                                                                           |
| `POST /auth/devices/{id}/revoke`               | Revoca i certificati del dispositivo, che resta in elenco.                                                                                                                                        |
| `DELETE /auth/devices/{id}`                    | Toglie il dispositivo e i suoi certificati.                                                                                                                                                       |
| `POST /auth/clients`                           | Con la password confermata, `{ name, syncId }`: crea il computer di un client di sincronizzazione (`syncId` è l'identità del suo Syncthing) e risponde con certificato, chiave e autorità in PEM. |
| `/client/sync/{pair,folders,syncs,syncs/<id>}` | Solo con il certificato attivo di un client di sincronizzazione: va alle rotte client di `nas-sync-manager`, con il computer in `x-nas-client`. `pair` solo con un certificato mai usato.         |
| `GET /auth/account`                            | Con una sessione: `{ username, email, recovery }`: `email` è l'indirizzo di recupero verificato o `null`, `recovery` dice se il reset via mail è acceso.                                          |
| `PUT /auth/account/username`                   | Con la password confermata, `{ username }`: cambia il nome di accesso; le sessioni restano aperte.                                                                                                |
| `PUT /auth/account/password`                   | Con la password confermata, `{ password }`: la cambia e chiude le altre sessioni.                                                                                                                 |
| `PUT /auth/account/share-password`             | Con una sessione, `{ password }`: la password dell'account, verificata come una conferma, va a Samba per le cartelle condivise. 204, 403 se sbagliata, 503 senza Samba.                           |
| `POST /auth/account/email`                     | Con la password confermata, `{ email }`: manda un codice all'indirizzo. 202, o 502 se la mail non parte.                                                                                          |
| `POST /auth/account/email/verify`              | Con una sessione, `{ code }`: il codice giusto rende l'indirizzo quello di recupero, altrimenti 400.                                                                                              |
| `DELETE /auth/account/email`                   | Con la password confermata, toglie l'indirizzo di recupero.                                                                                                                                       |
| `GET /auth/certificate`                        | Con una sessione: il certificato HTTPS in uso (soggetto, firmatario, nomi, validità, impronta), l'autorità, i nomi automatici e quelli aggiunti.                                                  |
| `PUT /auth/certificate/names`                  | Con la password confermata, `{ names }`: gli indirizzi aggiunti al certificato del NAS (al massimo 20), emesso di nuovo subito.                                                                   |
| `POST /auth/certificate/renew`                 | Con la password confermata: un nuovo certificato del NAS, con la stessa autorità.                                                                                                                 |
| `PUT /auth/certificate/custom`                 | Con la password confermata, `{ certificate, key }` in PEM: un certificato portato dall'utente, controllato prima di usarlo.                                                                       |
| `DELETE /auth/certificate/custom`              | Con la password confermata: torna al certificato del NAS.                                                                                                                                         |
| `PUT /auth/account/recovery`                   | Con la password confermata, `{ enabled }`: accende o spegne il reset della password via mail. Spento di predefinito.                                                                              |
| `GET /auth/recovery`                           | Libera: `{ enabled }`, se la pagina di accesso offre il reset (reset acceso e indirizzo verificato).                                                                                              |
| `POST /auth/recovery`                          | Libera, `{ username }`: con il reset acceso, manda un codice all'indirizzo verificato. Sempre 202, o 429.                                                                                         |
| `POST /auth/recovery/reset`                    | Libera, `{ username, code, password }`: con il codice giusto cambia la password e chiude ogni sessione; altrimenti 400.                                                                           |

Nessuna rotta crea l'account: lo crea il wizard sulla macchina, prima che il gateway ascolti, con
`nas-os-gateway account create`. Il comando legge nome e password su due righe dell'input, mai
dalla riga di comando, e applica le stesse regole dell'accesso; il nome deve essere libero anche
per l'utente del terminale, che il wizard crea con lo stesso nome. Esce con 0 se crea l'account, 2
se nome o password non sono validi, 3 se un account c'è già, 1 per un database che non si apre.
`nas-os-gateway --version` stampa la versione: il launcher la legge per proporre l'aggiornamento
del gateway insieme al proprio, e lo installa rieseguendo `gateway_installation/install.sh` dal
pacchetto della release.

Account e sessioni stanno in un database SQLite del gateway (`migrations/`): `GATEWAY_DB_PATH`,
altrimenti `gateway.db` nella cartella di stato di systemd, altrimenti, in una build di debug,
`data/gateway.db`. Accanto, in `copies/gateway.db`, il gateway tiene una copia coerente fatta a
servizio acceso con `VACUUM INTO`, all'avvio e una volta al giorno. La password è un hash Argon2id; una sessione si conserva come SHA-256 del suo
token e finisce dopo 30 minuti senza richieste o 12 ore dopo l'accesso. Dopo i rifiuti che la
regola ammette da uno stesso indirizzo, il gateway risponde 429 finché i minuti non sono passati
(di predefinito attiva, 5 tentativi, 1 minuto). Senza account ogni accesso è rifiutato.

## HTTPS e mTLS

Con `GATEWAY_TLS_PORT` il gateway termina TLS lui stesso (rustls). La prima volta crea la CA del
NAS in `pki/`, accanto al database (`GATEWAY_PKI_DIR` la sposta), con la chiave leggibile solo da
lui. Con quella firma il proprio certificato, per il nome della macchina, lo stesso con `.local`,
`localhost`, `127.0.0.1`, l'indirizzo principale e i nomi in `GATEWAY_TLS_NAMES`, e lo rifà
all'avvio quando i nomi cambiano o mancano meno di 30 giorni alla scadenza. Sulla porta
`GATEWAY_PORT` serve la stessa interfaccia e le API in HTTP, salvo il redirect HTTPS scelto nelle impostazioni. Il cookie
di sessione è `Secure` solo sulle connessioni HTTPS. Senza `GATEWAY_TLS_PORT`,
come in sviluppo, ascolta in HTTP semplice.

`GET /auth/https` returns `{ port, force }` for the signed-in user. `PUT /auth/https` requires
password confirmation and saves those connection settings in `gateway.connection`, beside the
database. The gateway binds the new port before replacing the current listener and updates the
base firewall through the existing `nas-os-firewall.service`. A failed bind or firewall update
keeps the previous settings. These changes never regenerate the server certificate or CA, and
do not replace an installed custom certificate. With enforcement enabled, HTTP requests receive
a temporary redirect preserving their path and query. The physical screen and loopback health
checks retain their local HTTP access. Update the wizard's base firewall and the launcher helper
alongside the gateway before enabling a custom port.

Con `GATEWAY_SCREEN_PORT` (8081 nell'unità) il gateway risponde anche in HTTP su quella porta di
`127.0.0.1`: è il monitor collegato al NAS, che il firewall di base apre solo all'utente del suo
browser. Lì l'accesso chiede la password come altrove, ma non il certificato del dispositivo: chi è
davanti alla macchina ci è fisicamente.

Ogni handshake chiede un certificato client firmato dalla CA del NAS e accetta anche chi non ne ha.
Con l'mTLS acceso (spento di predefinito), ogni richiesta senza il certificato di un dispositivo
valido riceve una pagina 403 che lo spiega; restano liberi `/health` e `/auth/ca.crt`. Un
dispositivo è riconosciuto dall'impronta SHA-256 del suo certificato. Un certificato nuovo è
`pending` finché non si accede con lui, poi `active`; revocarlo è una riga del database, senza CRL.
Il file di un dispositivo è un PKCS#12 con chiave, certificato e CA, cifrato con una password
casuale che si vede una sola volta. Accendere l'mTLS è possibile solo da un dispositivo con un
certificato valido, e non si revoca il certificato della connessione in uso: così nessuno resta
chiuso fuori.

Un client di sincronizzazione (NAS Sync) riceve il proprio certificato con `POST /auth/clients`, una
volta confermata la password, e da lì raggiunge solo `/client/sync/...`: il gateway controlla il
certificato, toglie ogni `x-nas-client` arrivato da fuori, lo scrive con l'identità del Syncthing
del computer e avvia `nas-sync-manager` se non risponde. Revocare o togliere quel computer chiede
all'applicazione di dimenticarne il Syncthing e le sincronizzazioni; finché non conferma, il
gateway riprova ogni cinque minuti (`sync_revocations`). Con l'mTLS acceso un computer nuovo non
può chiedere il certificato.

Il wizard usa solo `nas-os-gateway ca`, che scrive la CA per HTTPS, e crea l'account con password.
I dispositivi e l'attivazione mTLS si gestiscono dal Centro sicurezza dopo l'accesso al NAS:
si crea e si importa il primo certificato, si riapre il NAS in HTTPS e si attiva mTLS confermando
la password. Il comando locale di amministrazione `nas-os-gateway device create --name <nome>
[--icon <icona>] [--enable-mtls]` resta disponibile sul NAS e scrive CA, file e password come
una riga JSON sull'uscita. Un dispositivo dello stesso nome con un certificato mai usato viene
rinnovato invece di duplicarlo.

## Sul NAS

Con `GATEWAY_UI_DIR` serve l'interfaccia, che installa il launcher in
`/usr/local/share/nas-os/ui`. Risponde a `/api/*` solo con una sessione viva e lo inoltra al
launcher (`GATEWAY_LAUNCHER`, `127.0.0.1:3000` di predefinito); fanno eccezione `GET /api/setup`,
che la UI chiede prima dell'accesso per sapere se il NAS è pronto, e `/api/access/failures`. Le
applicazioni, sotto `/apps/<id>/`, vanno al launcher allo stesso modo, solo con una sessione e senza
il cookie di sessione.

Il gateway scrive `X-NAS-User` con il nome dell'utente collegato su ciò che inoltra, dopo aver tolto
qualunque valore mandato dal browser. Allo stesso modo scrive `X-NAS-Secure: 1` solo su una
richiesta arrivata in TLS o dallo schermo del NAS: il launcher la chiede prima di accettare o
restituire una password o una chiave (cifratura dei dischi, dischi di rete). Il ripristino (`POST /api/system/reset`), l'esportazione
(`GET /api/system/config`) e l'importazione (`POST /api/system/config`) della configurazione
chiedono di nuovo la password dell'account. Il browser la manda a `POST /auth/confirm`, che con la
password giusta risponde con un codice valido per una sola richiesta entro un minuto; la richiesta
lo porta in `X-NAS-Confirmation`. Il gateway toglie il codice e inoltra la richiesta, corpo
intatto, con `X-NAS-Reauthenticated` e il nome dell'utente, intestazione che il browser non può
mandare da sé. La password non arriva mai al launcher. Una password sbagliata risponde `403` (la
sessione resta valida) e conta fra gli accessi rifiutati dell'indirizzo, come un accesso
sbagliato. Il launcher resta sul loopback.

Il certificato HTTPS in uso vive in memoria e il gateway lo cambia senza riavvio: lo legge rustls a
ogni connessione. Quello del NAS copre i nomi automatici (nome host, `.local`, `localhost`,
`127.0.0.1`, l'indirizzo principale, `GATEWAY_TLS_NAMES`) e quelli aggiunti dalle impostazioni
(`server.extra` nella cartella dell'autorità); ogni ora il gateway ricontrolla i nomi e lo emette di
nuovo solo se sono cambiati, per esempio con un nuovo indirizzo. Un certificato personalizzato
(`custom.crt` e `custom.key`, chiave `0600`) prende il posto di quello del NAS finché vale: va
controllato che la chiave sia la sua e che valga adesso, altrimenti è rifiutato.

Il nome di accesso cambia solo nel gateway: l'utente Linux del terminale e la cartella
`.nas-users/<utente>` dei dischi restano quelli creati dal wizard. I codici per le mail sono di sei
cifre, valgono 15 minuti e cinque tentativi, e il database ne tiene solo lo SHA-256; un codice per
il recupero non riparte prima di un minuto. Il gateway non manda posta da sé: chiede al launcher,
sul loopback, `POST /internal/mail/code` con `{ to, purpose, code }` (`verify` o `reset`), e il
launcher lo passa all'app Email (nas-mail-client). `/internal/` non è mai inoltrato dal browser. La
risposta del recupero è la stessa che l'account o l'indirizzo esistano o no, e un codice sbagliato
conta fra gli accessi rifiutati dell'indirizzo.

## Installazione

Ogni release pubblica `nas-gateway-<versione>-linux-x64.tar.gz` e il suo `.sha256`. Il pacchetto
contiene `packages/gateway_installation`: vedere il suo [README](system/packages/gateway_installation/README.md).

## Verifiche

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
npm run test:scripts
```

`npm run release:test` le esegue tutte in ordine e costruisce il pacchetto. Lo sviluppo e il
rilascio sono in [DEVELOPMENT.md](DEVELOPMENT.md).

## NAS Finder

Il gateway risponde alle richieste di NAS Finder su UDP 39877, mostrando nome, stato di
configurazione e porta della pagina web. Decide il firewall di base: la porta è aperta alla sola
rete locale finché il set `nas_discovery` la contiene. Il wizard la apre durante la prima
configurazione e la chiude al passaggio al gateway; da lì la riapre il launcher, solo mentre
l'opzione "Rilevamento in rete" di Security Center è accesa.

Funzionamento, verifica e limiti della prova sono documentati in
[Integrazione NAS Finder](../destkop-apps/nas-finder/NAS-INTEGRATION.md).
La discovery non modifica autenticazione, HTTPS, mTLS o accesso al sistema.
