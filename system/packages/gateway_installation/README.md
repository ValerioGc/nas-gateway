# Installazione del gateway

Script per installare il gateway su una macchina Debian 13 reale. Sul NAS li esegue il wizard, che
prima configura il sistema operativo: non servono per lo sviluppo.

| File                           | Scopo                                                                           |
| ------------------------------ | ------------------------------------------------------------------------------- |
| `install.sh`                   | Installa o aggiorna binario e unità; `--no-start` la abilita senza avviarla     |
| `scripts/check.sh`             | Verifica che il gateway sia installato e risponda, senza cambiare niente        |
| `scripts/uninstall.sh`         | Rimuove il gateway; l'account resta, salvo con `--purge`                        |
| `scripts/copy-database.sh`     | Copia il database prima di un aggiornamento, tenendo le ultime cinque copie     |
| `files/nas-os-gateway.service` | L'unità, con un utente dinamico e la sola porta 80 come privilegio              |
| `files/nas-os-share-password.socket`, `files/nas-os-share-password@.service` | Il socket dove il gateway passa a Samba la password delle cartelle condivise, e il servizio root che lo serve |
| `scripts/share-password.sh`    | L'helper di quel servizio: scrive la password in Samba con `smbpasswd`, da stdin |
| `bin/nas-os-gateway`           | Il binario, aggiunto dal pacchetto                                              |

## Utilizzo

Il wizard lo esegue con `--no-start`: la porta 80 è sua finché lavora. Crea l'account con
`nas-os-gateway account create` e avvia il gateway quando ha finito.

A mano, per aggiornare il gateway su un NAS già configurato:

```bash
sha256sum -c nas-gateway-<versione>-linux-x64.tar.gz.sha256
mkdir nas-gateway && tar -xzf nas-gateway-<versione>-linux-x64.tar.gz -C nas-gateway
cd nas-gateway/packages/gateway_installation
./install.sh --dry-run
sudo ./install.sh
sudo /usr/local/lib/nas-os-gateway/check.sh
```

L'installazione non cambia l'account: sta, con le sessioni, in
`/var/lib/private/nas-os-gateway/gateway.db`, la cartella di stato dell'utente dinamico, leggibile
solo da root. Prima che il nuovo binario la apra (e ne applichi le migrazioni), `install.sh` ferma il
gateway e la copia con il suo log (`-wal`, `-shm`) in `before-update/gateway-<ora UTC>.db`, accanto
al database: fermo, il database e il log sono un insieme coerente. Restano le ultime cinque copie.
Con `--no-start` un gateway che era acceso viene riavviato lo stesso.

`install.sh` crea anche il gruppo `nas-os-share-password` prima dell'unità che lo nomina: è l'unico
gruppo del gateway, e il solo che può aprire `/run/nas-os-share-password.sock`. Per spegnere il
passaggio della password a Samba: `sudo systemctl disable --now nas-os-share-password.socket`.

Per tornare alla versione precedente con account e sessioni come li conosceva:

```bash
sudo systemctl stop nas-os-gateway
cd /var/lib/private/nas-os-gateway
sudo rm -f gateway.db-wal gateway.db-shm
for suffix in '' -wal -shm; do
  [[ -e before-update/gateway-<ora>.db$suffix ]] && sudo cp -a before-update/gateway-<ora>.db$suffix gateway.db$suffix
done
cd -    # la cartella del pacchetto della versione precedente
sudo ./install.sh
```

Il gateway acceso tiene anche una copia sua, fatta all'avvio e poi una volta al giorno con `VACUUM
INTO` senza fermarsi: `copies/gateway.db`, nella stessa cartella. È quella da usare per una copia di
sicurezza, invece dei file vivi.

## Cosa resta sulla macchina

`/usr/local/bin/nas-os-gateway`, `/etc/systemd/system/nas-os-gateway.service` e, in
`/usr/local/lib/nas-os-gateway/`, `check.sh` e `uninstall.sh`, perché il pacchetto non resta.

## Rimozione

```bash
sudo /usr/local/lib/nas-os-gateway/uninstall.sh            # servizio e binario, l'account resta
sudo /usr/local/lib/nas-os-gateway/uninstall.sh --purge    # anche account e sessioni, con conferma
```

La rimozione completa del NAS sta nel pacchetto del wizard, che chiama questo script.
