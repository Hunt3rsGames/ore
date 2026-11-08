# TimbraOre Live Pro

Calcolo ore lavorate, pausa e previsione uscita, con login multiutente.
Node.js + Express + SQLite (better-sqlite3), sessione JWT in cookie httpOnly, frontend Vue 3 + Tailwind (CDN).

## Avvio

    docker compose up -d
    # http://localhost:8080

Al primo avvio viene creato l'utente `ADMIN_USER` / `ADMIN_PASSWORD` (se il DB è vuoto).
Dopo aver creato gli account, imposta `ALLOW_REGISTRATION: "false"` e riavvia.

## Dati

Tutto sta in `./data/ore.db` (SQLite): fai il backup di quella cartella.
Al primo login con un account vuoto, i dati del vecchio localStorage del browser vengono importati automaticamente.

## Reverse proxy

L'app si fida del primo proxy (`trust proxy 1`): dietro Nginx Proxy Manager con HTTPS il cookie diventa `Secure`.
Punta Nginx Proxy Manager a `ore:3000` (o `IP-host:8080`) e abilita SSL.
