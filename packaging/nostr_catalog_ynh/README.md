# `nostr_catalog_ynh` packaging contract

This directory contains deployment assets for the future normal YunoHost
wrapper app. It is intentionally separate from the Go core and is not yet a
complete installable YunoHost package.

The wrapper must:

1. Install the `nostr-catalogd` binary.
2. Create a restricted service user and writable state directory.
3. Render the daemon environment from YunoHost app settings.
4. Start the systemd service.
5. Register `http://127.0.0.1:8090/v3/apps.json` as a custom YunoHost catalogue.
6. Stop/remove the service cleanly during removal.

The wrapper does not install discovered applications and does not contain
Nostr protocol logic. Those responsibilities stay in the daemon.

The service template and environment file below are starting points for the
separate `nostr_catalog_ynh` repository.
