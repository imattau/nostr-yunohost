# YunoHost wrapper integration

`nostr_catalog_ynh` is the planned normal YunoHost app that runs the catalogue
daemon. It should expose the daemon's settings through the standard YunoHost
configuration panel:

- relay URLs;
- trusted publisher npubs;
- cache/state location;
- listen address and port, restricted to loopback by default;
- refresh and experimental-app policy when those features exist.

The wrapper should render `NOSTR_YNH_RELAYS` and
`NOSTR_YNH_TRUSTED_PUBLISHERS`, then manage the daemon as a systemd service.
The initial service template is in
`packaging/nostr_catalog_ynh/nostr-catalogd.service`.

The custom YunoHost catalogue registration belongs in the wrapper's install
and remove scripts. The catalogue URL must point to the local daemon and the
daemon must remain bound to loopback unless an administrator explicitly
chooses otherwise.

This wrapper is a deployment adapter, not a second implementation of the
publisher, relay, trust, or catalogue logic.
