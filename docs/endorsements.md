# Endorsement events

Endorsements are separate from app declarations. A publisher signs the app
declaration; a curator signs an independent recommendation or test result.

The current provisional event kind is `30079`. Its target is an addressable
app identity:

```text
30078:<publisher-pubkey>:<app-id>
```

The event contains:

- `a` — target app declaration address;
- `claim` — for example `recommend` or `tested`;
- content — optional human-readable comment.

The curation package validates endorsements from configured curator identities
and can select a unique canonical candidate once the endorsement threshold is
met. `nostr-catalogd` accepts `--trusted-curators` and
`--minimum-endorsements` to enable this selection policy.

## Publishing an endorsement

Curators can publish an endorsement with the CLI:

```bash
nostr-ynh endorse \
  --claim tested \
  --comment "Installed and tested successfully" \
  --private-key-file curator.key \
  --relays wss://relay.example \
  <app-naddr>
```

The command signs a kind `30079` event with the curator key and publishes it
to every configured relay. Catalogue administrators must add the curator's
`npub` to their trusted-curators setting before the endorsement can affect
canonical selection.
