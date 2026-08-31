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

No catalogue accepts endorsements automatically yet. A future trust policy can
require one or more endorsements from configured curator identities and use
that result to select a canonical app when multiple publishers use the same
YunoHost app ID.
