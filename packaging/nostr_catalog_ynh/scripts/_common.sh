#!/bin/bash
# Common variables and helpers shared by install/upgrade/remove.
#
# This packaging has not been exercised against a live YunoHost server (no
# such environment is available where it was written) - it follows the
# packaging v2 helper conventions as documented, but treat it as a first
# draft to validate on a real install before relying on it, same as any
# other untested code path.

pkg_dependencies=""

# nostr-catalogd is a single Go binary; there is no compiled dependency to
# install beyond what resources.sources already downloads in manifest.toml.

nostr_catalogd_env_file="/etc/nostr_catalog/env"
