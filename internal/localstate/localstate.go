// Package localstate reads the locally installed YunoHost app snapshot that
// a privileged, root-run helper writes out of band (nostr-catalogd itself
// never gains YunoHost API access - see the packaging repo's refresh-timer
// unit). The daemon only ever reads a file root already wrote.
package localstate

import (
	"encoding/json"
	"fmt"
	"os"
)

// InstalledApp is one locally installed YunoHost app, as reported by the
// privileged snapshot helper.
type InstalledApp struct {
	AppID      string `json:"app_id"`
	Repository string `json:"repository"`
}

type snapshotFile struct {
	Apps []InstalledApp `json:"apps"`
}

// Load reads the installed-app snapshot from path. A missing file is not an
// error - it means the snapshot has not been generated yet (fresh install,
// or the refresh timer has not run) - and yields an empty list.
func Load(path string) ([]InstalledApp, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read installed-app snapshot: %w", err)
	}
	var snapshot snapshotFile
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("decode installed-app snapshot: %w", err)
	}
	return snapshot.Apps, nil
}
