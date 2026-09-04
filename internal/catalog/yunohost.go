package catalog

import (
	"fmt"

	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
)

// YunoHostCatalog is the top-level shape used by the v3 application catalog.
type YunoHostCatalog struct {
	Antifeatures []any                  `json:"antifeatures"`
	Apps         map[string]YunoHostApp `json:"apps"`
	Categories   []any                  `json:"categories"`
	Security     SecurityIndex          `json:"security"`
}

// SecurityIndex is the versioned empty security index accepted by YunoHost.
// Future Nostr security attestations can populate Apps and System.
type SecurityIndex struct {
	Version int              `json:"version"`
	Apps    map[string][]any `json:"apps"`
	System  map[string][]any `json:"system"`
}

type YunoHostApp struct {
	AddedInCatalog         int64          `json:"added_in_catalog"`
	AlternativeBranches    map[string]any `json:"alternative_branches"`
	Antifeatures           []string       `json:"antifeatures"`
	Category               string         `json:"category,omitempty"`
	Featured               bool           `json:"featured"`
	Git                    GitSource      `json:"git"`
	HighQuality            bool           `json:"high_quality"`
	ID                     string         `json:"id"`
	LastUpdate             int64          `json:"lastUpdate"`
	Level                  int            `json:"level"`
	LogoHash               string         `json:"logo_hash,omitempty"`
	Manifest               map[string]any `json:"manifest"`
	Maintained             bool           `json:"maintained"`
	PotentialAlternativeTo []string       `json:"potential_alternative_to"`
	State                  string         `json:"state"`
	Subtags                []string       `json:"subtags"`
}

type GitSource struct {
	Branch   string `json:"branch"`
	Revision string `json:"revision"`
	URL      string `json:"url"`
}

// Translate converts a validated declaration and the authoritative manifest
// fetched from its pinned repository into the YunoHost v3 app entry.
func Translate(declaration protocol.AppDeclaration, manifest map[string]any, publishedAt int64) (YunoHostApp, error) {
	return TranslateWithLogo(declaration, manifest, "", publishedAt)
}

// TranslateWithLogo converts a verified package and optional local logo into
// the YunoHost v3 app representation.
func TranslateWithLogo(declaration protocol.AppDeclaration, manifest map[string]any, logoHash string, publishedAt int64) (YunoHostApp, error) {
	if manifest == nil {
		return YunoHostApp{}, fmt.Errorf("manifest is required")
	}
	if manifestID, ok := manifest["id"].(string); !ok || manifestID != declaration.AppID {
		return YunoHostApp{}, fmt.Errorf("manifest id does not match declaration app ID")
	}
	if manifestVersion, ok := manifest["version"].(string); !ok || manifestVersion != declaration.Version {
		return YunoHostApp{}, fmt.Errorf("manifest version does not match declaration version")
	}
	return YunoHostApp{
		AddedInCatalog:      publishedAt,
		AlternativeBranches: map[string]any{},
		Antifeatures:        []string{},
		Category:            declaration.Category,
		Git:                 GitSource{Branch: "main", Revision: declaration.Commit, URL: declaration.Repository},
		ID:                  declaration.AppID,
		LastUpdate:          publishedAt,
		// YunoHost treats levels <= 4 as bad quality and blocks upgrades. This
		// catalogue has independently verified the repository, commit, manifest,
		// and content hashes, but has not run YunoHost CI. Level 5 is therefore a
		// compatibility floor that keeps custom-catalogue installs upgradeable;
		// HighQuality remains false so this is not presented as fully vetted.
		Level:                  5,
		LogoHash:               logoHash,
		Manifest:               manifest,
		Maintained:             true,
		PotentialAlternativeTo: []string{},
		State:                  "working",
		Subtags:                []string{},
	}, nil
}
