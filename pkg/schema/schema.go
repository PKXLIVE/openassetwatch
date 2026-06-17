package schema

const InventorySchemaVersion = "oaw.inventory.v1"

var allowedToolFields = map[string]struct{}{
	"approved_scope_id":    {},
	"asset_id":             {},
	"connector_id":         {},
	"domain_id":            {},
	"evidence_artifact_id": {},
	"review_profile":       {},
	"sensor_id":            {},
	"site_id":              {},
}

var forbiddenToolFields = map[string]struct{}{
	"additional_args": {},
	"args":            {},
	"command":         {},
	"file_path":       {},
	"hash":            {},
	"password":        {},
	"script_content":  {},
	"target":          {},
	"url":             {},
	"username":        {},
}

func IsAllowedToolField(field string) bool {
	_, ok := allowedToolFields[field]
	return ok
}

func IsForbiddenToolField(field string) bool {
	_, ok := forbiddenToolFields[field]
	return ok
}
