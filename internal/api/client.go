package api

type ClientConfig struct {
	ConnectorID string `json:"connector_id,omitempty"`
	SiteID      string `json:"site_id,omitempty"`
}

func CheckInPath() string {
	return "/api/v1/collectors/checkin"
}

func InventoryPath() string {
	return "/api/v1/collectors/inventory"
}
