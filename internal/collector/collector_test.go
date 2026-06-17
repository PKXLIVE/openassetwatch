package collector

import "testing"

func TestCollectLocalInventoryDoesNotFabricateDeploymentIdentity(t *testing.T) {
	inventory := CollectLocalInventory("site-local")

	if inventory.SiteID != "site-local" {
		t.Fatalf("SiteID = %q, want site-local", inventory.SiteID)
	}
	if inventory.DeploymentID != "" {
		t.Fatalf("DeploymentID = %q, want empty until enrollment identity exists", inventory.DeploymentID)
	}
	if inventory.AgentID != "" {
		t.Fatalf("AgentID = %q, want empty until installed agent identity exists", inventory.AgentID)
	}
	if inventory.SensorID != "" {
		t.Fatalf("SensorID = %q, want empty for agent local collection", inventory.SensorID)
	}
}
