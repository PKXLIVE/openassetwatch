package audit

import "time"

type Event struct {
	Action    string    `json:"action"`
	Actor     string    `json:"actor,omitempty"`
	SiteID    string    `json:"site_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func NewEvent(action string) Event {
	return Event{
		Action:    action,
		CreatedAt: time.Now().UTC(),
	}
}
