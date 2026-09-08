package lark

import (
	"encoding/json"
	"errors"
)

func (r SendEphemeralMessageReq) MarshalJSON() ([]byte, error) {
	if r.Card != nil && len(r.CardV2) > 0 {
		return nil, errors.New("lark: SendEphemeralMessageReq Card and CardV2 cannot both be set")
	}

	var card any
	if len(r.CardV2) > 0 {
		card = r.CardV2
	} else if r.Card != nil {
		card = r.Card
	}

	type request SendEphemeralMessageReq
	return json.Marshal(struct {
		request
		Card any `json:"card,omitempty"`
	}{
		request: request(r),
		Card:    card,
	})
}
