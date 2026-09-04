package lark

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSendEphemeralMessageReqMarshalsV2Card(t *testing.T) {
	card := json.RawMessage(`{"schema":"2.0","body":{"elements":[]}}`)
	req := &SendEphemeralMessageReq{
		ChatID:  "oc_test",
		OpenID:  "ou_test",
		MsgType: MsgTypeInteractive,
		CardV2:  card,
	}

	body, err := json.Marshal(req)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"chat_id":"oc_test",
		"open_id":"ou_test",
		"msg_type":"interactive",
		"card":{"schema":"2.0","body":{"elements":[]}}
	}`, string(body))
}

func TestSendEphemeralMessageReqKeepsV1CardCompatibility(t *testing.T) {
	card := &MessageContentCard{
		Modules: []MessageContentCardModule{
			MessageContentCardModuleDIV{
				Text: &MessageContentCardObjectText{Tag: "lark_md", Content: "hello"},
			},
		},
	}
	req := &SendEphemeralMessageReq{
		ChatID:  "oc_test",
		OpenID:  "ou_test",
		MsgType: MsgTypeInteractive,
		Card:    card,
	}
	var typedCard *MessageContentCard = req.Card
	require.Same(t, card, typedCard)

	body, err := json.Marshal(req)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"chat_id":"oc_test",
		"open_id":"ou_test",
		"msg_type":"interactive",
		"card":{"elements":[{"tag":"div","text":{"tag":"lark_md","content":"hello"}}]}
	}`, string(body))
}

func TestSendEphemeralMessageReqRejectsBothCardVersions(t *testing.T) {
	req := &SendEphemeralMessageReq{
		Card:   &MessageContentCard{},
		CardV2: json.RawMessage(`{"schema":"2.0","body":{"elements":[]}}`),
	}

	_, err := json.Marshal(req)
	require.ErrorContains(t, err, "Card and CardV2 cannot both be set")
}
