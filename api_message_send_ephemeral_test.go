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
		Card:    card,
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
	req := &SendEphemeralMessageReq{
		ChatID:  "oc_test",
		OpenID:  "ou_test",
		MsgType: MsgTypeInteractive,
		Card: &MessageContentCard{
			Modules: []MessageContentCardModule{
				MessageContentCardModuleDIV{
					Text: &MessageContentCardObjectText{Tag: "lark_md", Content: "hello"},
				},
			},
		},
	}

	body, err := json.Marshal(req)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"chat_id":"oc_test",
		"open_id":"ou_test",
		"msg_type":"interactive",
		"card":{"elements":[{"tag":"div","text":{"tag":"lark_md","content":"hello"}}]}
	}`, string(body))
}
