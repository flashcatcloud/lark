package lark

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func sealCallbackRequest(t *testing.T, key, body string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	require.NoError(t, err)
	pad := aes.BlockSize - len(body)%aes.BlockSize
	plain := append([]byte(body), []byte(strings.Repeat(string(rune(pad)), pad))...)
	ciphertext := make([]byte, aes.BlockSize+len(plain))
	cipher.NewCBCEncrypter(block, ciphertext[:aes.BlockSize]).CryptBlocks(ciphertext[aes.BlockSize:], plain)
	return fmt.Sprintf(`{"encrypt":%q}`, base64.StdEncoding.EncodeToString(ciphertext))
}

func TestCallbackRequestErrorsReturnBadRequest(t *testing.T) {
	const challenge = `{"type":"url_verification","challenge":"c-123","token":"verify-token"}`
	// This valid ciphertext, sealed with sender-key-39, passes padding
	// validation under new-key but cannot be decoded as a callback request.
	const wrongKeyValidPadding = `{"encrypt":"AAAAAAAAAAAAAAAAAAAAALtMakf+QNAjWhlZXUwFfYV+Uso58j+Cq4lVJh6/ykWu0nmFOai9ExA7WCnyVZHOfMcDs9PJbNznClu0t5AviAQsB8Rki7SiooeQCg+7fvLj"}`
	for _, tt := range []struct {
		name, key, body, wantError string
	}{
		{"invalid JSON", "new-key", `not json`, "parse callback request"},
		{"null request", "new-key", `null`, "callback request must be an object"},
		{"missing v2 header", "new-key", `{"schema":"2.0"}`, "header is nil"},
		{"missing Encrypt Key", "", sealCallbackRequest(t, "new-key", challenge), "encrypt key not set"},
		{"invalid base64", "new-key", `{"encrypt":"not base64"}`, "illegal base64 data"},
		{"short ciphertext", "new-key", `{"encrypt":"AA=="}`, "ciphertext too short"},
		{"empty ciphertext", "new-key", `{"encrypt":"AAAAAAAAAAAAAAAAAAAAAA=="}`, "empty after decryption"},
		{"unaligned ciphertext", "new-key", `{"encrypt":"AAAAAAAAAAAAAAAAAAAAAAA="}`, "ciphertext length"},
		{"wrong key with valid padding", "new-key", wrongKeyValidPadding, "parse callback request"},
		{"invalid decrypted JSON", "new-key", sealCallbackRequest(t, "new-key", `not json`), "parse callback request"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cli := New(WithEventCallbackVerify(tt.key, "verify-token"))
			response := httptest.NewRecorder()
			require.NotPanics(t, func() {
				cli.EventCallback.ListenCallback(context.Background(), strings.NewReader(tt.body), response)
			})
			require.Equal(t, http.StatusBadRequest, response.Code)
			var result struct {
				Err string `json:"err"`
			}
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
			require.Contains(t, result.Err, tt.wantError)
		})
	}
}

func TestCallbackWrongKeysReturnBadRequest(t *testing.T) {
	const challenge = `{"type":"url_verification","challenge":"c-123","token":"verify-token"}`
	cli := New(WithEventCallbackVerify("new-key", "verify-token"))
	for i := 0; i < 4096; i++ {
		body := sealCallbackRequest(t, fmt.Sprintf("sender-key-%d", i), challenge)
		response := httptest.NewRecorder()
		cli.EventCallback.ListenCallback(context.Background(), strings.NewReader(body), response)
		require.Equal(t, http.StatusBadRequest, response.Code, "sender key %d", i)
		require.True(t, json.Valid(response.Body.Bytes()), "sender key %d: %q", i, response.Body.String())
	}
}

func TestCallbackHandlerErrorsRemainInternalServerErrors(t *testing.T) {
	const body = `{"schema":"2.0","header":{"event_id":"card-event","event_type":"card.action.trigger"},"event":{"action":{"tag":"button","value":{"ack":"1"}}}}`
	for _, message := range []string{"backend unavailable", "invalid padding", "invalid PKCS7 padding"} {
		t.Run(message, func(t *testing.T) {
			cli := New()
			cli.EventCallback.HandlerEventV2CardActionTrigger(func(context.Context, *Lark, string, *EventHeaderV2, *EventV2CardActionTrigger) (string, error) {
				return "", errors.New(message)
			})
			response := httptest.NewRecorder()
			cli.EventCallback.ListenCallback(context.Background(), strings.NewReader(body), response)
			require.Equal(t, http.StatusInternalServerError, response.Code)
			require.JSONEq(t, fmt.Sprintf(`{"err":%q}`, message), response.Body.String())
		})
	}
}

func TestCallbackVerificationAndEventResponses(t *testing.T) {
	const challenge = `{"type":"url_verification","challenge":"c-123","token":"verify-token"}`
	for _, body := range []string{challenge, sealCallbackRequest(t, "new-key", challenge)} {
		cli := New(WithEventCallbackVerify("new-key", "verify-token"))
		response := httptest.NewRecorder()
		cli.EventCallback.ListenCallback(context.Background(), strings.NewReader(body), response)
		require.Equal(t, http.StatusOK, response.Code)
		require.JSONEq(t, `{"challenge":"c-123"}`, response.Body.String())
	}

	cli := New()
	cli.EventCallback.HandlerEventV2CardActionTrigger(func(context.Context, *Lark, string, *EventHeaderV2, *EventV2CardActionTrigger) (string, error) {
		return `{"toast":{"type":"success","content":"done"}}`, nil
	})
	response := httptest.NewRecorder()
	cli.EventCallback.ListenCallback(context.Background(), strings.NewReader(`{"schema":"2.0","header":{"event_id":"card-event","event_type":"card.action.trigger"},"event":{"action":{"tag":"button"}}}`), response)
	require.Equal(t, http.StatusOK, response.Code)
	require.JSONEq(t, `{"toast":{"type":"success","content":"done"}}`, response.Body.String())
}

func TestCallbackSecurityErrorsReturnForbidden(t *testing.T) {
	cli := New(WithEventCallbackVerify("new-key", "verify-token"))
	response := httptest.NewRecorder()
	cli.EventCallback.ListenSecurityCallback(context.Background(), http.Header{}, strings.NewReader(`{"schema":"2.0","header":{"event_id":"card-event","event_type":"card.action.trigger","token":"wrong-token"},"event":{"action":{"tag":"button"}}}`), response)
	require.Equal(t, http.StatusForbidden, response.Code)
	require.JSONEq(t, `{"err":"verification token check failed"}`, response.Body.String())
}
