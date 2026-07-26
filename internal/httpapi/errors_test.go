package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteErrorShape(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusNotFound, CodeNotFound, "no such item")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Error.Code != "not_found" {
		t.Errorf("code = %q, want %q", body.Error.Code, "not_found")
	}
	if body.Error.Message != "no such item" {
		t.Errorf("message = %q, want %q", body.Error.Message, "no such item")
	}
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusCreated, map[string]string{"id": "abc"})

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"id":"abc"}` {
		t.Errorf("body = %q, want %q", got, `{"id":"abc"}`)
	}
}

func TestDecodeJSONAcceptsValidBody(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"x"}`))

	var dst struct {
		Name string `json:"name"`
	}
	if ok := DecodeJSON(rec, req, &dst); !ok {
		t.Fatalf("DecodeJSON returned false; body was %q", rec.Body.String())
	}
	if dst.Name != "x" {
		t.Errorf("Name = %q, want %q", dst.Name, "x")
	}
}

func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"x","surprise":1}`))

	var dst struct {
		Name string `json:"name"`
	}
	// Unknown fields are rejected so a client sending a misspelled key gets
	// told, rather than having it silently ignored — which for a field like
	// recoveryKdfParams would mean a vault that cannot be recovered.
	if ok := DecodeJSON(rec, req, &dst); ok {
		t.Error("DecodeJSON accepted an unknown field")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDecodeJSONRejectsMalformedAndOversizedBodies(t *testing.T) {
	for name, body := range map[string]string{
		"malformed": `{"name":`,
		"oversized": `{"name":"` + strings.Repeat("a", 2<<20) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			var dst struct {
				Name string `json:"name"`
			}
			if ok := DecodeJSON(rec, req, &dst); ok {
				t.Error("DecodeJSON accepted a body it should have rejected")
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}
