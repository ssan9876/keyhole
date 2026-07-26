// Package httpapi is the HTTP surface: routing, middleware, and handlers.
//
// Named httpapi rather than http, deliberately: a package named http shadows
// the standard library import at every call site inside it.
package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// ErrorCode is a stable identifier a client can branch on. Messages are for
// humans and may change; codes may not.
type ErrorCode string

const (
	CodeBadRequest   ErrorCode = "bad_request"
	CodeUnauthorized ErrorCode = "unauthorized"
	CodeForbidden    ErrorCode = "forbidden"
	CodeNotFound     ErrorCode = "not_found"
	CodeConflict     ErrorCode = "conflict"
	CodeRateLimited  ErrorCode = "rate_limited"
	CodeInternal     ErrorCode = "internal"
)

// maxRequestBody caps decoded request bodies at 1 MiB. Vault items are small;
// anything larger is a mistake or an attempt to exhaust memory.
const maxRequestBody = 1 << 20

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func WriteError(w http.ResponseWriter, status int, code ErrorCode, message string) {
	WriteJSON(w, status, errorEnvelope{Error: errorBody{Code: code, Message: message}})
}

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		// The status line is already sent, so this can only be logged.
		slog.Error("encode response", "error", err)
	}
}

// DecodeJSON reads a JSON body into dst. It writes the error response itself
// and returns false when it fails, so handlers read as:
//
//	if !DecodeJSON(w, r, &req) { return }
//
// Unknown fields are rejected. Silently dropping a misspelled key is how a
// client ships without recoveryKdfParams and nobody notices until a user tries
// to recover a vault.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		var maxBytes *http.MaxBytesError
		switch {
		case errors.As(err, &maxBytes):
			WriteError(w, http.StatusBadRequest, CodeBadRequest, "request body is too large")
		case strings.Contains(err.Error(), "unknown field"):
			WriteError(w, http.StatusBadRequest, CodeBadRequest, "request contains an unrecognized field")
		default:
			WriteError(w, http.StatusBadRequest, CodeBadRequest, "request body is not valid JSON")
		}
		return false
	}

	// A second value in the stream means the client sent something we would
	// only partly honour.
	if decoder.More() {
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "request body must contain a single JSON object")
		return false
	}
	return true
}
