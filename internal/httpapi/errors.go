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
	"sync/atomic"
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

// writeLogger is where WriteJSON reports an encode failure.
//
// WriteError and WriteJSON are free functions, called from handlers, from
// recoverPanic, and from tests — every endpoint in the next plan will call
// them. Threading a *slog.Logger through would change two exported signatures
// at 33 non-test call sites and oblige every future handler to carry a logger
// into every error write, all to serve one line that fires when a response body
// fails to encode. So: a package-level default, set once from New, rather than
// the global slog.
//
// atomic.Pointer, not a plain var, because tests construct servers freely and
// two of them racing on a plain assignment is a data race the race detector
// would rightly flag. Last writer wins, which is correct: a process has one
// configured logger, and in a test binary every server's logger discards.
var writeLogger atomic.Pointer[slog.Logger]

// setWriteLogger points the encode-failure path at the configured logger.
func setWriteLogger(logger *slog.Logger) {
	if logger != nil {
		writeLogger.Store(logger)
	}
}

func writeLoggerOrDefault() *slog.Logger {
	if logger := writeLogger.Load(); logger != nil {
		return logger
	}
	// Reachable only if WriteJSON is called before any server exists, which in
	// practice means a test.
	return slog.Default()
}

func WriteError(w http.ResponseWriter, status int, code ErrorCode, message string) {
	WriteJSON(w, status, errorEnvelope{Error: errorBody{Code: code, Message: message}})
}

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		// The status line is already sent, so this can only be logged.
		writeLoggerOrDefault().Error("encode response", "error", err)
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
	return DecodeJSONLimit(w, r, dst, maxRequestBody)
}

// DecodeJSONLimit is DecodeJSON with an explicit cap. Only the bulk import
// route raises it: a vault export is thousands of items, and forcing the client
// to send them one per request turns an import into thousands of round trips.
// Everything else keeps the 1 MiB default, because a single item is small and
// anything larger is a mistake or an attempt to exhaust memory.
func DecodeJSONLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)

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
