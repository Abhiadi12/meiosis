package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPanickingHandlerBecomesA500AndTheServerKeepsServing(t *testing.T) {
	var logs bytes.Buffer
	s := &Server{log: slog.New(slog.NewTextHandler(&logs, nil))}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/boom", nil)
	s.serveRecovering(&statusRecorder{ResponseWriter: rec, status: http.StatusOK}, r, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("kaboom")
	}))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(logs.String(), "kaboom") || !strings.Contains(logs.String(), "/boom") {
		t.Fatalf("the panic was not logged: %s", logs.String())
	}
	if strings.Contains(rec.Body.String(), "kaboom") {
		t.Fatal("the panic value leaked to the client")
	}
}
