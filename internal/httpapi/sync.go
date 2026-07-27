package httpapi

import (
	"net/http"
	"strconv"
)

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	// An absent cursor is a first run. A present but unparseable one is a
	// client bug: falling back to 0 would silently re-send the entire vault on
	// every poll and hide the bug that caused it.
	var since int64
	if query := r.URL.Query(); query.Has("since") {
		parsed, err := strconv.ParseInt(query.Get("since"), 10, 64)
		if err != nil || parsed < 0 {
			WriteError(w, http.StatusBadRequest, CodeBadRequest,
				"since must be a non-negative integer")
			return
		}
		since = parsed
	}

	result, err := s.store.SyncSince(r.Context(), user.ID, since)
	if err != nil {
		s.writeStoreError(w, r, "sync", err)
		return
	}

	items := make([]itemJSON, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, toItemJSON(item))
	}
	folders := make([]folderJSON, 0, len(result.Folders))
	for _, folder := range result.Folders {
		folders = append(folders, toFolderJSON(folder))
	}

	collections := make([]collectionJSON, 0, len(result.Collections))
	for _, collection := range result.Collections {
		collections = append(collections, toCollectionJSON(collection))
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"revision":    result.Revision,
		"items":       items,
		"folders":     folders,
		"collections": collections,
	})
}
