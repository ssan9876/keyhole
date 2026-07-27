package httpapi

import (
	"errors"
	"net/http"

	"github.com/ssan9876/keyhole/internal/store"
)

type folderRequest struct {
	EncryptedName string `json:"encryptedName"`
	Revision      int64  `json:"revision"`
}

// requireOwnFolder resolves a folder the caller owns. Folders are personal:
// there is no shared-folder concept, so ownership is the whole rule. A folder
// belonging to someone else reports not-found rather than forbidden.
func (s *Server) requireOwnFolder(w http.ResponseWriter, r *http.Request, id, userID string) (store.Folder, bool) {
	folder, err := s.store.FolderByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "load folder", err)
		return store.Folder{}, false
	}
	allowed, err := s.store.CanAccessFolder(r.Context(), userID, folder)
	if err != nil {
		s.writeStoreError(w, r, "check folder access", err)
		return store.Folder{}, false
	}
	if !allowed {
		WriteError(w, http.StatusNotFound, CodeNotFound, "not found")
		return store.Folder{}, false
	}
	return folder, true
}

func (s *Server) handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	var req folderRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	folder, err := s.store.CreateFolder(r.Context(), user.ID, req.EncryptedName)
	if err != nil {
		s.writeStoreError(w, r, "create folder", err)
		return
	}
	WriteJSON(w, http.StatusCreated, toFolderJSON(folder))
}

func writeFolderConflict(w http.ResponseWriter, current store.Folder) {
	WriteJSON(w, http.StatusConflict, struct {
		Error  errorBody  `json:"error"`
		Folder folderJSON `json:"folder"`
	}{
		Error: errorBody{
			Code:    CodeConflict,
			Message: "this folder changed on the server since you last synced",
		},
		Folder: toFolderJSON(current),
	})
}

func (s *Server) handleUpdateFolder(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	var req folderRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if _, ok := s.requireOwnFolder(w, r, id, user.ID); !ok {
		return
	}

	folder, err := s.store.UpdateFolder(r.Context(), id, req.Revision, req.EncryptedName)
	if errors.Is(err, store.ErrRevisionConflict) {
		writeFolderConflict(w, folder)
		return
	}
	if err != nil {
		s.writeStoreError(w, r, "update folder", err)
		return
	}
	WriteJSON(w, http.StatusOK, toFolderJSON(folder))
}

func (s *Server) handleDeleteFolder(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	if _, ok := s.requireOwnFolder(w, r, id, user.ID); !ok {
		return
	}

	folder, err := s.store.DeleteFolder(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "delete folder", err)
		return
	}
	WriteJSON(w, http.StatusOK, toFolderJSON(folder))
}
