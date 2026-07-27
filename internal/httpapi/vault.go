package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/ssan9876/keyhole/internal/store"
)

// itemJSON is the wire shape of an item. Pointers for the nullable fields so a
// personal item sends `"collectionId": null` rather than an empty string a
// client would have to special-case.
type itemJSON struct {
	ID             string  `json:"id"`
	CollectionID   *string `json:"collectionId"`
	OwnerUserID    string  `json:"ownerUserId"`
	Ciphertext     string  `json:"ciphertext"`
	WrappedItemKey string  `json:"wrappedItemKey"`
	Revision       int64   `json:"revision"`
	CreatedAt      string  `json:"createdAt"`
	UpdatedAt      string  `json:"updatedAt"`
	DeletedAt      *string `json:"deletedAt"`
}

func toItemJSON(item store.Item) itemJSON {
	out := itemJSON{
		ID:             item.ID,
		OwnerUserID:    item.OwnerUserID,
		Ciphertext:     item.Ciphertext,
		WrappedItemKey: item.WrappedItemKey,
		Revision:       item.Revision,
		CreatedAt:      item.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      item.UpdatedAt.Format(time.RFC3339),
	}
	if item.CollectionID.Valid {
		collection := item.CollectionID.String
		out.CollectionID = &collection
	}
	if item.DeletedAt.Valid {
		deleted := item.DeletedAt.Time.Format(time.RFC3339)
		out.DeletedAt = &deleted
	}
	return out
}

type folderJSON struct {
	ID            string  `json:"id"`
	EncryptedName string  `json:"encryptedName"`
	Revision      int64   `json:"revision"`
	CreatedAt     string  `json:"createdAt"`
	UpdatedAt     string  `json:"updatedAt"`
	DeletedAt     *string `json:"deletedAt"`
}

func toFolderJSON(folder store.Folder) folderJSON {
	out := folderJSON{
		ID:            folder.ID,
		EncryptedName: folder.EncryptedName,
		Revision:      folder.Revision,
		CreatedAt:     folder.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     folder.UpdatedAt.Format(time.RFC3339),
	}
	if folder.DeletedAt.Valid {
		deleted := folder.DeletedAt.Time.Format(time.RFC3339)
		out.DeletedAt = &deleted
	}
	return out
}

// writeStoreError is the one place a store error becomes a response.
//
// The default branch is the important one: a transient SQLite error must not
// reach a client as text, and must not be reported as the caller's fault. Only
// ValidationError is safe to echo, because the client wrote it.
func (s *Server) writeStoreError(w http.ResponseWriter, r *http.Request, what string, err error) {
	var validation *store.ValidationError
	switch {
	case errors.Is(err, store.ErrNotFound):
		WriteError(w, http.StatusNotFound, CodeNotFound, "not found")
	case errors.As(err, &validation):
		WriteError(w, http.StatusBadRequest, CodeBadRequest, validation.Error())
	default:
		s.logger.Error(what, "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not process the request")
	}
}

// isCollectionMember reports whether the user may act inside a collection.
// A caller who is not a member is told the collection does not exist, so the
// endpoint cannot be used to map the membership graph one guess at a time.
func (s *Server) isCollectionMember(r *http.Request, collectionID, userID string) (bool, error) {
	var count int
	err := s.store.DB().QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM collection_memberships WHERE collection_id = ? AND user_id = ?`,
		collectionID, userID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
