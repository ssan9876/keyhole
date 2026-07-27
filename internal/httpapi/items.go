package httpapi

import (
	"errors"
	"net/http"

	"github.com/ssan9876/keyhole/internal/store"
)

const (
	// maxBulkItems bounds one import transaction. SQLite tolerates a single
	// writer, so an unbounded batch blocks every other write for as long as it
	// runs. The client chunks; a thousand rows per request keeps a full vault
	// import to a handful of requests.
	maxBulkItems = 1000
	// maxBulkBody is the matching body cap. The 1 MiB default would reject a
	// batch well under the row limit.
	maxBulkBody = 8 << 20
)

// itemRequest's CollectionID is a pointer so an omitted field and an explicit
// null are distinguishable.
//
// With a plain string they are not, and the indistinguishable case loses data:
// a client that PUTs a new body without echoing collectionId would move a
// shared item back to personal, and every other member's next sync would drop
// it with no error anywhere. Task 1's store layer enforces the same
// distinction — nil means "no change" on update.
type itemRequest struct {
	CollectionID   *string `json:"collectionId"`
	Ciphertext     string  `json:"ciphertext"`
	WrappedItemKey string  `json:"wrappedItemKey"`
	Revision       int64   `json:"revision"`
}

func (req itemRequest) input() store.ItemInput {
	return store.ItemInput{
		CollectionID:   req.CollectionID,
		Ciphertext:     req.Ciphertext,
		WrappedItemKey: req.WrappedItemKey,
	}
}

// collectionTarget is the id this request wants the item in, or "" for none.
// Used only for the membership check; the store gets the pointer.
func (req itemRequest) collectionTarget() string {
	if req.CollectionID == nil {
		return ""
	}
	return *req.CollectionID
}

// checkCollectionTarget verifies the caller may place an item in the requested
// collection. It writes the response and returns false when they may not.
func (s *Server) checkCollectionTarget(w http.ResponseWriter, r *http.Request, collectionID, userID string) bool {
	if collectionID == "" {
		return true
	}
	member, err := s.isCollectionMember(r, collectionID, userID)
	if err != nil {
		s.writeStoreError(w, r, "check collection membership", err)
		return false
	}
	if !member {
		WriteError(w, http.StatusNotFound, CodeNotFound, "no such collection")
		return false
	}
	return true
}

func (s *Server) handleCreateItem(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	var req itemRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if !s.checkCollectionTarget(w, r, req.collectionTarget(), user.ID) {
		return
	}

	item, err := s.store.CreateItem(r.Context(), user.ID, req.input())
	if err != nil {
		s.writeStoreError(w, r, "create item", err)
		return
	}
	WriteJSON(w, http.StatusCreated, toItemJSON(item))
}

type bulkItemsRequest struct {
	Items []itemRequest `json:"items"`
}

func (s *Server) handleBulkItems(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	var req bulkItemsRequest
	if !DecodeJSONLimit(w, r, &req, maxBulkBody) {
		return
	}
	if len(req.Items) == 0 {
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "items must not be empty")
		return
	}
	if len(req.Items) > maxBulkItems {
		WriteError(w, http.StatusBadRequest, CodeBadRequest,
			"too many items in one request; send them in smaller batches")
		return
	}

	inputs := make([]store.ItemInput, 0, len(req.Items))
	for _, item := range req.Items {
		if !s.checkCollectionTarget(w, r, item.collectionTarget(), user.ID) {
			return
		}
		inputs = append(inputs, item.input())
	}

	items, err := s.store.CreateItemsBulk(r.Context(), user.ID, inputs)
	if err != nil {
		s.writeStoreError(w, r, "bulk create items", err)
		return
	}

	out := make([]itemJSON, 0, len(items))
	for _, item := range items {
		out = append(out, toItemJSON(item))
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"items": out})
}

// writeItemConflict is the one place the error envelope carries a sibling.
// The client needs the winning row to build a conflicted copy; without it the
// only way to resolve a conflict is to throw one of the two edits away.
func writeItemConflict(w http.ResponseWriter, current store.Item) {
	WriteJSON(w, http.StatusConflict, struct {
		Error errorBody `json:"error"`
		Item  itemJSON  `json:"item"`
	}{
		Error: errorBody{
			Code:    CodeConflict,
			Message: "this item changed on the server since you last synced",
		},
		Item: toItemJSON(current),
	})
}

func (s *Server) handleUpdateItem(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	var req itemRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	// Authorize against the item as it stands before authorizing the target
	// collection. Checking only the target would let anyone who is a member of
	// any collection move someone else's item into it.
	existing, err := s.store.ItemByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "load item", err)
		return
	}
	allowed, err := s.store.CanAccessItem(r.Context(), user.ID, existing)
	if err != nil {
		s.writeStoreError(w, r, "check item access", err)
		return
	}
	if !allowed {
		WriteError(w, http.StatusNotFound, CodeNotFound, "not found")
		return
	}
	if !s.checkCollectionTarget(w, r, req.collectionTarget(), user.ID) {
		return
	}

	item, err := s.store.UpdateItem(r.Context(), id, req.Revision, req.input())
	if errors.Is(err, store.ErrRevisionConflict) {
		writeItemConflict(w, item)
		return
	}
	if err != nil {
		s.writeStoreError(w, r, "update item", err)
		return
	}
	WriteJSON(w, http.StatusOK, toItemJSON(item))
}

func (s *Server) handleDeleteItem(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	existing, err := s.store.ItemByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "load item", err)
		return
	}
	allowed, err := s.store.CanAccessItem(r.Context(), user.ID, existing)
	if err != nil {
		s.writeStoreError(w, r, "check item access", err)
		return
	}
	if !allowed {
		WriteError(w, http.StatusNotFound, CodeNotFound, "not found")
		return
	}

	item, err := s.store.DeleteItem(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "delete item", err)
		return
	}
	WriteJSON(w, http.StatusOK, toItemJSON(item))
}
