package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/ssan9876/keyhole/internal/store"
)

type collectionJSON struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Role                string `json:"role"`
	SealedCollectionKey string `json:"sealedCollectionKey"`
	CreatedBy           string `json:"createdBy"`
	CreatedAt           string `json:"createdAt"`
}

func toCollectionJSON(c store.CollectionWithMembership) collectionJSON {
	return collectionJSON{
		ID:                  c.ID,
		Name:                c.Name,
		Role:                c.Role,
		SealedCollectionKey: c.SealedCollectionKey,
		CreatedBy:           c.CreatedBy,
		CreatedAt:           c.CreatedAt.Format(time.RFC3339),
	}
}

type pendingGrantJSON struct {
	CollectionID   string `json:"collectionId"`
	CollectionName string `json:"collectionName"`
	UserID         string `json:"userId"`
	Role           string `json:"role"`
	RequestedBy    string `json:"requestedBy"`
	CreatedAt      string `json:"createdAt"`
}

func toPendingGrantJSON(g store.PendingGrant) pendingGrantJSON {
	return pendingGrantJSON{
		CollectionID:   g.CollectionID,
		CollectionName: g.CollectionName,
		UserID:         g.UserID,
		Role:           g.Role,
		RequestedBy:    g.RequestedBy,
		CreatedAt:      g.CreatedAt.Format(time.RFC3339),
	}
}

// requireManager resolves the caller's authority over one collection.
//
// A manager of the collection, or an admin, may manage its membership. The two
// are not the same power: a manager holds the collection key and can therefore
// complete a grant, while an admin can only request one. That asymmetry is the
// cryptographic guarantee showing through, not an oversight.
//
// A caller with neither standing gets 404 when they are not a member — the
// collection's existence is not theirs to learn — and 403 when they are a
// plain member, since they already know it exists.
func (s *Server) requireManager(w http.ResponseWriter, r *http.Request, collectionID string) bool {
	user, _ := UserFrom(r.Context())

	membership, err := s.store.MembershipFor(r.Context(), collectionID, user.ID)
	switch {
	case err == nil:
		if membership.Role == "manager" || user.Role == "admin" {
			return true
		}
		WriteError(w, http.StatusForbidden, CodeForbidden,
			"only a manager of this collection can change its membership")
		return false
	case errors.Is(err, store.ErrNotFound):
		if user.Role != "admin" {
			WriteError(w, http.StatusNotFound, CodeNotFound, "no such collection")
			return false
		}
		// An admin who is not a member still administers the collection, but
		// only if it exists.
		if _, err := s.store.CollectionByID(r.Context(), collectionID); err != nil {
			s.writeStoreError(w, r, "load collection", err)
			return false
		}
		return true
	default:
		s.writeStoreError(w, r, "load membership", err)
		return false
	}
}

type createCollectionRequest struct {
	Name                string `json:"name"`
	SealedCollectionKey string `json:"sealedCollectionKey"`
}

func (s *Server) handleCreateCollection(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	var req createCollectionRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	collection, err := s.store.CreateCollection(r.Context(), req.Name, user.ID, req.SealedCollectionKey)
	if err != nil {
		s.writeStoreError(w, r, "create collection", err)
		return
	}
	WriteJSON(w, http.StatusCreated, collectionJSON{
		ID:                  collection.ID,
		Name:                collection.Name,
		Role:                "manager",
		SealedCollectionKey: req.SealedCollectionKey,
		CreatedBy:           collection.CreatedBy,
		CreatedAt:           collection.CreatedAt.Format(time.RFC3339),
	})
}

func (s *Server) handleListCollections(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	collections, err := s.store.CollectionsForUser(r.Context(), user.ID)
	if err != nil {
		s.writeStoreError(w, r, "list collections", err)
		return
	}
	grants, err := s.pendingGrantsFor(r, user)
	if err != nil {
		s.writeStoreError(w, r, "list pending grants", err)
		return
	}

	out := make([]collectionJSON, 0, len(collections))
	for _, collection := range collections {
		out = append(out, toCollectionJSON(collection))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"collections":   out,
		"pendingGrants": grants,
	})
}

// pendingGrantsFor returns what this caller should see. A member sees the
// grants they can actually fulfil; an admin sees all of them, because an admin
// needs to know a grant they requested is still waiting on someone else.
func (s *Server) pendingGrantsFor(r *http.Request, user store.User) ([]pendingGrantJSON, error) {
	var grants []store.PendingGrant
	var err error
	if user.Role == "admin" {
		grants, err = s.store.AllPendingGrants(r.Context())
	} else {
		grants, err = s.store.PendingGrantsFulfillableBy(r.Context(), user.ID)
	}
	if err != nil {
		return nil, err
	}
	out := make([]pendingGrantJSON, 0, len(grants))
	for _, grant := range grants {
		out = append(out, toPendingGrantJSON(grant))
	}
	return out, nil
}

func (s *Server) handleListPendingGrants(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())

	grants, err := s.pendingGrantsFor(r, user)
	if err != nil {
		s.writeStoreError(w, r, "list pending grants", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"pendingGrants": grants})
}

func (s *Server) handleDeleteCollection(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	if err := s.store.DeleteCollection(r.Context(), id); err != nil {
		s.writeStoreError(w, r, "delete collection", err)
		return
	}
	if err := s.store.AppendAudit(r.Context(), user.ID, "collection.delete", "collection:"+id, ""); err != nil {
		s.logger.Error("audit collection delete", "id", RequestIDFrom(r.Context()), "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

type addMemberRequest struct {
	UserID              string `json:"userId"`
	Role                string `json:"role"`
	SealedCollectionKey string `json:"sealedCollectionKey"`
}

// handleAddMember takes one of two paths, and the status code says which.
//
// With a sealed key the caller has done the crypto themselves and membership
// is immediate: 201. Without one the server records an intention it cannot
// carry out — it holds no collection key and never will — so it answers 202
// and waits for a member's client to complete the grant. Answering 201 in that
// case would tell the admin the user has access when they do not.
func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())
	collectionID := r.PathValue("id")

	var req addMemberRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if !s.requireManager(w, r, collectionID) {
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}

	// The target must be a real, active account. Recording a grant against an
	// id that does not resolve leaves an entry no client can ever fulfil.
	target, err := s.store.UserByID(r.Context(), req.UserID)
	if err != nil || target.Status != "active" {
		WriteError(w, http.StatusNotFound, CodeNotFound, "no such user")
		return
	}

	if req.SealedCollectionKey == "" {
		if err := s.store.CreatePendingGrant(r.Context(), collectionID, req.UserID, req.Role, actor.ID); err != nil {
			s.writeStoreError(w, r, "create pending grant", err)
			return
		}
		WriteJSON(w, http.StatusAccepted, map[string]any{
			"status": "pending",
			"message": "recorded. A member of this collection must seal the key " +
				"to this user before they gain access.",
		})
		return
	}

	// Supplying a sealed key requires actually holding the collection key,
	// which only a member does. An admin who is not a member cannot get here
	// with a real blob, and a fabricated one would lock the target out.
	if _, err := s.store.MembershipFor(r.Context(), collectionID, actor.ID); err != nil {
		s.writeStoreError(w, r, "load membership", err)
		return
	}
	if err := s.store.FulfilGrantOrAdd(r.Context(), collectionID, req.UserID,
		req.SealedCollectionKey, req.Role, actor.ID); err != nil {
		s.writeStoreError(w, r, "add member", err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "granted"})
}

func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())
	collectionID := r.PathValue("id")
	userID := r.PathValue("userId")

	if !s.requireManager(w, r, collectionID) {
		return
	}
	if err := s.store.RemoveMember(r.Context(), collectionID, userID, actor.ID); err != nil {
		s.writeStoreError(w, r, "remove member", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type fulfilGrantRequest struct {
	UserID              string `json:"userId"`
	SealedCollectionKey string `json:"sealedCollectionKey"`
}

// handleFulfilGrant completes a grant an admin could only request. The caller
// must be a manager AND a member: only a member holds the key to seal.
func (s *Server) handleFulfilGrant(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())
	collectionID := r.PathValue("id")

	var req fulfilGrantRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	membership, err := s.store.MembershipFor(r.Context(), collectionID, actor.ID)
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, http.StatusNotFound, CodeNotFound, "no such collection")
		return
	}
	if err != nil {
		s.writeStoreError(w, r, "load membership", err)
		return
	}
	if membership.Role != "manager" {
		WriteError(w, http.StatusForbidden, CodeForbidden,
			"only a manager of this collection can fulfil grants")
		return
	}

	if err := s.store.FulfilGrant(r.Context(), collectionID, req.UserID,
		req.SealedCollectionKey, actor.ID); err != nil {
		s.writeStoreError(w, r, "fulfil grant", err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "granted"})
}

type memberJSON struct {
	UserID    string `json:"userId"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	GrantedAt string `json:"grantedAt"`
}

// handleListMembers is a directory, not a key distribution channel: it
// deliberately omits every sealed_collection_key. Each member's blob opens the
// collection for them alone, and handing the whole set to any caller would put
// every one of them in one response.
func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	collectionID := r.PathValue("id")

	if _, err := s.store.MembershipFor(r.Context(), collectionID, user.ID); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.writeStoreError(w, r, "load membership", err)
			return
		}
		if user.Role != "admin" {
			WriteError(w, http.StatusNotFound, CodeNotFound, "no such collection")
			return
		}
	}

	memberships, err := s.store.MembershipsOf(r.Context(), collectionID)
	if err != nil {
		s.writeStoreError(w, r, "list members", err)
		return
	}

	out := make([]memberJSON, 0, len(memberships))
	for _, membership := range memberships {
		member, err := s.store.UserByID(r.Context(), membership.UserID)
		if err != nil {
			s.writeStoreError(w, r, "load member", err)
			return
		}
		out = append(out, memberJSON{
			UserID:    member.ID,
			Name:      member.Name,
			Email:     member.Email,
			Role:      membership.Role,
			GrantedAt: membership.GrantedAt.Format(time.RFC3339),
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"members": out})
}
