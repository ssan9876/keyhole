package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ssan9876/keyhole/internal/store"
)

// adminUserJSON is the admin's view of an account. Every key-material column
// is absent by construction rather than by filtering: this struct simply has
// no field for them, so a future column cannot leak by being added to User.
//
// Spec section 10 names this as a security test — an admin holds no ability to
// read another user's vault, and that is enforced cryptographically. Returning
// wrapped blobs here would not break the crypto, but it would hand an attacker
// who compromised one admin session every user's material to grind offline.
type adminUserJSON struct {
	ID               string `json:"id"`
	Email            string `json:"email"`
	Name             string `json:"name"`
	Role             string `json:"role"`
	Status           string `json:"status"`
	HasPendingInvite bool   `json:"hasPendingInvite"`
	CreatedAt        string `json:"createdAt"`
}

func toAdminUserJSON(user store.UserSummary) adminUserJSON {
	return adminUserJSON{
		ID:               user.ID,
		Email:            user.Email,
		Name:             user.Name,
		Role:             user.Role,
		Status:           user.Status,
		HasPendingInvite: user.HasPendingInvite,
		CreatedAt:        user.CreatedAt.Format(time.RFC3339),
	}
}

func (s *Server) inviteURL(token string) string {
	return s.cfg.BaseURL + "/enroll/" + token
}

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.writeStoreError(w, r, "list users", err)
		return
	}
	out := make([]adminUserJSON, 0, len(users))
	for _, user := range users {
		out = append(out, toAdminUserJSON(user))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"users": out})
}

type createUserRequest struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())

	var req createUserRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Role == "" {
		req.Role = "user"
	}

	user, err := s.store.CreatePendingUser(r.Context(), req.Email, req.Name, req.Role)
	if errors.Is(err, store.ErrEmailTaken) {
		WriteError(w, http.StatusConflict, CodeConflict, "an account already exists for that email")
		return
	}
	if err != nil {
		// CreatePendingUser's validation errors are plain errors rather than
		// ValidationError, so they cannot be echoed. A bad role or a malformed
		// address is still the caller's fault.
		WriteError(w, http.StatusBadRequest, CodeBadRequest,
			"email, name, and role must be valid")
		return
	}

	_, token, err := s.store.CreateInvite(r.Context(), user.ID, store.InviteTTL)
	if err != nil {
		s.writeStoreError(w, r, "create invite", err)
		return
	}
	if err := s.store.AppendAudit(r.Context(), actor.ID, "user.create", "user:"+user.ID, ""); err != nil {
		s.logger.Error("audit user create", "id", RequestIDFrom(r.Context()), "error", err)
	}

	// There is no mail server (spec section 1), so the link comes back in this
	// response and the admin hands it over out of band.
	WriteJSON(w, http.StatusCreated, map[string]any{
		"user": toAdminUserJSON(store.UserSummary{User: user, HasPendingInvite: true}),
		// The raw token exists exactly once, here. It cannot be recovered from
		// the database afterwards, by an admin or by anyone who steals it.
		"inviteUrl": s.inviteURL(token),
		"expiresIn": store.InviteTTL.String(),
	})
}

func (s *Server) handleAdminReissueInvite(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "load user", err)
		return
	}
	// Reissuing for an active account would hand someone a second route into a
	// vault that is already set up. A reset is the deliberate way to do that,
	// and it says so.
	if user.Status != "pending" {
		WriteError(w, http.StatusConflict, CodeConflict,
			"this account has already been set up; use reset to start it over")
		return
	}

	_, token, err := s.store.CreateInvite(r.Context(), id, store.InviteTTL)
	if err != nil {
		s.writeStoreError(w, r, "create invite", err)
		return
	}
	if err := s.store.AppendAudit(r.Context(), actor.ID, "user.invite.reissue", "user:"+id, ""); err != nil {
		s.logger.Error("audit invite reissue", "id", RequestIDFrom(r.Context()), "error", err)
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"inviteUrl": s.inviteURL(token),
		"expiresIn": store.InviteTTL.String(),
	})
}

type patchUserRequest struct {
	Status string `json:"status"`
}

func (s *Server) handleAdminPatchUser(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	var req patchUserRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	if err := s.store.SetUserStatus(r.Context(), id, req.Status, actor.ID); err != nil {
		if errors.Is(err, store.ErrLastAdmin) {
			WriteError(w, http.StatusConflict, CodeConflict,
				"this is the only administrator; promote another account first")
			return
		}
		s.writeStoreError(w, r, "set user status", err)
		return
	}

	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "load user", err)
		return
	}
	WriteJSON(w, http.StatusOK, toAdminUserJSON(store.UserSummary{User: user}))
}

type resetUserRequest struct {
	ConfirmEmail string `json:"confirmEmail"`
}

func (s *Server) handleAdminResetUser(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())
	id := r.PathValue("id")

	var req resetUserRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, r, "load user", err)
		return
	}
	// Spec section 3.7 puts the typed-email confirmation in the dialog. It is
	// re-checked here because an irreversible action that destroys a vault must
	// not hinge on a client-side check alone.
	if store.NormalizeEmail(req.ConfirmEmail) != user.Email {
		WriteError(w, http.StatusBadRequest, CodeBadRequest,
			"confirmEmail does not match this account")
		return
	}

	token, err := s.store.ResetUser(r.Context(), id, actor.ID)
	if err != nil {
		s.writeStoreError(w, r, "reset user", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"inviteUrl": s.inviteURL(token),
		"expiresIn": store.InviteTTL.String(),
		"message": "Key material and personal items destroyed. Collection access " +
			"must be re-granted after the user enrolls again.",
	})
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserFrom(r.Context())

	err := s.store.DeleteUser(r.Context(), r.PathValue("id"), actor.ID)
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		WriteError(w, http.StatusConflict, CodeConflict,
			"this is the only administrator; promote another account first")
		return
	case errors.Is(err, store.ErrUserReferenced):
		// Naming the obstacle matters: without it the operator has a database
		// error and no next step. The references are deliberate — deleting an
		// account must not cascade into destroying a shared collection.
		WriteError(w, http.StatusConflict, CodeConflict,
			"this account created a collection or granted a membership. "+
				"Delete or reassign those collections first, or disable the account instead.")
		return
	case err != nil:
		s.writeStoreError(w, r, "delete user", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			WriteError(w, http.StatusBadRequest, CodeBadRequest, "limit must be an integer")
			return
		}
		limit = parsed
	}

	entries, err := s.store.AuditPage(r.Context(), limit, r.URL.Query().Get("before"))
	if err != nil {
		s.writeStoreError(w, r, "read audit log", err)
		return
	}

	type entryJSON struct {
		ID          string `json:"id"`
		ActorUserID string `json:"actorUserId"`
		Action      string `json:"action"`
		Target      string `json:"target"`
		Metadata    string `json:"metadata"`
		CreatedAt   string `json:"createdAt"`
	}
	out := make([]entryJSON, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entryJSON{
			ID:          entry.ID,
			ActorUserID: entry.ActorUserID.String,
			Action:      entry.Action,
			Target:      entry.Target,
			Metadata:    entry.Metadata,
			CreatedAt:   entry.CreatedAt.Format(time.RFC3339),
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// handleAdminListCollections is the membership-graph view. It carries no
// sealed keys: an admin who is not a member holds none, and the server has
// none to give.
func (s *Server) handleAdminListCollections(w http.ResponseWriter, r *http.Request) {
	collections, err := s.store.AllCollections(r.Context())
	if err != nil {
		s.writeStoreError(w, r, "list collections", err)
		return
	}
	grants, err := s.store.AllPendingGrants(r.Context())
	if err != nil {
		s.writeStoreError(w, r, "list pending grants", err)
		return
	}

	type summary struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		CreatedBy   string `json:"createdBy"`
		CreatedAt   string `json:"createdAt"`
		MemberCount int    `json:"memberCount"`
	}
	out := make([]summary, 0, len(collections))
	for _, collection := range collections {
		members, err := s.store.MembershipsOf(r.Context(), collection.ID)
		if err != nil {
			s.writeStoreError(w, r, "count members", err)
			return
		}
		out = append(out, summary{
			ID:          collection.ID,
			Name:        collection.Name,
			CreatedBy:   collection.CreatedBy,
			CreatedAt:   collection.CreatedAt.Format(time.RFC3339),
			MemberCount: len(members),
		})
	}

	pending := make([]pendingGrantJSON, 0, len(grants))
	for _, grant := range grants {
		pending = append(pending, toPendingGrantJSON(grant))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"collections":   out,
		"pendingGrants": pending,
	})
}
