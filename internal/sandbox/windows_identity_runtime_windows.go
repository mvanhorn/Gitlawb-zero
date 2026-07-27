//go:build windows

package sandbox

// Using a sandbox principal at command time.
//
// This is the seam between the identity model and the existing runner. It is
// deliberately fail-soft: when no principal is provisioned, when the secret is
// missing, or when the opt-in is off, it reports "not available" and the caller
// keeps using today's restricted-token backend. Only an outright failure to log
// on with a principal that IS provisioned surfaces as an error, because that
// means setup ran but the identity is broken, and silently downgrading the
// sandbox in that case would be the wrong kind of quiet.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// windowsSandboxIdentityEnv opts a machine into the principal backend while it
// is still experimental. Provisioning is inert without it, so an existing
// install keeps the restricted-token behaviour until someone turns this on.
const windowsSandboxIdentityEnv = "ZERO_WINDOWS_SANDBOX_IDENTITY"

// windowsSandboxIdentityEnabled reports whether the principal backend is opted
// into. Kept as a function so the check reads the environment at call time,
// which is what lets a test or an elevated setup run flip it.
func windowsSandboxIdentityEnabled(env map[string]string) bool {
	if value, ok := env[windowsSandboxIdentityEnv]; ok {
		return strings.TrimSpace(value) == "1"
	}
	return strings.TrimSpace(os.Getenv(windowsSandboxIdentityEnv)) == "1"
}

// windowsSandboxWorkspaceKey derives the per-workspace key a principal is named
// after. It hashes the workspace root the same way the sandbox runtime keys its
// own state, so the account name leaks no path and one workspace always maps to
// one principal.
func windowsSandboxWorkspaceKey(workspaceRoots []string) string {
	root := ""
	for _, candidate := range workspaceRoots {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			root = normalizeProfilePath(trimmed)
			break
		}
	}
	if root == "" {
		root = "default"
	}
	digest := sha256.Sum256([]byte(strings.ToLower(root)))
	return hex.EncodeToString(digest[:])
}

// windowsSandboxPrincipalEligible reports whether the principal backend may be
// used for this command at all, before any account or secret is consulted.
//
// Kept separate from the lookup so the decision is observable on its own: on a
// machine with nothing provisioned the lookup declines anyway, which would let a
// missing guard here pass unnoticed.
func windowsSandboxPrincipalEligible(config WindowsSandboxCommandConfig) bool {
	return windowsSandboxIdentityEnabled(config.Env)
}

// windowsSandboxRoleForNetwork maps a command's network mode onto the principal
// that enforces it.
//
// The two roles differ only in membership of the offline group, which the block
// filters are keyed to. That indirection exists because network denial cannot be
// expressed on a logon token the way it is on a restricted token: the restricted
// token carries the offline-marker SID as a restricting SID, and LogonUser has
// no equivalent, since it builds a token from the account's real memberships.
//
// Defaulting anything that is not an explicit allow to the offline principal is
// deliberate. A mode this does not recognise should lose the network, not keep
// it.
func windowsSandboxRoleForNetwork(mode NetworkMode) windowsSandboxRole {
	if mode == NetworkAllow {
		return windowsSandboxRoleOnline
	}
	return windowsSandboxRoleOffline
}

// windowsSandboxPrincipalToken returns a token for this workspace's sandbox
// principal.
//
// ok is false, with a nil error, whenever the principal backend simply is not in
// play: the opt-in is off, setup has not provisioned an account, or no secret is
// stored. The caller falls back to the restricted token in those cases. An error
// means the identity exists but could not be used, which is worth surfacing
// rather than downgrading around.
func windowsSandboxPrincipalToken(config WindowsSandboxCommandConfig) (windows.Token, bool, error) {
	if !windowsSandboxPrincipalEligible(config) {
		return 0, false, nil
	}
	key := windowsSandboxWorkspaceKey(config.WorkspaceRoots)
	// The network mode picks the principal. Both are provisioned by setup; the
	// offline one is in the group the block filters match, so choosing here is
	// what enforces the mode.
	role := windowsSandboxRoleForNetwork(config.PermissionProfile.Network.Mode)
	identity, err := lookupWindowsSandboxIdentity(key, role)
	if err != nil {
		if errors.Is(err, errWindowsSandboxIdentityUnavailable) {
			// Not provisioned: fall back quietly, this is the default state.
			return 0, false, nil
		}
		// The name resolves to something that is not a usable principal, most
		// likely squatted by a local group or alias. That is a conflict an
		// operator has to see, not a reason to pretend setup never ran.
		return 0, false, err
	}
	secretPath, err := windowsSandboxSecretPath(config.SandboxHome, identity.Username)
	if err != nil {
		return 0, false, err
	}
	password, err := readWindowsSandboxSecret(secretPath)
	if err != nil {
		if errors.Is(err, errWindowsSandboxIdentityUnavailable) {
			// The account exists but its password does not. Setup was interrupted
			// or the secret was removed; fall back rather than fail the command.
			return 0, false, nil
		}
		return 0, false, err
	}
	token, err := logonWindowsSandboxPrincipal(identity.Username, password)
	if err != nil {
		// Provisioned but unusable. Surface it: a wrong password or a revoked
		// batch-logon right is a broken sandbox, not an absent one.
		return 0, false, err
	}
	return token, true, nil
}

// provisionWindowsSandboxPrincipalForSetup does the elevated half: create the
// account, grant it the batch logon right, and store its password locked to the
// invoking user. Called from `zero sandbox setup`.
//
// The password is written BEFORE the caller applies any ACL plan, so a setup
// that fails partway leaves a principal that can at least be logged on and
// therefore cleaned up, rather than an account nothing holds the secret for.
func provisionWindowsSandboxPrincipalForSetup(config WindowsSandboxCommandConfig, role windowsSandboxRole) (windowsSandboxIdentity, error) {
	key := windowsSandboxWorkspaceKey(config.WorkspaceRoots)
	identity, password, created, err := provisionWindowsSandboxIdentity(key, role)

	// Undo whatever this run actually did, in reverse, on any failure after the
	// account exists. Without it a failure between creating the account and
	// storing its secret left the account behind with no caller able to remove
	// it: the rollback the setup path installs is only built once this function
	// has returned successfully.
	//
	// Scoped to what THIS run created on purpose. An account that already existed
	// and belongs to Zero is a working principal from an earlier setup, and
	// deleting it because a later run failed would turn a partial failure into a
	// total one.
	rightsGranted := false
	// Resolved from the account name rather than the identity, so it is known
	// before anything can fail. Deriving it later, after the rights grant, left
	// the one window this cleanup exists for uncovered: provisioning ALWAYS sets
	// the password, including resetting a pre-existing account's, so from the
	// moment it returns the stored secret is already stale. A failure before the
	// path was computed then had nothing to remove.
	secretPath, secretPathErr := windowsSandboxSecretPath(config.SandboxHome, windowsSandboxUserName(key, role))
	undo := func() {
		// Unconditionally, not only when this run wrote one. Provisioning has
		// already replaced the account's password by the time any of this can
		// fail, so whatever is on disk cannot authenticate. Absent beats stale:
		// the command path treats a missing secret as "not provisioned" and falls
		// back, while a stale one fails the logon and reports a broken sandbox.
		if secretPath != "" {
			_ = removeWindowsSandboxSecret(secretPath)
		}
		if identity.SID != nil && rightsGranted {
			_ = revokeWindowsSandboxLogonRights(identity.SID)
		}
		if created {
			_ = removeWindowsSandboxIdentity(identity.Username)
		}
	}

	if err != nil {
		// provisionWindowsSandboxIdentity can fail after creating the account, so
		// this path needs the same cleanup even though nothing below ran.
		undo()
		return windowsSandboxIdentity{}, err
	}
	if err := grantWindowsSandboxLogonRights(identity.SID); err != nil {
		undo()
		return windowsSandboxIdentity{}, err
	}
	rightsGranted = true
	if secretPathErr != nil {
		undo()
		return windowsSandboxIdentity{}, secretPathErr
	}
	// The secret is rewritten every run so it stays in step with the account.
	// provisionWindowsSandboxIdentity guarantees the password it returns is the
	// account's real one, resetting it explicitly when the account already
	// existed and belongs to Zero, so this write is always storing something that
	// can log on.
	if err := writeWindowsSandboxSecret(secretPath, password); err != nil {
		undo()
		return windowsSandboxIdentity{}, err
	}
	return identity, nil
}

// setupWindowsSandboxPrincipal provisions this workspace's principal and grants
// it the filesystem access its permission profile describes. It returns a
// rollback that undoes everything it created, so a later setup step failing does
// not leave a half-provisioned account behind.
//
// Rollback order is the inverse of creation and matters: ACEs are revoked BEFORE
// the account is deleted, because removing the account first would leave ACEs
// naming a SID that no longer resolves, which is the orphaned-entry residue this
// model exists to avoid.
func setupWindowsSandboxPrincipal(config WindowsSandboxCommandConfig) (func() error, error) {
	// Both roles are provisioned regardless of the profile this setup ran with.
	// Setup needs elevation and a command does not, so a command whose network
	// mode differs from the one setup happened to see must still find a principal
	// waiting; provisioning lazily would mean an unelevated command discovering it
	// needs an account it cannot create.
	roles := []windowsSandboxRole{windowsSandboxRoleOffline, windowsSandboxRoleOnline}

	var undo []func() error
	rollback := func() error {
		// Unwind in reverse, and keep going after a failure so one broken step
		// cannot strand everything behind it. The first error is reported.
		var firstErr error
		for i := len(undo) - 1; i >= 0; i-- {
			if err := undo[i](); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}

	filesystem := config.PermissionProfile.FileSystem
	for _, role := range roles {
		identity, err := provisionWindowsSandboxPrincipalForSetup(config, role)
		if err != nil {
			_ = rollback()
			return nil, err
		}
		undo = append(undo, func() error { return removeWindowsSandboxPrincipalForSetup(config, role) })

		// Both principals get the same filesystem access. They differ only in
		// network reach, so granting the offline one less would make an approved
		// network command see a different filesystem than an ordinary one.
		plan, err := buildWindowsPrincipalACLPlan(windowsPrincipalACLInput{
			PrincipalSID: identity.SID.String(),
			WriteRoots:   filesystem.WriteRoots,
			ReadRoots:    filesystem.ReadRoots,
			DenyRead:     filesystem.DenyRead,
		})
		if err != nil {
			_ = rollback()
			return nil, err
		}
		revertACL, err := applyWindowsACLPlan(plan)
		if err != nil {
			_ = rollback()
			return nil, err
		}
		// ACEs are reverted before the account they name is deleted, because
		// removing the account first leaves ACEs naming a SID that no longer
		// resolves, which is the orphaned residue this model exists to avoid.
		// Appending after the removal closure puts it earlier in the reverse
		// unwind, which is what gets that ordering.
		undo = append(undo, revertACL)
	}
	return rollback, nil
}

// removeWindowsSandboxPrincipalForSetup retires a workspace's principal: secret
// first, then the account. ACE revocation is the caller's job and must happen
// before this, or ACEs naming a deleted SID are left behind.
func removeWindowsSandboxPrincipalForSetup(config WindowsSandboxCommandConfig, role windowsSandboxRole) error {
	key := windowsSandboxWorkspaceKey(config.WorkspaceRoots)
	username := windowsSandboxUserName(key, role)
	secretPath, err := windowsSandboxSecretPath(config.SandboxHome, username)
	if err != nil {
		return err
	}
	if err := removeWindowsSandboxSecret(secretPath); err != nil {
		return err
	}
	// Drop the LSA account rights before the account itself. Deleting the account
	// first would leave its rights behind keyed to a SID that no longer resolves,
	// which is the same orphaned residue the trustee-keyed ACE revocation exists
	// to avoid. A principal that was never provisioned has no SID to resolve and
	// nothing to revoke, so that case is not an error.
	if identity, err := lookupWindowsSandboxIdentity(key, role); err == nil {
		if err := revokeWindowsSandboxLogonRights(identity.SID); err != nil {
			return err
		}
	} else if !errors.Is(err, errWindowsSandboxIdentityUnavailable) {
		return err
	}
	return removeWindowsSandboxIdentity(username)
}
