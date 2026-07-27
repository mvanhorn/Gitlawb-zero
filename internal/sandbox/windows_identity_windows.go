//go:build windows

package sandbox

// Windows sandbox principals.
//
// Every other Windows backend here derives its token from the CALLING user via
// CreateRestrictedToken, which is why the sandbox can constrain writes but not
// reads: a deny ACE that would stop the sandboxed child reading a credential
// store names the same account Zero itself runs as, so it would lock Zero out
// too. Reads therefore stay on the caller's identity and
// credentialDenyReadPaths is a no-op on Windows (#662, #675).
//
// This file provisions a SEPARATE local account per workspace, held in one
// managed local group, so the sandbox has an identity of its own. A deny-read
// ACE naming that principal denies the sandboxed child and nothing else, and
// the same SID is what a firewall rule or a write grant can be keyed to. The
// accounts are created by the elevated `zero sandbox setup` path because
// NetUserAdd requires administrator rights; nothing here runs unelevated.
//
// Provisioning is idempotent: the "already exists" status from each API is a
// success, so setup can be re-run safely and a partially provisioned machine
// converges.

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// windowsSandboxGroupName holds every sandbox principal. Grouping them means
	// an ACE can name the group once instead of enumerating accounts, and it
	// gives setup a single place to find what it previously created.
	windowsSandboxGroupName    = "ZeroSandboxUsers"
	windowsSandboxGroupComment = "Zero sandbox principals (managed by zero sandbox setup)"

	// windowsSandboxUserPrefix keeps the accounts recognisable in `net user` and
	// lets cleanup identify what belongs to Zero. Windows caps a local account
	// name at 20 characters, which windowsSandboxUserName respects.
	windowsSandboxUserPrefix  = "zero-sbx-"
	windowsSandboxUserComment = "Zero sandbox principal (managed)"
	windowsSandboxUserNameMax = 20

	// windowsSandboxOfflineGroupName is what the network block filters are keyed
	// to. Network denial cannot be expressed on a principal's own token the way
	// it is on a restricted token: the block filters match the offline-marker
	// SID, which is a synthetic capability SID, and LogonUser mints a token from
	// an account's real group memberships rather than from arbitrary SIDs. A
	// principal is therefore denied the network by being a MEMBER of this group,
	// whose SID the filters also match.
	//
	// A group rather than the offline principal's own SID because principals are
	// per workspace: one filter set covers every offline principal on the machine
	// instead of needing a filter per workspace.
	windowsSandboxOfflineGroupName    = "ZeroSandboxOffline"
	windowsSandboxOfflineGroupComment = "Zero sandbox principals denied network access (managed)"
)

// windowsSandboxRole distinguishes the two principals a workspace gets. They are
// separate accounts rather than one account reconfigured per command, because
// the network decision is baked into group membership at setup time and setup
// needs elevation; flipping it per command would need an elevated hop on every
// command.
type windowsSandboxRole string

const (
	// windowsSandboxRoleOffline is a member of the offline group, so the block
	// filters match its token and it has no network.
	windowsSandboxRoleOffline windowsSandboxRole = "offline"
	// windowsSandboxRoleOnline is not, so an approved network command reaches the
	// network while still being read-confined by having its own identity.
	windowsSandboxRoleOnline windowsSandboxRole = "online"
)

// roleTag is the single character that distinguishes the two accounts for a
// workspace. One character because the 20-character account-name limit is
// already tight and every character spent here is a bit of workspace hash lost.
func (role windowsSandboxRole) roleTag() string {
	if role == windowsSandboxRoleOnline {
		return "n"
	}
	return "d"
}

// Win32 status codes that mean "already there". Treated as success so
// provisioning converges instead of failing on a second run.
const (
	nerrSuccess         = 0
	nerrGroupExists     = 2223
	nerrUserExists      = 2224
	errorAliasExists    = 1379
	errorMemberInAlias  = 1378
	errorAccessDenied32 = 5
	nerrUserNotFound    = 2221
)

// USER_INFO_1 privilege and flag values.
const (
	usrPrivUser           = 1
	ufScript              = 0x0001
	ufNormalAccount       = 0x0200
	ufDontExpirePasswd    = 0x10000
	windowsPasswordLength = 24
)

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd              = netapi32.NewProc("NetUserAdd")
	procNetLocalGroupAdd        = netapi32.NewProc("NetLocalGroupAdd")
	procNetLocalGroupAddMembers = netapi32.NewProc("NetLocalGroupAddMembers")
	procNetUserDel              = netapi32.NewProc("NetUserDel")
	procNetUserSetInfo          = netapi32.NewProc("NetUserSetInfo")
	procNetUserGetInfo          = netapi32.NewProc("NetUserGetInfo")
	procNetApiBufferFree        = netapi32.NewProc("NetApiBufferFree")
)

// userInfo1 mirrors USER_INFO_1. Field order and widths must match the Win32
// struct exactly; it is passed to NetUserAdd as a raw buffer.
type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

// userInfo1003 mirrors USER_INFO_1003, the password-only form NetUserSetInfo
// takes when nothing else about the account should change.
type userInfo1003 struct {
	Password *uint16
}

// localGroupInfo1 mirrors LOCALGROUP_INFO_1.
type localGroupInfo1 struct {
	Name    *uint16
	Comment *uint16
}

// localGroupMembersInfo3 mirrors LOCALGROUP_MEMBERS_INFO_3, which identifies a
// member by name rather than SID.
type localGroupMembersInfo3 struct {
	DomainAndName *uint16
}

// windowsSandboxIdentity is a provisioned sandbox principal: the account name
// and the SID that ACEs, tokens and firewall rules are keyed to.
type windowsSandboxIdentity struct {
	Username string
	SID      *windows.SID
}

// String renders the identity for logs without exposing the password, which is
// never stored on this struct.
func (identity windowsSandboxIdentity) String() string {
	if identity.SID == nil {
		return identity.Username
	}
	return identity.Username + " (" + identity.SID.String() + ")"
}

// windowsSandboxUserName derives a stable account name for a workspace key and
// role. The key is hashed by the caller (see windowsSandboxWorkspaceKey) so the
// name reveals no path, and it is truncated to the 20-character local-account
// limit. The same workspace and role always map to the same account, so
// re-running setup reuses the principals instead of accumulating accounts.
//
// The role tag sits before the hash rather than after it, so truncation eats
// hash characters and never the tag. A name that lost its tag would collide the
// two roles onto one account, which would silently put an online principal in
// the offline group or the reverse.
func windowsSandboxUserName(workspaceKey string, role windowsSandboxRole) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return -1
		}
	}, workspaceKey)
	if cleaned == "" {
		cleaned = "default"
	}
	name := windowsSandboxUserPrefix + role.roleTag() + cleaned
	if len(name) > windowsSandboxUserNameMax {
		name = name[:windowsSandboxUserNameMax]
	}
	return name
}

// newWindowsSandboxPassword returns a random password for a sandbox principal.
// The account is never signed into interactively: the password exists only so
// LogonUser can mint a token for it, so it is generated per provisioning run,
// handed straight to the caller, and never persisted by this file. Base32 of
// crypto/rand bytes keeps it alphanumeric, which satisfies complexity policies
// that reject unusual punctuation, and a fixed suffix guarantees the mixed-case
// and digit classes even if the random draw happens to omit one.
func newWindowsSandboxPassword() (string, error) {
	raw := make([]byte, windowsPasswordLength)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate sandbox password: %w", err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	if len(encoded) > windowsPasswordLength {
		encoded = encoded[:windowsPasswordLength]
	}
	return "Zs1!" + encoded, nil
}

// netAPIStatus converts a netapi32 return value into an error, treating the
// supplied status codes as success so callers can spell out which "already
// exists" results are expected.
func netAPIStatus(call string, status uintptr, okStatuses ...uintptr) error {
	if status == nerrSuccess {
		return nil
	}
	for _, ok := range okStatuses {
		if status == ok {
			return nil
		}
	}
	if status == errorAccessDenied32 {
		return fmt.Errorf("%s: access denied (run `zero sandbox setup` from an elevated terminal)", call)
	}
	return fmt.Errorf("%s: status %d", call, status)
}

// ensureWindowsSandboxGroup creates the managed local group, or leaves it alone
// when it already exists.
func ensureWindowsSandboxGroup() error {
	return ensureWindowsLocalGroup(windowsSandboxGroupName, windowsSandboxGroupComment)
}

// ensureWindowsSandboxOfflineGroup creates the group the network block filters
// are keyed to. Membership of it is what denies a principal the network, so it
// has to exist before any offline principal is created.
func ensureWindowsSandboxOfflineGroup() error {
	return ensureWindowsLocalGroup(windowsSandboxOfflineGroupName, windowsSandboxOfflineGroupComment)
}

// Wires the portable network planner to the Windows group lookup. Done here so
// windows_network.go can stay free of Win32 calls while still folding the group
// into the filter identity set.
func init() {
	resolveWindowsSandboxOfflineGroupSIDHook = resolveWindowsSandboxOfflineGroupSID
}

// resolveWindowsSandboxOfflineGroupSID returns the SID the block filters key to.
//
// Reports ("", nil) when the group does not exist, which is the state before
// setup has ever run. Callers fold that into "no extra identity", so the plan
// they compute matches what an un-provisioned machine would produce rather than
// failing to build at all.
func resolveWindowsSandboxOfflineGroupSID() (string, error) {
	sid, _, accountType, err := windows.LookupSID("", windowsSandboxOfflineGroupName)
	if err != nil {
		if errors.Is(err, windows.ERROR_NONE_MAPPED) {
			return "", nil
		}
		return "", fmt.Errorf("look up %s: %w", windowsSandboxOfflineGroupName, err)
	}
	// A local group is an alias. Anything else means the name has been taken by
	// something that is not ours, and keying network filters to it would be both
	// wrong and a way to affect unrelated accounts.
	if accountType != windows.SidTypeAlias && accountType != windows.SidTypeGroup {
		return "", fmt.Errorf("%s resolves to a non-group account (type %d)", windowsSandboxOfflineGroupName, accountType)
	}
	return sid.String(), nil
}

// ensureWindowsLocalGroup creates a local group, or leaves it alone when it
// already exists.
func ensureWindowsLocalGroup(groupName string, groupComment string) error {
	name, err := windows.UTF16PtrFromString(groupName)
	if err != nil {
		return err
	}
	comment, err := windows.UTF16PtrFromString(groupComment)
	if err != nil {
		return err
	}
	info := localGroupInfo1{Name: name, Comment: comment}
	status, _, _ := procNetLocalGroupAdd.Call(
		0, // local machine
		1, // level: LOCALGROUP_INFO_1
		uintptr(unsafe.Pointer(&info)),
		0,
	)
	// The struct holds pointers into Go memory that the syscall dereferences, so
	// it has to stay reachable until the call has returned.
	runtime.KeepAlive(info)
	runtime.KeepAlive(name)
	runtime.KeepAlive(comment)
	return netAPIStatus("NetLocalGroupAdd", status, nerrGroupExists, errorAliasExists)
}

// ensureWindowsSandboxUser creates a sandbox account with the supplied password.
// The account is a plain local user with no home directory or logon script,
// flagged so its password never expires (nobody is there to rotate it) and so it
// is a normal, enabled account LogonUser can authenticate.
//
// It reports whether the account already existed, because NetUserAdd leaves such
// an account completely untouched, password included. The caller has to reset it
// or the secret it goes on to store would not be the account's password at all.
func ensureWindowsSandboxUser(username string, password string) (bool, error) {
	name, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return false, err
	}
	secret, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return false, err
	}
	comment, err := windows.UTF16PtrFromString(windowsSandboxUserComment)
	if err != nil {
		return false, err
	}
	info := userInfo1{
		Name:     name,
		Password: secret,
		Priv:     usrPrivUser,
		Comment:  comment,
		Flags:    ufScript | ufNormalAccount | ufDontExpirePasswd,
	}
	status, _, _ := procNetUserAdd.Call(
		0, // local machine
		1, // level: USER_INFO_1
		uintptr(unsafe.Pointer(&info)),
		0,
	)
	// The struct holds pointers into Go memory that the call dereferences, so
	// everything it borrows has to outlive the call.
	runtime.KeepAlive(info)
	runtime.KeepAlive(name)
	runtime.KeepAlive(secret)
	runtime.KeepAlive(comment)
	if status == nerrUserExists {
		return true, nil
	}
	return false, netAPIStatus("NetUserAdd", status)
}

// resetWindowsSandboxUserPassword sets the password on an account that already
// existed, so the secret the caller stores is actually the account's password.
//
// Without this, re-running setup produced a fresh random password, wrote it to
// disk, and left the account authenticating with the old one, so every later
// command failed to log on with a principal that looked correctly provisioned.
func resetWindowsSandboxUserPassword(username string, password string) error {
	name, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	secret, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	// USER_INFO_1003 is a password-only update, so nothing else about the
	// account is disturbed.
	info := userInfo1003{Password: secret}
	status, _, _ := procNetUserSetInfo.Call(
		0, // local machine
		uintptr(unsafe.Pointer(name)),
		1003, // level: USER_INFO_1003
		uintptr(unsafe.Pointer(&info)),
		0,
	)
	runtime.KeepAlive(info)
	runtime.KeepAlive(name)
	runtime.KeepAlive(secret)
	return netAPIStatus("NetUserSetInfo", status)
}

// addWindowsSandboxUserToGroup puts a principal in the managed group, ignoring
// the status that means it is already a member.
func addWindowsSandboxUserToGroup(username string) error {
	return addWindowsUserToLocalGroup(windowsSandboxGroupName, username)
}

// addWindowsSandboxUserToOfflineGroup is what actually denies a principal the
// network: the block filters match this group's SID, and LogonUser puts the
// group into the token it mints for a member.
func addWindowsSandboxUserToOfflineGroup(username string) error {
	return addWindowsUserToLocalGroup(windowsSandboxOfflineGroupName, username)
}

// addWindowsUserToLocalGroup puts an account in a local group, ignoring the
// status that means it is already a member.
func addWindowsUserToLocalGroup(groupName string, username string) error {
	group, err := windows.UTF16PtrFromString(groupName)
	if err != nil {
		return err
	}
	member, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	entry := localGroupMembersInfo3{DomainAndName: member}
	status, _, _ := procNetLocalGroupAddMembers.Call(
		0, // local machine
		uintptr(unsafe.Pointer(group)),
		3, // level: LOCALGROUP_MEMBERS_INFO_3
		uintptr(unsafe.Pointer(&entry)),
		1, // one member
	)
	runtime.KeepAlive(entry)
	runtime.KeepAlive(group)
	runtime.KeepAlive(member)
	return netAPIStatus("NetLocalGroupAddMembers", status, errorMemberInAlias)
}

// errWindowsSandboxNameCollision reports that the derived account name is taken
// by a local account Zero did not create. Setup refuses rather than adopting it.
var errWindowsSandboxNameCollision = errors.New("a local account with Zero's derived sandbox name already exists and was not created by Zero")

// windowsSandboxUserIsManaged reports whether a local account is one Zero
// created, by reading back the comment provisioning stamps on it.
//
// This is the gate on adopting an existing account. The name is derived, not
// discovered, so an account can be sitting on it for reasons that have nothing
// to do with Zero, and taking it over means resetting a stranger's password.
//
// A missing account is not managed rather than an error, so callers can use this
// as a plain question without special-casing absence.
func windowsSandboxUserIsManaged(username string) (bool, error) {
	name, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return false, err
	}
	var buffer *byte
	status, _, _ := procNetUserGetInfo.Call(
		0, // local machine
		uintptr(unsafe.Pointer(name)),
		1, // level: USER_INFO_1
		uintptr(unsafe.Pointer(&buffer)),
	)
	runtime.KeepAlive(name)
	if status == nerrUserNotFound {
		return false, nil
	}
	if err := netAPIStatus("NetUserGetInfo", status); err != nil {
		return false, err
	}
	if buffer == nil {
		return false, nil
	}
	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(buffer)))
	info := (*userInfo1)(unsafe.Pointer(buffer))
	if info.Comment == nil {
		return false, nil
	}
	return windows.UTF16PtrToString(info.Comment) == windowsSandboxUserComment, nil
}

// resolveWindowsSandboxSID looks up the SID for a provisioned principal. The SID
// is the durable handle: account names can collide with a pre-existing local
// user, so every ACE and firewall rule is keyed to the SID rather than the name.
func resolveWindowsSandboxSID(username string) (*windows.SID, error) {
	sid, _, accountType, err := windows.LookupSID("", username)
	if err != nil {
		return nil, fmt.Errorf("look up sandbox principal %q: %w", username, err)
	}
	if accountType != windows.SidTypeUser {
		return nil, fmt.Errorf("sandbox principal %q resolves to a non-user account (type %d)", username, accountType)
	}
	return sid, nil
}

// provisionWindowsSandboxIdentity ensures the managed group and one sandbox
// principal for workspaceKey exist, and returns the identity plus the password
// the caller needs to mint a token with LogonUser. It is idempotent, so setup
// can run repeatedly.
//
// The password is returned rather than stored, so no credential is written to
// disk here; that happens a layer up where the secret has somewhere safe to
// live. The returned value is always the account's actual password, including
// when the account already existed, because that case is reset explicitly
// below.
func provisionWindowsSandboxIdentity(workspaceKey string, role windowsSandboxRole) (windowsSandboxIdentity, string, bool, error) {
	if err := ensureWindowsSandboxGroup(); err != nil {
		return windowsSandboxIdentity{}, "", false, err
	}
	// The offline group has to exist before an offline principal joins it, and it
	// is created unconditionally so the network filters can be keyed to its SID
	// whether or not an offline principal has been provisioned yet.
	if err := ensureWindowsSandboxOfflineGroup(); err != nil {
		return windowsSandboxIdentity{}, "", false, err
	}
	username := windowsSandboxUserName(workspaceKey, role)
	password, err := newWindowsSandboxPassword()
	if err != nil {
		return windowsSandboxIdentity{}, "", false, err
	}
	existed, err := ensureWindowsSandboxUser(username, password)
	if err != nil {
		return windowsSandboxIdentity{}, "", false, err
	}
	if existed {
		// Prove the account is ours before touching it. The name is derived from a
		// workspace hash rather than discovered, so it can be occupied by an
		// account that has nothing to do with Zero, whether by coincidence or
		// because somebody created it deliberately. Adopting one means resetting
		// its password, which is not something to do on the strength of a name
		// matching a pattern we generate ourselves.
		managed, err := windowsSandboxUserIsManaged(username)
		if err != nil {
			return windowsSandboxIdentity{}, "", false, err
		}
		if !managed {
			return windowsSandboxIdentity{}, "", false, fmt.Errorf("%w: %q", errWindowsSandboxNameCollision, username)
		}
		// Ours, and NetUserAdd left it untouched, so the password above is not yet
		// its password. Set it, or the secret stored by the caller would never
		// authenticate and every command would fail to log on with a principal
		// that looks perfectly provisioned.
		if err := resetWindowsSandboxUserPassword(username, password); err != nil {
			return windowsSandboxIdentity{}, "", false, err
		}
	}
	if err := addWindowsSandboxUserToGroup(username); err != nil {
		return windowsSandboxIdentity{}, "", !existed, err
	}
	// Membership of the offline group IS the network denial, so it is applied
	// here rather than left to a later step: a principal that reached the runner
	// without it would look correctly provisioned and quietly have the network.
	if role == windowsSandboxRoleOffline {
		if err := addWindowsSandboxUserToOfflineGroup(username); err != nil {
			return windowsSandboxIdentity{}, "", !existed, err
		}
	}
	sid, err := resolveWindowsSandboxSID(username)
	if err != nil {
		return windowsSandboxIdentity{}, "", !existed, err
	}
	return windowsSandboxIdentity{Username: username, SID: sid}, password, !existed, nil
}

// removeWindowsSandboxIdentity deletes a provisioned principal. Callers must
// revoke the principal's ACEs FIRST (see windowsPrincipalRevokePlan): deleting
// the account leaves any surviving ACE naming an unresolvable SID, which is what
// shows up in Explorer as an orphaned entry and is exactly the residue this
// model is meant to avoid.
//
// A missing account is success, so teardown converges the same way provisioning
// does. Requires an elevated caller.
func removeWindowsSandboxIdentity(username string) error {
	// Account names here are derived, not discovered, so this could be pointed at
	// a name that happens to belong to somebody else's local account. Deleting a
	// user is not a recoverable mistake, so ownership is proven before deleting
	// rather than inferred from the name matching a pattern we generate.
	managed, err := windowsSandboxUserIsManaged(username)
	if err != nil {
		return err
	}
	if !managed {
		return nil
	}
	name, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	status, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(name)))
	runtime.KeepAlive(name)
	return netAPIStatus("NetUserDel", status, nerrUserNotFound)
}

// errWindowsSandboxIdentityUnavailable reports that no sandbox principal has
// been provisioned yet, so callers can fall back to the restricted-token
// backend instead of failing the command.
var errWindowsSandboxIdentityUnavailable = errors.New("no Zero sandbox principal is provisioned; run `zero sandbox setup` from an elevated terminal")

// lookupWindowsSandboxIdentity resolves an already-provisioned principal without
// creating anything, so the unelevated command path can discover whether an
// identity exists. It returns errWindowsSandboxIdentityUnavailable when setup
// has not run.
func lookupWindowsSandboxIdentity(workspaceKey string, role windowsSandboxRole) (windowsSandboxIdentity, error) {
	username := windowsSandboxUserName(workspaceKey, role)
	sid, err := resolveWindowsSandboxSID(username)
	if err != nil {
		return windowsSandboxIdentity{}, classifyWindowsSandboxLookupError(err)
	}
	return windowsSandboxIdentity{Username: username, SID: sid}, nil
}

// classifyWindowsSandboxLookupError decides whether a failed SID resolution
// means "setup has not run" or "this principal exists but is unusable".
//
// Only "no such account" is the former. Every other failure is a principal the
// caller must not paper over, including the deliberate refusal in
// resolveWindowsSandboxSID of a name squatted by a group or alias. Collapsing
// those into the unavailable sentinel would turn a real conflict into a silent
// fall back to the restricted token, which is exactly the case that should
// reach the operator rather than be absorbed.
//
// Split out from the lookup so the decision can be asserted on its own: the
// lookup derives its account name from a workspace key, so a test cannot hand
// it a name that resolves to a group.
func classifyWindowsSandboxLookupError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return errWindowsSandboxIdentityUnavailable
	}
	return err
}
