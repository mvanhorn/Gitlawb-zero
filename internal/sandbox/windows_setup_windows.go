//go:build windows

package sandbox

import (
	"fmt"
	"io"

	"golang.org/x/sys/windows"
)

func runWindowsSandboxSetup(config WindowsSandboxSetupConfig, stderr io.Writer) int {
	// Applying the WFP network filters and workspace ACLs requires Administrator
	// rights; without them WFP fails deep inside with a raw ACCESS_DENIED (0x5).
	// Check up front and return an actionable message instead.
	if !windowsProcessIsElevated() {
		fmt.Fprintln(stderr, WindowsSandboxSetupName+": Administrator rights are required. Re-run `zero sandbox setup` from an elevated (Run as administrator) terminal.")
		return 1
	}
	plan, err := BuildWindowsACLPlan(config.commandConfig())
	if err != nil {
		fmt.Fprintln(stderr, WindowsSandboxSetupName+": "+err.Error())
		return 1
	}
	rollback, err := applyWindowsACLPlan(plan)
	if err != nil {
		fmt.Fprintln(stderr, WindowsSandboxSetupName+": "+err.Error())
		return 1
	}
	// Provision this workspace's sandbox principal, when opted in. A principal is
	// a separate local account, so it is created only on an explicit opt-in: it
	// is visible in `net user`, and account creation is exactly the kind of thing
	// endpoint protection and enterprise policy object to. Without the opt-in the
	// capability-SID backend above is the whole of setup, unchanged.
	if windowsSandboxIdentityEnabled(config.commandConfig().Env) {
		principalRollback, err := setupWindowsSandboxPrincipal(config.commandConfig())
		if err != nil {
			if rollbackErr := rollback(); rollbackErr != nil {
				fmt.Fprintf(stderr, "%s: %v; rollback failed: %v\n", WindowsSandboxSetupName, err, rollbackErr)
				return 1
			}
			fmt.Fprintln(stderr, WindowsSandboxSetupName+": "+err.Error())
			return 1
		}
		// Fold the principal into the existing rollback so every later failure
		// path undoes it too, rather than each one having to remember.
		aclRollback := rollback
		rollback = func() error {
			principalErr := principalRollback()
			aclErr := aclRollback()
			if principalErr != nil {
				return principalErr
			}
			return aclErr
		}
	}
	// Built AFTER any principal provisioning, not before. The block filters are
	// keyed to the offline group as well as the offline-marker SID, and that group
	// is created as part of provisioning: planning first would install filters
	// that name only the marker, leaving every offline principal with an open
	// network while looking correctly set up.
	//
	// Mode-INDEPENDENT by design. Which identity a command runs under is what
	// selects allow or deny, so one setup serves both modes.
	networkPlan, err := BuildWindowsNetworkInfraPlan(config.commandConfig())
	if err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			fmt.Fprintf(stderr, "%s: %v; rollback failed: %v\n", WindowsSandboxSetupName, err, rollbackErr)
			return 1
		}
		fmt.Fprintln(stderr, WindowsSandboxSetupName+": "+err.Error())
		return 1
	}
	if err := applyWindowsNetworkPlan(networkPlan); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			fmt.Fprintf(stderr, "%s: %v; rollback failed: %v\n", WindowsSandboxSetupName, err, rollbackErr)
			return 1
		}
		fmt.Fprintln(stderr, WindowsSandboxSetupName+": "+err.Error())
		return 1
	}
	if _, err := WriteWindowsSandboxSetupMarker(config); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			fmt.Fprintf(stderr, "%s: %v; rollback failed: %v\n", WindowsSandboxSetupName, err, rollbackErr)
			return 1
		}
		fmt.Fprintln(stderr, WindowsSandboxSetupName+": "+err.Error())
		return 1
	}
	return 0
}

// windowsProcessIsElevated reports whether the current process runs with an
// elevated (Administrator) token. On any error obtaining the token it returns
// true so the setup proceeds and surfaces the real WFP/ACL error rather than a
// false "needs admin" claim.
func windowsProcessIsElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return true
	}
	defer token.Close()
	return token.IsElevated()
}
