//go:build windows

package sandbox

import "testing"

// Setup must stay inert unless the principal backend is explicitly opted into.
// This is the property that makes the branch safe to merge while the privileged
// paths are still being validated: without the opt-in, `zero sandbox setup`
// creates no local account and the capability-SID backend is the whole of setup.
func TestWindowsSandboxIdentityGating(t *testing.T) {
	for name, testCase := range map[string]struct {
		env  map[string]string
		want bool
	}{
		"absent":         {env: map[string]string{}, want: false},
		"empty":          {env: map[string]string{windowsSandboxIdentityEnv: ""}, want: false},
		"zero":           {env: map[string]string{windowsSandboxIdentityEnv: "0"}, want: false},
		"true not one":   {env: map[string]string{windowsSandboxIdentityEnv: "true"}, want: false},
		"one":            {env: map[string]string{windowsSandboxIdentityEnv: "1"}, want: true},
		"one with space": {env: map[string]string{windowsSandboxIdentityEnv: " 1 "}, want: true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := windowsSandboxIdentityEnabled(testCase.env); got != testCase.want {
				t.Fatalf("enabled = %v, want %v for %q", got, testCase.want, testCase.env[windowsSandboxIdentityEnv])
			}
		})
	}
}

// The command environment wins over the process environment, so a run can opt in
// or out without depending on how the parent shell was launched.
func TestWindowsSandboxIdentityEnvOverridesProcess(t *testing.T) {
	t.Setenv(windowsSandboxIdentityEnv, "1")
	if windowsSandboxIdentityEnabled(map[string]string{windowsSandboxIdentityEnv: "0"}) {
		t.Fatal("command env set to 0 must override a process env of 1")
	}
	if !windowsSandboxIdentityEnabled(map[string]string{}) {
		t.Fatal("with no command-env entry the process env should apply")
	}
}

// One workspace maps to one principal, and different workspaces must not share
// an account, or two projects would run under the same identity and could reach
// each other's granted roots.
func TestWindowsSandboxWorkspaceKeyIsStableAndDistinct(t *testing.T) {
	first := windowsSandboxWorkspaceKey([]string{`C:\ws\alpha`})
	again := windowsSandboxWorkspaceKey([]string{`C:\ws\alpha`})
	other := windowsSandboxWorkspaceKey([]string{`C:\ws\beta`})
	if first != again {
		t.Fatalf("key is not stable: %q vs %q", first, again)
	}
	if first == other {
		t.Fatal("two different workspaces produced the same principal key")
	}
	if first == "" {
		t.Fatal("empty key")
	}
	// An empty root list still has to yield a usable key rather than a blank one.
	if windowsSandboxWorkspaceKey(nil) == "" {
		t.Fatal("no workspace roots produced an empty key")
	}
}

// Network denial is enforced by WFP filters keyed to the offline-marker SID,
// which only the restricted token carries. A principal token would leave those
// filters matching nothing, so the principal backend must stand down whenever
// the network is denied rather than silently trading network enforcement for
// read confinement.
// The backend now runs under both network modes, so the opt-in is the only thing
// eligibility turns on. The mode selects which principal is used, not whether one
// is used at all.
func TestPrincipalBackendEligibilityTurnsOnlyOnTheOptIn(t *testing.T) {
	eligible := func(mode NetworkMode, optIn string) bool {
		config := WindowsSandboxCommandConfig{
			SandboxHome:    t.TempDir(),
			WorkspaceRoots: []string{t.TempDir()},
			Env:            map[string]string{windowsSandboxIdentityEnv: optIn},
		}
		config.PermissionProfile.Network.Mode = mode
		return windowsSandboxPrincipalEligible(config)
	}

	for _, mode := range []NetworkMode{NetworkDeny, NetworkAllow} {
		if !eligible(mode, "1") {
			t.Fatalf("principal backend refused with network %q; the mode should choose a principal, not disable the backend", mode)
		}
		if eligible(mode, "0") {
			t.Fatalf("principal backend eligible without the opt-in for network %q", mode)
		}
	}
}

// The network mode is enforced by WHICH principal runs, because the offline one
// is a member of the group the block filters match. Picking the wrong role is
// therefore a silent loss of network enforcement, so the mapping is asserted
// directly rather than inferred from a token that only exists on a provisioned
// machine.
func TestPrincipalRoleFollowsNetworkMode(t *testing.T) {
	if got := windowsSandboxRoleForNetwork(NetworkDeny); got != windowsSandboxRoleOffline {
		t.Fatalf("deny selected %q, want the offline principal; the online one is not in the blocked group and would have the network", got)
	}
	if got := windowsSandboxRoleForNetwork(NetworkAllow); got != windowsSandboxRoleOnline {
		t.Fatalf("allow selected %q, want the online principal", got)
	}
	// Fail closed. An unrecognised mode must lose the network rather than keep it,
	// so anything that is not an explicit allow maps to the offline principal.
	for _, mode := range []NetworkMode{NetworkMode(""), NetworkMode("bogus"), NetworkMode("ALLOW")} {
		if got := windowsSandboxRoleForNetwork(mode); got != windowsSandboxRoleOffline {
			t.Fatalf("unrecognised mode %q selected %q, want the offline principal so an unknown mode fails closed", mode, got)
		}
	}
}
