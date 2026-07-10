package sandbox

import (
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

func TestTranslatePolicy(t *testing.T) {
	tests := []struct {
		name         string
		capabilities *config.Capabilities
		wantPolicy   string
		wantAllow    []string
		wantBlock    []string
		wantBypass   []string
	}{
		{
			name:         "nil capabilities returns full deny",
			capabilities: nil,
			wantPolicy:   "DENY",
			wantAllow:    nil,
			wantBlock:    []string{"169.254.169.254/32"},
			wantBypass:   []string{"localhost", "127.0.0.1", "::1"},
		},
		{
			name: "explicit empty egress returns full deny",
			capabilities: &config.Capabilities{
				Network: &config.NetworkCaps{
					Egress: []config.EgressRule{},
					Deny:   []string{},
				},
			},
			wantPolicy: "DENY",
			wantAllow:  nil,
			wantBlock:  []string{"169.254.169.254/32"},
			wantBypass: []string{"localhost", "127.0.0.1", "::1"},
		},
		{
			name: "domains become allow_hosts with :443",
			capabilities: &config.Capabilities{
				Network: &config.NetworkCaps{
					Egress: []config.EgressRule{
						{Host: "api.github.com"},
						{Host: "registry.npmjs.org"},
					},
				},
			},
			wantPolicy: "DENY",
			wantAllow:  []string{"api.github.com:443", "registry.npmjs.org:443"},
			wantBlock:  []string{"169.254.169.254/32"},
			wantBypass: []string{"localhost", "127.0.0.1", "::1"},
		},
		{
			name: "egress with explicit port preserves port",
			capabilities: &config.Capabilities{
				Network: &config.NetworkCaps{
					Egress: []config.EgressRule{
						{Host: "example.com", Port: 8080},
					},
				},
			},
			wantPolicy: "DENY",
			wantAllow:  []string{"example.com:8080"},
		},
		{
			name: "deny list becomes block_cidrs",
			capabilities: &config.Capabilities{
				Network: &config.NetworkCaps{
					Deny: []string{"10.0.0.0/8", "192.168.0.0/16"},
				},
			},
			wantPolicy: "DENY",
			wantBlock:  []string{"169.254.169.254/32", "10.0.0.0/8", "192.168.0.0/16"},
		},
		{
			name: "metadata endpoint always blocked even with explicit allows",
			capabilities: &config.Capabilities{
				Network: &config.NetworkCaps{
					Egress: []config.EgressRule{{Host: "api.github.com"}},
				},
			},
			wantBlock: []string{"169.254.169.254/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TranslatePolicy("test-vm", tt.capabilities)

			if got.VMName != "test-vm" {
				t.Errorf("VMName = %q, want %q", got.VMName, "test-vm")
			}
			if tt.wantPolicy != "" && got.Policy != tt.wantPolicy {
				t.Errorf("Policy = %q, want %q", got.Policy, tt.wantPolicy)
			}
			if tt.wantAllow != nil {
				assertStringSlice(t, "AllowHosts", got.AllowHosts, tt.wantAllow)
			}
			if tt.wantBlock != nil {
				assertContainsAll(t, "BlockCIDRs", got.BlockCIDRs, tt.wantBlock)
			}
			if tt.wantBypass != nil {
				assertStringSlice(t, "BypassHosts", got.BypassHosts, tt.wantBypass)
			}
		})
	}
}

func assertStringSlice(t *testing.T, field string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s length = %d, want %d\n  got:  %v\n  want: %v", field, len(got), len(want), got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, want %q", field, i, got[i], want[i])
		}
	}
}

func assertContainsAll(t *testing.T, field string, got []string, want []string) {
	t.Helper()
	set := make(map[string]bool, len(got))
	for _, s := range got {
		set[s] = true
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("%s missing %q (got %v)", field, w, got)
		}
	}
}
