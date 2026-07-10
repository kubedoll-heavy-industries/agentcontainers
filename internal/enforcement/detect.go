package enforcement

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
)

// Level represents the enforcement mechanism in use, ordered from strongest
// to weakest.
type Level int

const (
	// LevelGRPC delegates enforcement to an agentcontainer-enforcer gRPC sidecar.
	LevelGRPC Level = iota

	// LevelNone indicates no enforcement mechanism is available.
	LevelNone
)

// String returns the string representation of the enforcement level.
func (l Level) String() string {
	switch l {
	case LevelGRPC:
		return "grpc"
	case LevelNone:
		return "none"
	default:
		return "unknown"
	}
}

// DetectLevel probes the system and returns the best available enforcement level.
func DetectLevel() Level {
	// Check for agentcontainer-enforcer sidecar via gRPC health check.
	if target := os.Getenv("AC_ENFORCER_ADDR"); target != "" {
		if probeEnforcerHealth(target) {
			return LevelGRPC
		}
	}

	return LevelNone
}

// ProbeEnforcerHealth checks if the agentcontainer-enforcer sidecar is reachable via gRPC.
// It returns true if the health check succeeds within a 2-second timeout.
func ProbeEnforcerHealth(target string) bool {
	return probeEnforcerHealth(target)
}

// probeEnforcerHealth checks if the agentcontainer-enforcer sidecar is reachable via gRPC.
func probeEnforcerHealth(target string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if socketPath, ok := strings.CutPrefix(target, "unix://"); ok {
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}))
	}
	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return false
	}
	defer conn.Close() //nolint:errcheck
	client := healthgrpc.NewHealthClient(conn)
	resp, err := client.Check(ctx, &healthgrpc.HealthCheckRequest{
		Service: "agentcontainers.enforcer.v1.Enforcer",
	})
	if err != nil {
		return false
	}
	return resp.GetStatus() == healthgrpc.HealthCheckResponse_SERVING
}

// NewStrategy creates a Strategy for the given enforcement level.
//
// When AC_ENFORCER_TLS_CERT, AC_ENFORCER_TLS_KEY, and AC_ENFORCER_TLS_CA are
// set, the gRPC connection uses mTLS. When only AC_ENFORCER_TLS_CA is set,
// server-only TLS verification is used. Otherwise insecure transport is used.
func NewStrategy(level Level) Strategy {
	switch level {
	case LevelGRPC:
		target := os.Getenv("AC_ENFORCER_ADDR")
		if target == "" {
			target = "127.0.0.1:50051"
		}
		opts, err := GRPCOptsFromEnv()
		if err != nil {
			return &FailClosedStrategy{}
		}
		s, err := NewGRPCStrategy(target, opts...)
		if err != nil {
			return &FailClosedStrategy{}
		}
		return s
	default:
		return &FailClosedStrategy{}
	}
}
