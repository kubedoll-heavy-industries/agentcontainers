package enforcement

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

// GRPCStrategy delegates enforcement to an agentcontainer-enforcer gRPC sidecar service.
type GRPCStrategy struct {
	client   enforcerapi.EnforcerClient
	conn     *grpc.ClientConn
	level    Level
	events   map[string]chan Event
	cancelFn map[string]context.CancelFunc
	mu       sync.Mutex
}

// GRPCOption configures GRPCStrategy.
type GRPCOption func(*grpcConfig)

type grpcConfig struct {
	dialTimeout time.Duration
	tlsConfig   *tls.Config
	insecure    bool
}

func defaultGRPCConfig() *grpcConfig {
	return &grpcConfig{
		dialTimeout: 5 * time.Second,
		insecure:    true,
	}
}

// WithDialTimeout sets the gRPC dial timeout.
func WithDialTimeout(d time.Duration) GRPCOption {
	return func(c *grpcConfig) {
		c.dialTimeout = d
	}
}

// WithTLSConfig enables TLS with the given configuration.
func WithTLSConfig(tlsConf *tls.Config) GRPCOption {
	return func(c *grpcConfig) {
		c.tlsConfig = tlsConf
		c.insecure = false
	}
}

// WithInsecure explicitly enables insecure mode (no TLS).
func WithInsecure() GRPCOption {
	return func(c *grpcConfig) {
		c.insecure = true
		c.tlsConfig = nil
	}
}

// WithMTLSConfig builds a mutual-TLS configuration from PEM files and enables
// mTLS on the gRPC connection.
//
//   - certFile: path to the client certificate (PEM)
//   - keyFile:  path to the client private key (PEM)
//   - caFile:   path to the CA certificate used to verify the server (PEM)
//
// Returns an error if any file cannot be read or the certificate pool cannot
// be built.
func WithMTLSConfig(certFile, keyFile, caFile string) (GRPCOption, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: load client cert/key: %w", err)
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: read CA cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mtls: failed to parse CA cert from %s", caFile)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}

	return WithTLSConfig(tlsConf), nil
}

// tlsPoolFromPEM parses a PEM-encoded CA certificate into a cert pool.
func tlsPoolFromPEM(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA PEM")
	}
	return pool, nil
}

// GRPCOptsFromEnv derives GRPCOptions from the standard environment variables:
//
//	AC_ENFORCER_TLS_CERT / AC_ENFORCER_TLS_KEY / AC_ENFORCER_TLS_CA
//
// When all three are set, mTLS is configured. When only CA is set, server-only
// TLS is used. When none are set, insecure transport is used.
func GRPCOptsFromEnv() ([]GRPCOption, error) {
	certFile := os.Getenv("AC_ENFORCER_TLS_CERT")
	keyFile := os.Getenv("AC_ENFORCER_TLS_KEY")
	caFile := os.Getenv("AC_ENFORCER_TLS_CA")

	if certFile != "" && keyFile != "" && caFile != "" {
		opt, err := WithMTLSConfig(certFile, keyFile, caFile)
		if err != nil {
			return nil, err
		}
		return []GRPCOption{opt}, nil
	}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool, err := tlsPoolFromPEM(caPEM)
		if err != nil {
			return nil, err
		}
		tlsConf := &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		}
		return []GRPCOption{WithTLSConfig(tlsConf)}, nil
	}

	return []GRPCOption{WithInsecure()}, nil
}

// NewGRPCStrategy creates a gRPC-based enforcement strategy that connects
// to an agentcontainer-enforcer sidecar at the given target address.
func NewGRPCStrategy(target string, opts ...GRPCOption) (*GRPCStrategy, error) {
	cfg := defaultGRPCConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	dialOpts := []grpc.DialOption{}
	if socketPath, ok := strings.CutPrefix(target, "unix://"); ok {
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}))
	}
	if cfg.insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else if cfg.tlsConfig != nil {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(cfg.tlsConfig)))
	} else {
		// Default: system TLS credentials
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("grpc strategy: dial %q: %w", target, err)
	}

	client := enforcerapi.NewEnforcerClient(conn)

	return &GRPCStrategy{
		client:   client,
		conn:     conn,
		level:    LevelGRPC,
		events:   make(map[string]chan Event),
		cancelFn: make(map[string]context.CancelFunc),
	}, nil
}

// Apply registers the container with the enforcer sidecar and applies all policies.
func (s *GRPCStrategy) Apply(ctx context.Context, containerID string, initPID uint32, p *policy.ContainerPolicy) error {
	// Resolve the cgroup path for this container.
	cgroupPath, err := ResolveCgroupPath(containerID)
	if err != nil {
		return fmt.Errorf("grpc strategy: resolve cgroup: %w", err)
	}

	// Register the container with the enforcer, passing init PID for
	// /proc/<pid>/root/ access during secret injection.
	_, err = s.client.RegisterContainer(ctx, &enforcerapi.RegisterContainerRequest{
		ContainerId: containerID,
		CgroupPath:  cgroupPath,
		InitPid:     initPID,
	})
	if err != nil {
		return fmt.Errorf("grpc strategy: register container: %w", err)
	}

	// Apply network policy.
	netReq := translateNetworkPolicy(containerID, p)
	netResp, err := s.client.ApplyNetworkPolicy(ctx, netReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: apply network policy: %w", err)
	}
	if !netResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: network policy failed: %s", netResp.GetError())
	}

	// Apply filesystem policy.
	fsReq := translateFilesystemPolicy(containerID, p)
	fsResp, err := s.client.ApplyFilesystemPolicy(ctx, fsReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: apply filesystem policy: %w", err)
	}
	if !fsResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: filesystem policy failed: %s", fsResp.GetError())
	}

	// Apply process policy.
	procReq := translateProcessPolicy(containerID, p)
	procResp, err := s.client.ApplyProcessPolicy(ctx, procReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: apply process policy: %w", err)
	}
	if !procResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: process policy failed: %s", procResp.GetError())
	}

	// Apply credential policy (Phase 6).
	if len(p.SecretACLs) > 0 {
		credReq := translateCredentialPolicy(containerID, p)
		credResp, err := s.client.ApplyCredentialPolicy(ctx, credReq)
		if err != nil {
			return fmt.Errorf("grpc strategy: apply credential policy: %w", err)
		}
		if !credResp.GetSuccess() {
			return fmt.Errorf("grpc strategy: credential policy failed: %s", credResp.GetError())
		}
	}

	// Start event streaming for this container.
	// Non-fatal: a missing event stream degrades observability but does not
	// compromise enforcement. Log the error so operators can diagnose it.
	if err := s.startEventStream(containerID); err != nil {
		fmt.Printf("enforcement: event stream for container %s failed to start: %v\n", containerID, err)
	}

	return nil
}

// Update applies updated policies to an already-registered container.
func (s *GRPCStrategy) Update(ctx context.Context, containerID string, p *policy.ContainerPolicy) error {
	// Apply network policy.
	netReq := translateNetworkPolicy(containerID, p)
	netResp, err := s.client.ApplyNetworkPolicy(ctx, netReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: update network policy: %w", err)
	}
	if !netResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: network policy failed: %s", netResp.GetError())
	}

	// Apply filesystem policy.
	fsReq := translateFilesystemPolicy(containerID, p)
	fsResp, err := s.client.ApplyFilesystemPolicy(ctx, fsReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: update filesystem policy: %w", err)
	}
	if !fsResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: filesystem policy failed: %s", fsResp.GetError())
	}

	// Apply process policy.
	procReq := translateProcessPolicy(containerID, p)
	procResp, err := s.client.ApplyProcessPolicy(ctx, procReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: update process policy: %w", err)
	}
	if !procResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: process policy failed: %s", procResp.GetError())
	}

	// Apply credential policy (Phase 6).
	if len(p.SecretACLs) > 0 {
		credReq := translateCredentialPolicy(containerID, p)
		credResp, err := s.client.ApplyCredentialPolicy(ctx, credReq)
		if err != nil {
			return fmt.Errorf("grpc strategy: update credential policy: %w", err)
		}
		if !credResp.GetSuccess() {
			return fmt.Errorf("grpc strategy: credential policy failed: %s", credResp.GetError())
		}
	}

	return nil
}

// Remove unregisters the container from the enforcer sidecar.
func (s *GRPCStrategy) Remove(ctx context.Context, containerID string) error {
	// Stop event streaming if active.
	s.mu.Lock()
	if cancel, ok := s.cancelFn[containerID]; ok {
		cancel()
		delete(s.cancelFn, containerID)
	}
	if ch, ok := s.events[containerID]; ok {
		close(ch)
		delete(s.events, containerID)
	}
	s.mu.Unlock()

	// Unregister the container.
	_, err := s.client.UnregisterContainer(ctx, &enforcerapi.UnregisterContainerRequest{
		ContainerId: containerID,
	})
	if err != nil {
		return fmt.Errorf("grpc strategy: unregister container: %w", err)
	}

	return nil
}

// InjectSecrets writes secret values into the container via the enforcer sidecar.
// The enforcer writes directly to the container's filesystem through
// /proc/<init_pid>/root/run/secrets/<name>. BPF LSM SECRET_ACLS gates access.
func (s *GRPCStrategy) InjectSecrets(ctx context.Context, containerID string, resolved map[string]*secrets.Secret) error {
	entries := make([]*enforcerapi.SecretEntry, 0, len(resolved))
	for name, secret := range resolved {
		entries = append(entries, &enforcerapi.SecretEntry{
			Name:  name,
			Value: secret.Value,
			Mode:  0400,
		})
	}
	resp, err := s.client.InjectSecrets(ctx, &enforcerapi.InjectSecretsRequest{
		ContainerId: containerID,
		Secrets:     entries,
	})
	if err != nil {
		return fmt.Errorf("grpc strategy: inject secrets: %w", err)
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("grpc strategy: inject secrets failed: %s", resp.GetError())
	}
	return nil
}

// Events returns the audit event channel for the given container.
func (s *GRPCStrategy) Events(containerID string) <-chan Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events[containerID]
}

// Level returns LevelGRPC.
func (s *GRPCStrategy) Level() Level {
	return s.level
}

// Close closes the gRPC connection.
// The mutex is held for the full duration so that no concurrent Apply() call
// can observe a partially-closed connection.
func (s *GRPCStrategy) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Cancel all active event streams.
	for _, cancel := range s.cancelFn {
		cancel()
	}
	for _, ch := range s.events {
		close(ch)
	}
	s.cancelFn = make(map[string]context.CancelFunc)
	s.events = make(map[string]chan Event)

	return s.conn.Close()
}

// startEventStream starts a goroutine that streams events for the given container.
func (s *GRPCStrategy) startEventStream(containerID string) error {
	ctx, cancel := context.WithCancel(context.Background())

	stream, err := s.client.StreamEvents(ctx, &enforcerapi.StreamEventsRequest{
		ContainerId: containerID,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("grpc strategy: start event stream: %w", err)
	}

	eventCh := make(chan Event, 100)

	s.mu.Lock()
	s.events[containerID] = eventCh
	s.cancelFn[containerID] = cancel
	s.mu.Unlock()

	go func() {
		defer cancel()
		for {
			protoEvent, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				// Stream closed or error
				return
			}

			event := translateEvent(protoEvent)
			s.mu.Lock()
			ch, ok := s.events[containerID]
			if !ok {
				s.mu.Unlock()
				return
			}
			select {
			case ch <- event:
			default:
				// Channel full, drop event
			}
			s.mu.Unlock()
		}
	}()

	return nil
}

// --- Policy translation helpers ---

func translateNetworkPolicy(containerID string, p *policy.ContainerPolicy) *enforcerapi.NetworkPolicyRequest {
	req := &enforcerapi.NetworkPolicyRequest{
		ContainerId:  containerID,
		AllowedHosts: p.AllowedHosts,
		DnsServers:   p.DNS,
	}

	for _, rule := range p.AllowedEgressRules {
		req.EgressRules = append(req.EgressRules, &enforcerapi.EgressRule{
			Host:     rule.Host,
			Port:     uint32(rule.Port),
			Protocol: rule.Protocol,
		})
	}

	return req
}

func translateFilesystemPolicy(containerID string, p *policy.ContainerPolicy) *enforcerapi.FilesystemPolicyRequest {
	req := &enforcerapi.FilesystemPolicyRequest{
		ContainerId: containerID,
	}

	for _, m := range p.AllowedMounts {
		if m.ReadOnly {
			req.ReadPaths = append(req.ReadPaths, m.Source)
		} else {
			req.WritePaths = append(req.WritePaths, m.Source)
		}
	}

	return req
}

func translateCredentialPolicy(containerID string, p *policy.ContainerPolicy) *enforcerapi.CredentialPolicyRequest {
	acls := make([]*enforcerapi.SecretAcl, len(p.SecretACLs))
	for i, acl := range p.SecretACLs {
		acls[i] = &enforcerapi.SecretAcl{
			Path:         acl.Path,
			AllowedTools: acl.AllowedTools,
			TtlSeconds:   acl.TTLSeconds,
		}
	}
	return &enforcerapi.CredentialPolicyRequest{
		ContainerId: containerID,
		SecretAcls:  acls,
	}
}

func translateProcessPolicy(containerID string, p *policy.ContainerPolicy) *enforcerapi.ProcessPolicyRequest {
	return &enforcerapi.ProcessPolicyRequest{
		ContainerId:     containerID,
		AllowedBinaries: p.AllowedCommands,
	}
}

// translateEvent converts a gRPC EnforcementEvent to an Event.
func translateEvent(protoEvent *enforcerapi.EnforcementEvent) Event {
	event := Event{
		Timestamp: protoEvent.GetTimestampNs(),
		PID:       protoEvent.GetPid(),
		Comm:      protoEvent.GetComm(),
	}

	// Map verdict
	switch protoEvent.GetVerdict() {
	case "allow":
		event.Verdict = VerdictAllow
	case "block":
		event.Verdict = VerdictBlock
	default:
		event.Verdict = VerdictBlock
	}

	// Map domain-specific event type and details
	details := protoEvent.GetDetails()
	switch protoEvent.GetDomain() {
	case "network":
		event.Type = EventNetConnect
		event.Net = &NetEvent{}
		// Parse details map for IP, port, protocol if needed
	case "filesystem":
		event.Type = EventFSOpen
		event.FS = &FSEvent{
			Path: details["path"],
		}
	case "process":
		event.Type = EventExec
		event.Exec = &ExecEvent{
			Binary: details["binary"],
		}
	case "credential":
		event.Type = EventCred
	}

	return event
}

// Compile-time interface check.
var _ Strategy = (*GRPCStrategy)(nil)
