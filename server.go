package socks5

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/things-go/go-socks5/bufferpool"
	"github.com/things-go/go-socks5/statute"
)

// GPool is used to implement custom goroutine pool default use goroutine
type GPool interface {
	Submit(f func()) error
}

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	// authMethods can be provided to implement authentication
	// By default, "no-auth" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	authMethods []Authenticator
	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and authMethods is nil, then "no-auth" mode is enabled.
	credentials CredentialStore
	// resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	resolver NameResolver
	// rules is provided to enable custom logic around permitting
	// various commands. If not provided, NewPermitAll is used.
	rules RuleSet
	// rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	rewriter AddressRewriter
	// bindIP is used for bind or udp associate
	bindIP net.IP
	// logger can be used to provide a custom log target.
	// Defaults to io.Discard.
	logger Logger
	// Optional function for dialing out.
	// The callback set by dialWithRequest will be called first.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Optional function for dialing out with the access of request detail.
	dialWithRequest func(ctx context.Context, network, addr string, request *Request) (net.Conn, error)
	// buffer pool
	bufferPool bufferpool.BufPool
	// goroutine pool
	gPool GPool
	// user's handle
	userConnectHandle   func(ctx context.Context, writer io.Writer, request *Request) error
	userBindHandle      func(ctx context.Context, writer io.Writer, request *Request) error
	userAssociateHandle func(ctx context.Context, writer io.Writer, request *Request) error

	mu         sync.Mutex
	listeners  map[*net.Listener]struct{}
	activeConn map[net.Conn]struct{}
	inShutdown atomic.Bool // true when server is in shutdown
	onShutdown []func()

	listenerGroup sync.WaitGroup
}

var ErrServerClosed = errors.New("socks5: Server closed")

// NewServer creates a new Server
func NewServer(opts ...Option) *Server {
	srv := &Server{
		authMethods: []Authenticator{},
		bufferPool:  bufferpool.NewPool(32 * 1024),
		resolver:    DNSResolver{},
		rules:       NewPermitAll(),
		logger:      NewLogger(log.New(io.Discard, "socks5: ", log.LstdFlags)),
	}

	for _, opt := range opts {
		opt(srv)
	}

	// Ensure we have at least one authentication method enabled
	if (len(srv.authMethods) == 0) && srv.credentials != nil {
		srv.authMethods = []Authenticator{&UserPassAuthenticator{srv.credentials}}
	}
	if len(srv.authMethods) == 0 {
		srv.authMethods = []Authenticator{&NoAuthAuthenticator{}}
	}

	return srv
}

func (s *Server) shuttingDown() bool {
	return s.inShutdown.Load()
}

// ListenAndServe is used to create a listener and serve on it
func (sf *Server) ListenAndServe(network, addr string) error {
	if sf.shuttingDown() {
		return ErrServerClosed
	}
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return sf.Serve(l)
}

// Serve is used to serve connections from a listener
func (sf *Server) Serve(l net.Listener) error {
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		sf.goFunc(func() {
			if err := sf.ServeConn(conn); err != nil {
				sf.logger.Errorf("server: %v", err)
			}
		})
	}
}

// ServeConn is used to serve a single connection.
func (sf *Server) ServeConn(conn net.Conn) error {
	var authContext *AuthContext

	defer conn.Close()

	bufConn := bufio.NewReader(conn)

	mr, err := statute.ParseMethodRequest(bufConn)
	if err != nil {
		return err
	}
	if mr.Ver != statute.VersionSocks5 {
		return statute.ErrNotSupportVersion
	}

	// Authenticate the connection
	userAddr := ""
	if conn.RemoteAddr() != nil {
		userAddr = conn.RemoteAddr().String()
	}
	authContext, err = sf.authenticate(conn, bufConn, userAddr, mr.Methods)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	// The client request detail
	request, err := ParseRequest(bufConn)
	if err != nil {
		if errors.Is(err, statute.ErrUnrecognizedAddrType) {
			if err := SendReply(conn, statute.RepAddrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("failed to send reply %w", err)
			}
		}
		return fmt.Errorf("failed to read destination address, %w", err)
	}

	if request.Request.Command != statute.CommandConnect &&
		request.Request.Command != statute.CommandBind &&
		request.Request.Command != statute.CommandAssociate {
		if err := SendReply(conn, statute.RepCommandNotSupported, nil); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("unrecognized command[%d]", request.Request.Command)
	}

	request.AuthContext = authContext
	request.LocalAddr = conn.LocalAddr()
	request.RemoteAddr = conn.RemoteAddr()
	// Track the connection
	sf.trackConn(conn, true)
	// Process the client request
	if err := sf.handleRequest(conn, request); err != nil {
		return err
	}

	sf.trackConn(conn, false)

	return nil
}

func (s *Server) trackListener(ln *net.Listener, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listeners == nil {
		s.listeners = make(map[*net.Listener]struct{})
	}
	if add {
		if s.shuttingDown() {
			return false
		}
		s.listeners[ln] = struct{}{}
		s.listenerGroup.Add(1)
	} else {
		delete(s.listeners, ln)
		s.listenerGroup.Done()
	}
	return true
}

func (sf *Server) closeListenersLocked() error {
	var err error
	for ln := range sf.listeners {
		if cerr := (*ln).Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

func (s *Server) trackConn(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeConn == nil {
		s.activeConn = make(map[net.Conn]struct{})
	}
	if add {
		s.activeConn[c] = struct{}{}
	} else {
		delete(s.activeConn, c)
	}
}

// RegisterOnShutdown registers a function to call on Shutdown.
func (srv *Server) RegisterOnShutdown(f func()) {
	srv.mu.Lock()
	srv.onShutdown = append(srv.onShutdown, f)
	srv.mu.Unlock()
}

func (s *Server) closeConns() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	quiescent := true
	for c := range s.activeConn {
		// Forcefully close connection discarding any error
		c.Close()
		delete(s.activeConn, c)
	}

	return quiescent
}

const shutdownPollIntervalMax = 500 * time.Millisecond

// Shutdown gracefully shuts down the server without interrupting any active connection.
func (srv *Server) Shutdown(ctx context.Context) error {
	srv.inShutdown.Store(true)

	srv.mu.Lock()
	lnerr := srv.closeListenersLocked()
	for _, f := range srv.onShutdown {
		go f()
	}
	srv.mu.Unlock()
	srv.listenerGroup.Wait()

	pollIntervalBase := time.Millisecond
	nextPollInterval := func() time.Duration {
		// Add 10% jitter.
		interval := pollIntervalBase + time.Duration(rand.Intn(int(pollIntervalBase/10)))
		// Double and clamp for next time.
		pollIntervalBase *= 2
		if pollIntervalBase > shutdownPollIntervalMax {
			pollIntervalBase = shutdownPollIntervalMax
		}
		return interval
	}

	timer := time.NewTimer(nextPollInterval())
	defer timer.Stop()
	for {
		if srv.closeConns() {
			return lnerr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			timer.Reset(nextPollInterval())
		}
	}
}

// authenticate is used to handle connection authentication
func (sf *Server) authenticate(conn io.Writer, bufConn io.Reader,
	userAddr string, methods []byte) (*AuthContext, error) {
	// Select a usable method
	for _, auth := range sf.authMethods {
		for _, method := range methods {
			if auth.GetCode() == method {
				return auth.Authenticate(bufConn, conn, userAddr)
			}
		}
	}
	// No usable method found
	conn.Write([]byte{statute.VersionSocks5, statute.MethodNoAcceptable}) //nolint: errcheck
	return nil, statute.ErrNoSupportedAuth
}

func (sf *Server) goFunc(f func()) {
	if sf.gPool == nil || sf.gPool.Submit(f) != nil {
		go f()
	}
}
