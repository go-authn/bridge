// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	adminv1 "github.com/go-authn/bridge/proto/bridge/admin/v1"
	"github.com/grpc-transports/control"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The administration API (proto/bridge/admin/v1/admin.proto), served only
// when the configuration has an admin block. `-tags nogrpc` leaves it out,
// with grpc and protobuf, and such a binary refuses a configuration that
// asks for it rather than start without it.

const haveGRPC = true

// openAdmin opens the admin listener, before anything is served: a
// configuration that asks for the API and cannot have it does not start.
// It returns nil when there is no admin block.
func (s *server) openAdmin() (func(context.Context) error, error) {
	b := s.cfg.Admin
	if b == nil {
		return nil, nil
	}
	// The listener is grpc-transports/control's, shared with go-fileshare: a
	// unix socket that is never reachable by another user, not even for the
	// instant between bind and chmod, and never taken from a running
	// instance; or TCP with mutual TLS.
	ln, opts, err := control.Listen(b.control())
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) error { return s.serveAdmin(ctx, ln, opts) }, nil
}

// serveAdmin runs the admin API on ln until ctx ends.
func (s *server) serveAdmin(ctx context.Context, ln net.Listener, opts []grpc.ServerOption) error {
	b := s.cfg.Admin
	g := grpc.NewServer(opts...)
	adminv1.RegisterAdminServiceServer(g, &adminServer{s: s})
	h := health.NewServer()
	healthpb.RegisterHealthServer(g, h)
	if b.Reflection {
		reflection.Register(g)
	}
	// Health follows readiness: SERVING while the federation's metadata is
	// vouched for, for the whole server and for the admin service by name.
	setHealth := func() {
		st := healthpb.HealthCheckResponse_NOT_SERVING
		if s.readiness() == nil {
			st = healthpb.HealthCheckResponse_SERVING
		}
		h.SetServingStatus("", st)
		h.SetServingStatus(adminv1.AdminService_ServiceDesc.ServiceName, st)
	}
	setHealth()
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				h.Shutdown()
				g.GracefulStop()
				return
			case <-t.C:
				setHealth()
			}
		}
	}()
	s.logf("admin API on %s", b.Listen)
	return g.Serve(ln)
}

type adminServer struct {
	adminv1.UnimplementedAdminServiceServer
	s *server
}

// caller is who is asking, for the audit line: cn=<client certificate CN>
// over mutual TLS, uid=<peer uid> on the unix socket.
func caller(ctx context.Context) string { return control.Caller(ctx) }

func (a *adminServer) Status(ctx context.Context, _ *adminv1.StatusRequest) (*adminv1.StatusResponse, error) {
	s := a.s
	fed := &adminv1.Federation{MetadataUrl: s.cfg.SAML.MetadataURL}
	if md := s.fed.Metadata(); md != nil {
		fed.Idps = int32(len(md.IdPs))
		for id := range md.IdPs {
			if s.allowedIdP(id) {
				fed.Usable++
			}
		}
		fed.ValidUntil = timestamppb.New(md.ValidUntil)
	}
	s.fedState.mu.Lock()
	if !s.fedState.lastRefresh.IsZero() {
		fed.LastRefresh = timestamppb.New(s.fedState.lastRefresh)
	}
	if s.fedState.lastErr != nil {
		fed.LastError = s.fedState.lastErr.Error()
	}
	s.fedState.mu.Unlock()
	return &adminv1.StatusResponse{
		Version:    version(),
		Issuer:     s.cfg.Issuer,
		Started:    timestamppb.New(s.started),
		Federation: fed,
		Counts: &adminv1.Counts{
			LoginsInProgress: int64(s.logins.count()),
			Codes:            int64(s.codes.count()),
			DevicesWaiting:   int64(s.devices.count()),
			RefreshFamilies:  int64(s.families.count()),
			AccessTokens:     int64(s.issued.count()),
		},
	}, nil
}

func (a *adminServer) RefreshMetadata(ctx context.Context, _ *adminv1.RefreshMetadataRequest) (*adminv1.RefreshMetadataResponse, error) {
	a.s.logf("admin: %s asked for a metadata refresh", caller(ctx))
	if err := a.s.refreshMetadata(ctx); err != nil {
		// The refresh failing is an answer, not an RPC failure: the status
		// says what failed and what is still in use.
		a.s.logf("admin: the refresh failed: %v", err)
	}
	st, err := a.Status(ctx, nil)
	return &adminv1.RefreshMetadataResponse{Status: st}, err
}

func (a *adminServer) ListIdPs(ctx context.Context, req *adminv1.ListIdPsRequest) (*adminv1.ListIdPsResponse, error) {
	md := a.s.fed.Metadata()
	if md == nil {
		return nil, status.Error(codes.Unavailable, "no federation metadata is in use")
	}
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 100
	}
	q := strings.ToLower(strings.TrimSpace(req.GetQuery()))
	out := &adminv1.ListIdPsResponse{}
	for _, i := range md.Sorted("fr", "en") {
		if !matches(i, q) {
			continue
		}
		out.Total++
		if len(out.Idps) < limit {
			out.Idps = append(out.Idps, &adminv1.IdP{
				EntityId: i.EntityID, Name: i.Name("fr", "en"), Scopes: i.Scopes,
				Categories: i.Categories, Allowed: a.s.allowedIdP(i.EntityID),
				Disabled: a.s.disabled.idp(i.EntityID, a.s.now()),
			})
		}
	}
	return out, nil
}

func (a *adminServer) ListClients(ctx context.Context, _ *adminv1.ListClientsRequest) (*adminv1.ListClientsResponse, error) {
	out := &adminv1.ListClientsResponse{}
	for _, c := range a.s.cfg.Clients {
		out.Clients = append(out.Clients, &adminv1.Client{
			Id: c.ID, Name: c.Name, Public: c.public(), Subject: c.Subject, Audience: c.Audience,
			Device: c.Device, SshCertificates: c.SSHCertificates, AppPasswords: c.AppPasswords,
			RefreshLifetimeSeconds: int64(c.refreshTTL.Seconds()),
		})
	}
	return out, nil
}

func (a *adminServer) RevokePerson(ctx context.Context, req *adminv1.RevokePersonRequest) (*adminv1.RevokePersonResponse, error) {
	u := strings.TrimSpace(req.GetUsername())
	if u == "" {
		return nil, status.Error(codes.InvalidArgument, "a username is required")
	}
	a.s.logf("admin: %s revokes %s", caller(ctx), u)
	r, err := a.s.revokePerson(u)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &adminv1.RevokePersonResponse{Revoked: revokedPB(r)}, nil
}

func (a *adminServer) DisablePerson(ctx context.Context, req *adminv1.DisablePersonRequest) (*adminv1.DisablePersonResponse, error) {
	u := strings.TrimSpace(req.GetUsername())
	e, r, err := a.s.disablePerson(u, req.GetReason(), caller(ctx), untilOf(req.GetUntil()))
	if err != nil {
		return nil, disableError(err)
	}
	return &adminv1.DisablePersonResponse{Disabled: disabledPB(u, "", e), Revoked: revokedPB(r)}, nil
}

func (a *adminServer) EnablePerson(ctx context.Context, req *adminv1.EnablePersonRequest) (*adminv1.EnablePersonResponse, error) {
	was, err := a.s.enablePerson(strings.TrimSpace(req.GetUsername()), caller(ctx))
	if err != nil {
		return nil, disableError(err)
	}
	return &adminv1.EnablePersonResponse{WasDisabled: was}, nil
}

func (a *adminServer) DisableIdP(ctx context.Context, req *adminv1.DisableIdPRequest) (*adminv1.DisableIdPResponse, error) {
	id := strings.TrimSpace(req.GetEntityId())
	// An entity ID the metadata does not have is still disabled: the next
	// metadata may bring it back, and the operator may know that before us.
	// The log says so.
	if md := a.s.fed.Metadata(); md != nil && id != "" {
		if _, ok := md.IdPs[id]; !ok {
			a.s.logf("admin: %s is not in the metadata in use; disabling it anyway", id)
		}
	}
	e, r, err := a.s.disableIdP(id, req.GetReason(), caller(ctx), untilOf(req.GetUntil()))
	if err != nil {
		return nil, disableError(err)
	}
	return &adminv1.DisableIdPResponse{Disabled: disabledPB("", id, e), Revoked: revokedPB(r)}, nil
}

func (a *adminServer) EnableIdP(ctx context.Context, req *adminv1.EnableIdPRequest) (*adminv1.EnableIdPResponse, error) {
	was, err := a.s.enableIdP(strings.TrimSpace(req.GetEntityId()), caller(ctx))
	if err != nil {
		return nil, disableError(err)
	}
	return &adminv1.EnableIdPResponse{WasDisabled: was}, nil
}

func (a *adminServer) ListDisabled(ctx context.Context, _ *adminv1.ListDisabledRequest) (*adminv1.ListDisabledResponse, error) {
	people, idps := a.s.disabled.list(a.s.now())
	out := &adminv1.ListDisabledResponse{}
	for _, p := range people {
		out.People = append(out.People, disabledPB(p.key, "", p.disabledEntry))
	}
	for _, i := range idps {
		out.Idps = append(out.Idps, disabledPB("", i.key, i.disabledEntry))
	}
	return out, nil
}

func untilOf(t *timestamppb.Timestamp) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.AsTime()
}

func disabledPB(username, entityID string, e disabledEntry) *adminv1.Disabled {
	pb := &adminv1.Disabled{Username: username, EntityId: entityID, Reason: e.Reason, By: e.By, Since: timestamppb.New(e.Since)}
	if !e.Until.IsZero() {
		pb.Until = timestamppb.New(e.Until)
	}
	return pb
}

func revokedPB(r revoked) *adminv1.Revoked {
	return &adminv1.Revoked{
		RefreshFamilies: int32(r.families), AccessTokens: int32(r.tokens),
		Logins: int32(r.logins), AppPasswords: int32(r.appPasswords), Certificates: int32(r.certificates),
	}
}

// disableError is the status for a disabling that could not be made: no
// file to keep it in, a request missing its subject, or the file failing.
func disableError(err error) error {
	switch {
	case errors.Is(err, errNoDisabledFile):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, errBadDisable):
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

// control is the admin block as grpc-transports/control reads it.
func (b *adminBlock) control() control.Config {
	return control.Config{Listen: b.Listen, TLSCertFile: b.TLSCertFile, TLSKeyFile: b.TLSKeyFile, ClientCAFile: b.ClientCAFile}
}

// checkAdmin refuses an admin block that cannot be served safely, at load
// time, without touching the network: control's Check.
func checkAdmin(b *adminBlock) error { return b.control().Check() }
