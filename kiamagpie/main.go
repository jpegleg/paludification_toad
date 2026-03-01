package main

import (
        "context"
        "crypto/ecdsa"
        "crypto/ed25519"
        "crypto/rsa"
        "crypto/tls"
        "crypto/x509"
        "encoding/json"
        "errors"
        "fmt"
        "io"
        "io/fs"
        "log"
        "mime"
        "net"
        "net/http"
        "os"
        "path/filepath"
        "strings"
        "sync"
        "sync/atomic"
        "time"

        "github.com/fsnotify/fsnotify"
        "github.com/google/uuid"
        "github.com/quic-go/quic-go/http3"
        "gopkg.in/yaml.v3"
)

type MagpieConfig struct {
        Magpie struct {
                QUICEnabled   bool        `yaml:"quic"`
                TLSEnabled    bool        `yaml:"tls"`
                HTTPEnabled   bool        `yaml:"http"`
                HSTS          bool        `yaml:"strict_transport_security"`
                RedirectHTTPS bool        `yaml:"redirect_https"`
                CacheAgeSecs  int         `yaml:"cache_age_seconds"`
                DomainsTLS    interface{} `yaml:"domains_tls"`
                DomainsQUIC   interface{} `yaml:"domains_quic"`
                DomainsHTTP   interface{} `yaml:"domains_http"`
        } `yaml:"kiamagpie"`
}

type RewriteRule struct {
        From string
        To   string
}

type VirtualHost struct {
        Domain   string
        Addr     string
        CertPath string
        KeyPath  string
        WebRoot  string
        Rewrites []RewriteRule
}

type ParsedHosts struct {
        TLS  []VirtualHost
        QUIC []VirtualHost
        HTTP []VirtualHost
}

type fileCache struct {
        sync.RWMutex
        Data map[string]map[string][]byte
}

type certStore struct {
        cert     atomic.Pointer[tls.Certificate]
        certPath string
        keyPath  string
}

type ctxKey int

const interactionIDKey ctxKey = 1

type connIDStore struct {
        mu sync.Mutex
        m  map[string]uuid.UUID
}

func (s *connIDStore) get(key string) (uuid.UUID, bool) {
        s.mu.Lock()
        defer s.mu.Unlock()
        id, ok := s.m[key]
        return id, ok
}

func (s *connIDStore) set(key string, id uuid.UUID) {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.m[key] = id
}

func (s *connIDStore) del(key string) {
        s.mu.Lock()
        defer s.mu.Unlock()
        delete(s.m, key)
}

func (s *connIDStore) findByRemote(remote string) (uuid.UUID, bool) {
        s.mu.Lock()
        defer s.mu.Unlock()
        prefix := remote + "|"
        for k, id := range s.m {
                if strings.HasPrefix(k, prefix) {
                        return id, true
                }
        }
        return uuid.UUID{}, false
}

type jsonErrorLogWriter struct {
        protocol string
        host     string
        addr     string
}

func (w *jsonErrorLogWriter) Write(p []byte) (int, error) {
        msg := strings.TrimSpace(string(p))
        if msg == "" {
                return len(p), nil
        }

        remote := extractRemoteFromErrorLog(msg)
        id := uuid.New()
        if remote != "" {
                if existing, ok := tcpConnIDs.findByRemote(remote); ok {
                        id = existing
                }
        }

        logEvent(id, map[string]interface{}{
                "level":    "error",
                "event":    "server_errorlog",
                "protocol": w.protocol,
                "host":     w.host,
                "addr":     w.addr,
                "remote":   remote,
                "message":  msg,
        })

        return len(p), nil
}

type quicSession struct {
        ID   uuid.UUID
        Last time.Time
}

type quicSessionStore struct {
        mu      sync.Mutex
        m       map[string]quicSession
        maxSize int
        ttl     time.Duration
}

func (s *quicSessionStore) getOrCreate(key string) uuid.UUID {
        now := time.Now()
        s.mu.Lock()
        defer s.mu.Unlock()

        if v, ok := s.m[key]; ok {
                v.Last = now
                s.m[key] = v
                return v.ID
        }

        if len(s.m) >= s.maxSize {
                s.evictLocked(now)
                if len(s.m) >= s.maxSize {
                        for k := range s.m {
                                delete(s.m, k)
                                break
                        }
                }
        }

        id := uuid.New()
        s.m[key] = quicSession{ID: id, Last: now}
        return id
}

func (s *quicSessionStore) evictLocked(now time.Time) {
        cutoff := now.Add(-s.ttl)
        for k, v := range s.m {
                if v.Last.Before(cutoff) {
                        delete(s.m, k)
                }
        }
}

var (
        config  *MagpieConfig
        cache   = &fileCache{Data: map[string]map[string][]byte{}}
        watcher *fsnotify.Watcher
        certMap = sync.Map{}

        rewriteMu      sync.RWMutex
        rewritesByHost = map[string][]RewriteRule{}

        tcpConnIDs = &connIDStore{m: map[string]uuid.UUID{}}

        quicSessions = &quicSessionStore{
                m:       map[string]quicSession{},
                maxSize: 10000,
                ttl:     10 * time.Minute,
        }
)

func main() {
        const kiamagpieVersion = "0.1.1"
        logEvent(uuid.New(), map[string]interface{}{
                "event":   "server_start",
                "version": kiamagpieVersion,
        })
        data, err := os.ReadFile("domains.yaml")
        if err != nil {
                logError(uuid.New(), "config_read_failed", err, map[string]interface{}{"path": "domains.yaml"})
                os.Exit(1)
        }

        var cfg MagpieConfig
        if err := yaml.Unmarshal(data, &cfg); err != nil {
                logError(uuid.New(), "config_unmarshal_failed", err, nil)
                os.Exit(1)
        }
        config = &cfg

        watcher, err = fsnotify.NewWatcher()
        if err != nil {
                logError(uuid.New(), "watcher_create_failed", err, nil)
                os.Exit(1)
        }
        defer watcher.Close()

        go watchLoop()

        hosts := parseVHosts(config)

        rewriteMu.Lock()
        for _, vh := range append(append(hosts.TLS, hosts.HTTP...), hosts.QUIC...) {
                if len(vh.Rewrites) > 0 {
                        rewritesByHost[vh.Domain] = vh.Rewrites
                }
        }
        rewriteMu.Unlock()

        reloadAllFiles(hosts)

        var wg sync.WaitGroup

        if config.Magpie.HTTPEnabled {
                for _, h := range hosts.HTTP {
                        wg.Add(1)
                        go func(v VirtualHost) {
                                defer wg.Done()
                                startHTTP(v)
                        }(h)
                }
        }

        if config.Magpie.TLSEnabled {
                for _, h := range hosts.TLS {
                        wg.Add(1)
                        go func(v VirtualHost) {
                                defer wg.Done()
                                startHTTPS(v)
                        }(h)
                }
        }

        if config.Magpie.QUICEnabled {
                for _, h := range hosts.QUIC {
                        wg.Add(1)
                        go func(v VirtualHost) {
                                defer wg.Done()
                                startQUIC(v)
                        }(h)
                }
        }

        wg.Wait()
}

func parseVHosts(cfg *MagpieConfig) ParsedHosts {
        res := ParsedHosts{}
        process := func(raw interface{}) []VirtualHost {
                list, ok := raw.([]interface{})
                if !ok {
                        return nil
                }
                var out []VirtualHost
                for _, item := range list {
                        m, ok := item.(map[string]interface{})
                        if !ok {
                                continue
                        }
                        for domain, details := range m {
                                arr, ok := details.([]interface{})
                                if !ok || len(arr) < 2 {
                                        continue
                                }
                                addr, _ := arr[0].(string)
                                vh := VirtualHost{Domain: domain, Addr: addr}
                                for i := 1; i < len(arr); i++ {
                                        props, ok := arr[i].(map[string]interface{})
                                        if !ok {
                                                continue
                                        }
                                        if v, ok := props["cert"]; ok {
                                                if s, ok := v.(string); ok {
                                                        vh.CertPath = s
                                                }
                                        }
                                        if v, ok := props["key"]; ok {
                                                if s, ok := v.(string); ok {
                                                        vh.KeyPath = s
                                                }
                                        }
                                        if v, ok := props["web_content"]; ok {
                                                if s, ok := v.(string); ok {
                                                        vh.WebRoot = s
                                                }
                                        }
                                        if v, ok := props["rewrites"]; ok {
                                                if m2, ok := v.(map[string]interface{}); ok {
                                                        for k, vv := range m2 {
                                                                if to, ok := vv.(string); ok {
                                                                        vh.Rewrites = append(vh.Rewrites, RewriteRule{From: k, To: to})
                                                                }
                                                        }
                                                }
                                        }
                                }
                                out = append(out, vh)
                        }
                }
                return out
        }
        res.TLS = process(cfg.Magpie.DomainsTLS)
        res.QUIC = process(cfg.Magpie.DomainsQUIC)
        res.HTTP = process(cfg.Magpie.DomainsHTTP)
        return res
}

func watchLoop() {
        for {
                select {
                case e := <-watcher.Events:
                        if e.Op&(fsnotify.Write|fsnotify.Create) != 0 {
                                if store, ok := certMap.Load(e.Name); ok {
                                        reloadCert(store.(*certStore))
                                }
                        }
                case err := <-watcher.Errors:
                        logWarn(uuid.New(), "watcher_error", err, nil)
                }
        }
}

func reloadCert(cs *certStore) {
        cert, err := tls.LoadX509KeyPair(cs.certPath, cs.keyPath)
        if err != nil {
                logWarn(uuid.New(), "certificate_reload_failed", err, map[string]interface{}{
                        "cert": cs.certPath,
                        "key":  cs.keyPath,
                })
                return
        }

        if err := validateIdentity(cert); err != nil {
                logWarn(uuid.New(), "certificate_identity_invalid", err, map[string]interface{}{
                        "cert": cs.certPath,
                })
                return
        }

        cs.cert.Store(&cert)

        logEvent(uuid.New(), map[string]interface{}{
                "event": "certificate_reloaded",
                "cert":  cs.certPath,
        })
}

func validateIdentity(cert tls.Certificate) error {
        leaf, err := x509.ParseCertificate(cert.Certificate[0])
        if err != nil {
                return err
        }

        switch leaf.PublicKeyAlgorithm {
        case x509.Ed25519:
                if _, ok := cert.PrivateKey.(ed25519.PrivateKey); !ok {
                        return errors.New("invalid ed25519 private key")
                }
                return nil

        case x509.ECDSA:
                key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
                if !ok {
                        return errors.New("invalid ecdsa private key")
                }
                switch key.Curve.Params().Name {
                case "P-256", "P-384", "P-521":
                default:
                        return errors.New("unsupported NIST curve")
                }
                if leaf.SignatureAlgorithm != x509.ECDSAWithSHA384 &&
                        leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 &&
                        leaf.SignatureAlgorithm != x509.ECDSAWithSHA512 {
                        return errors.New("unsupported ECDSA signature algorithm")
                }
                return nil

        case x509.RSA:
                key, ok := cert.PrivateKey.(*rsa.PrivateKey)
                if !ok {
                        return errors.New("invalid rsa private key")
                }
                if key.N.BitLen() < 2048 {
                        return errors.New("rsa key too small (min 2048 bits)")
                }
                switch leaf.SignatureAlgorithm {
                case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
                        x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
                        return nil
                default:
                        return errors.New("unsupported RSA signature algorithm")
                }

        default:
                return errors.New("unsupported identity certificate type")
        }
}

func loadCertAtomic(vh VirtualHost) (*certStore, error) {
        cert, err := tls.LoadX509KeyPair(vh.CertPath, vh.KeyPath)
        if err != nil {
                return nil, err
        }

        if err := validateIdentity(cert); err != nil {
                return nil, err
        }

        cs := &certStore{
                certPath: vh.CertPath,
                keyPath:  vh.KeyPath,
        }

        cs.cert.Store(&cert)

        if err := watcher.Add(vh.CertPath); err != nil {
                logWarn(uuid.New(), "watcher_add_failed", err, map[string]interface{}{"path": vh.CertPath})
        }
        if err := watcher.Add(vh.KeyPath); err != nil {
                logWarn(uuid.New(), "watcher_add_failed", err, map[string]interface{}{"path": vh.KeyPath})
        }

        certMap.Store(vh.CertPath, cs)
        certMap.Store(vh.KeyPath, cs)

        return cs, nil
}

func tlsConfigForHost(vh VirtualHost) (*tls.Config, error) {
        cs, err := loadCertAtomic(vh)
        if err != nil {
                return nil, err
        }

        return &tls.Config{
                MinVersion: tls.VersionTLS13,
                CurvePreferences: []tls.CurveID{
                        tls.X25519MLKEM768,
                        tls.X25519,
                        tls.CurveP256,
                        tls.CurveP384,
                        tls.CurveP521,
                },
                SessionTicketsDisabled:   true,
                PreferServerCipherSuites: true,
                GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
                        id := uuid.New()
                        if chi != nil && chi.Conn != nil {
                                key := connKey(chi.Conn)
                                if existing, ok := tcpConnIDs.get(key); ok {
                                        id = existing
                                } else {
                                        tcpConnIDs.set(key, id)
                                }
                        }
                        logEvent(id, map[string]interface{}{
                                "event":    "tls_client_hello",
                                "protocol": "https",
                                "sni":      chi.ServerName,
                                "remote":   safeRemote(chi),
                                "local":    safeLocal(chi),
                        })
                        return cs.cert.Load(), nil
                },
        }, nil
}

func startHTTP(vh VirtualHost) {
        mux := http.NewServeMux()
        mux.HandleFunc("/", handle)

        jw := &jsonErrorLogWriter{protocol: "http", host: vh.Domain, addr: vh.Addr}
        srv := &http.Server{
                Addr:     vh.Addr,
                Handler:  middleware(vh, mux),
                ErrorLog: log.New(jw, "", 0),
                ConnContext: func(ctx context.Context, c net.Conn) context.Context {
                        key := connKey(c)
                        id := uuid.New()
                        tcpConnIDs.set(key, id)
                        return context.WithValue(ctx, interactionIDKey, id)
                },
                ConnState: func(c net.Conn, s http.ConnState) {
                        key := connKey(c)
                        id, ok := tcpConnIDs.get(key)
                        if !ok {
                                id = uuid.New()
                                tcpConnIDs.set(key, id)
                        }
                        switch s {
                        case http.StateNew:
                                logEvent(id, map[string]interface{}{
                                        "event":       "connection_open",
                                        "protocol":    "http",
                                        "remote":      c.RemoteAddr().String(),
                                        "local":       c.LocalAddr().String(),
                                        "host":        vh.Domain,
                                        "listen_addr": vh.Addr,
                                })
                        case http.StateClosed, http.StateHijacked:
                                logEvent(id, map[string]interface{}{
                                        "event":    "connection_close",
                                        "protocol": "http",
                                        "remote":   c.RemoteAddr().String(),
                                        "local":    c.LocalAddr().String(),
                                        "host":     vh.Domain,
                                })
                                tcpConnIDs.del(key)
                        }
                },
        }

        ln, err := net.Listen("tcp", vh.Addr)
        if err != nil {
                logError(uuid.New(), "http_listen_failed", err, map[string]interface{}{"host": vh.Domain, "addr": vh.Addr})
                return
        }
        if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
                logError(uuid.New(), "http_server_error", err, map[string]interface{}{"host": vh.Domain, "addr": vh.Addr})
        }
}

func startHTTPS(vh VirtualHost) {
        conf, err := tlsConfigForHost(vh)
        if err != nil {
                logError(uuid.New(), "tls_config_error", err, map[string]interface{}{"host": vh.Domain, "addr": vh.Addr})
                return
        }

        mux := http.NewServeMux()
        mux.HandleFunc("/", handle)

        jw := &jsonErrorLogWriter{protocol: "https", host: vh.Domain, addr: vh.Addr}
        srv := &http.Server{
                Addr:      vh.Addr,
                TLSConfig: conf,
                Handler:   middleware(vh, mux),
                ErrorLog:  log.New(jw, "", 0),
                ConnContext: func(ctx context.Context, c net.Conn) context.Context {
                        key := connKey(c)
                        id := uuid.New()
                        tcpConnIDs.set(key, id)
                        return context.WithValue(ctx, interactionIDKey, id)
                },
                ConnState: func(c net.Conn, s http.ConnState) {
                        key := connKey(c)
                        id, ok := tcpConnIDs.get(key)
                        if !ok {
                                id = uuid.New()
                                tcpConnIDs.set(key, id)
                        }
                        switch s {
                        case http.StateNew:
                                logEvent(id, map[string]interface{}{
                                        "event":       "connection_open",
                                        "protocol":    "https",
                                        "remote":      c.RemoteAddr().String(),
                                        "local":       c.LocalAddr().String(),
                                        "host":        vh.Domain,
                                        "listen_addr": vh.Addr,
                                })
                        case http.StateClosed, http.StateHijacked:
                                logEvent(id, map[string]interface{}{
                                        "event":    "connection_close",
                                        "protocol": "https",
                                        "remote":   c.RemoteAddr().String(),
                                        "local":    c.LocalAddr().String(),
                                        "host":     vh.Domain,
                                })
                                tcpConnIDs.del(key)
                        }
                },
        }

        ln, err := tls.Listen("tcp", vh.Addr, conf)
        if err != nil {
                logError(uuid.New(), "https_listen_failed", err, map[string]interface{}{"host": vh.Domain, "addr": vh.Addr})
                return
        }

        if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
                logError(uuid.New(), "https_server_error", err, map[string]interface{}{"host": vh.Domain, "addr": vh.Addr})
        }
}

func startQUIC(vh VirtualHost) {
        conf, err := tlsConfigForHost(vh)
        if err != nil {
                logError(uuid.New(), "tls_config_error", err, map[string]interface{}{"host": vh.Domain, "addr": vh.Addr, "proto": "quic"})
                return
        }
        conf.NextProtos = []string{"h3"}

        srv := &http3.Server{
                Addr:      vh.Addr,
                TLSConfig: conf,
                Handler:   middleware(vh, http.HandlerFunc(handle)),
        }

        addr, err := net.ResolveUDPAddr("udp", vh.Addr)
        if err != nil {
                logError(uuid.New(), "udp_resolve_failed", err, map[string]interface{}{"host": vh.Domain, "addr": vh.Addr})
                return
        }

        const receiveBufferSize = 1024 * 1024

        packetConn, err := net.ListenUDP("udp", addr)
        if err != nil {
                logError(uuid.New(), "udp_listen_failed", err, map[string]interface{}{"host": vh.Domain, "addr": vh.Addr})
                return
        }

        if err := packetConn.SetReadBuffer(receiveBufferSize); err != nil {
                logWarn(uuid.New(), "udp_set_read_buffer_failed", err, map[string]interface{}{"host": vh.Domain, "addr": vh.Addr})
        }

        if err := srv.Serve(packetConn); err != nil {
                logError(uuid.New(), "quic_server_error", err, map[string]interface{}{"host": vh.Domain, "addr": vh.Addr})
        }
}

func middleware(vh VirtualHost, next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                id := interactionIDFromRequest(r)
                srcIP := sourceIP(r.RemoteAddr)
                start := time.Now()
                lrw := &respWrap{ResponseWriter: w, status: 200}
                next.ServeHTTP(lrw, r)

                logEvent(id, map[string]interface{}{
                        "src_ip":           srcIP,
                        "method":           r.Method,
                        "path":             r.URL.Path,
                        "host":             r.Host,
                        "sni":              tlsSNI(r),
                        "status":           lrw.status,
                        "wait_duration_ms": time.Since(start).Milliseconds(),
                        "listen_host":      vh.Domain,
                        "transport_proto":  requestTransportProto(r),
                        "http_proto":       r.Proto,
                        "http_proto_major": r.ProtoMajor,
                        "http_proto_minor": r.ProtoMinor,
                })
        })
}

func interactionIDFromRequest(r *http.Request) uuid.UUID {
        if r == nil {
                return uuid.New()
        }
        if v := r.Context().Value(interactionIDKey); v != nil {
                if id, ok := v.(uuid.UUID); ok {
                        return id
                }
        }
        if r.ProtoMajor >= 3 {
                return quicSessionID(r)
        }
        return uuid.New()
}

func quicSessionID(r *http.Request) uuid.UUID {
        key := ""
        if r != nil {
                key = stripPort(r.RemoteAddr) + "|" + stripPort(r.Host)
        }
        return quicSessions.getOrCreate(key)
}

type respWrap struct {
        http.ResponseWriter
        status int
}

func (r *respWrap) WriteHeader(code int) {
        r.status = code
        r.ResponseWriter.WriteHeader(code)
}

func applyRewrites(host, path string) string {
        rewriteMu.RLock()
        rules := rewritesByHost[host]
        rewriteMu.RUnlock()

        for _, rr := range rules {
                if rr.From == path && rr.To != "" {
                        return rr.To
                }
        }
        return path
}

func handle(w http.ResponseWriter, r *http.Request) {
        host := stripPort(r.Host)

        cache.RLock()
        data := cache.Data[host]
        cache.RUnlock()

        path := applyRewrites(host, r.URL.Path)

        content, ok := data[path]
        if !ok {
                http.NotFound(w, r)
                return
        }

        ctype := mime.TypeByExtension(filepath.Ext(path))
        if ctype == "" {
                ctype = "application/octet-stream"
        }
        w.Header().Set("Content-Type", ctype)
        _, _ = w.Write(content)
}

func reloadAllFiles(hosts ParsedHosts) {
        all := append(append(hosts.TLS, hosts.HTTP...), hosts.QUIC...)
        for _, vh := range all {
                if vh.WebRoot == "" {
                        continue
                }
                fsmap := map[string][]byte{}
                filepath.WalkDir(vh.WebRoot, func(p string, d fs.DirEntry, err error) error {
                        if err != nil {
                                logWarn(uuid.New(), "walkdir_error", err, map[string]interface{}{
                                        "host": vh.Domain,
                                        "path": p,
                                })
                                return nil
                        }
                        if !d.IsDir() {
                                rel, _ := filepath.Rel(vh.WebRoot, p)
                                rel = "/" + strings.ReplaceAll(rel, "\\", "/")
                                b, err := os.ReadFile(p)
                                if err != nil {
                                        logWarn(uuid.New(), "readfile_error", err, map[string]interface{}{
                                                "host": vh.Domain,
                                                "path": p,
                                        })
                                        return nil
                                }
                                fsmap[rel] = b
                        }
                        return nil
                })
                cache.Lock()
                cache.Data[vh.Domain] = fsmap
                cache.Unlock()
        }
}

func logEvent(id uuid.UUID, fields map[string]interface{}) {
        entry := map[string]interface{}{
                "timestamp":      time.Now().UTC().Format(time.RFC3339),
                "interaction_id": id.String(),
        }
        for k, v := range fields {
                entry[k] = v
        }
        b, _ := json.Marshal(entry)
        fmt.Println(string(b))
}

func logError(id uuid.UUID, event string, err error, fields map[string]interface{}) {
        if fields == nil {
                fields = map[string]interface{}{}
        }
        fields["level"] = "error"
        fields["event"] = event
        if err != nil {
                fields["error"] = err.Error()
        }
        logEvent(id, fields)
}

func logWarn(id uuid.UUID, event string, err error, fields map[string]interface{}) {
        if fields == nil {
                fields = map[string]interface{}{}
        }
        fields["level"] = "warn"
        fields["event"] = event
        if err != nil {
                fields["error"] = err.Error()
        }
        logEvent(id, fields)
}

func stripPort(h string) string {
        if i := strings.Index(h, ":"); i != -1 {
                return h[:i]
        }
        return h
}

func tlsSNI(r *http.Request) string {
        if r.TLS != nil {
                return r.TLS.ServerName
        }
        return ""
}

func sourceIP(remoteAddr string) string {
        if remoteAddr == "" {
                return ""
        }
        h, _, err := net.SplitHostPort(remoteAddr)
        if err == nil {
                return h
        }
        if strings.HasPrefix(remoteAddr, "[") && strings.Contains(remoteAddr, "]") {
                if end := strings.Index(remoteAddr, "]"); end != -1 {
                        return strings.TrimPrefix(remoteAddr[:end+1], "[")
                }
        }
        if i := strings.LastIndex(remoteAddr, ":"); i != -1 {
                return remoteAddr[:i]
        }
        return remoteAddr
}

func requestTransportProto(r *http.Request) string {
        if r == nil {
                return ""
        }
        if r.ProtoMajor >= 3 {
                return "quic"
        }
        if r.TLS != nil {
                return "tcp+tls"
        }
        return "tcp"
}

func connKey(c net.Conn) string {
        if c == nil {
                return ""
        }
        ra := ""
        la := ""
        if c.RemoteAddr() != nil {
                ra = c.RemoteAddr().String()
        }
        if c.LocalAddr() != nil {
                la = c.LocalAddr().String()
        }
        return ra + "|" + la
}

func safeRemote(chi *tls.ClientHelloInfo) string {
        if chi == nil || chi.Conn == nil || chi.Conn.RemoteAddr() == nil {
                return ""
        }
        return chi.Conn.RemoteAddr().String()
}

func safeLocal(chi *tls.ClientHelloInfo) string {
        if chi == nil || chi.Conn == nil || chi.Conn.LocalAddr() == nil {
                return ""
        }
        return chi.Conn.LocalAddr().String()
}

func extractRemoteFromErrorLog(msg string) string {
        idx := strings.Index(msg, " from ")
        tagLen := len(" from ")
        if idx == -1 {
                idx = strings.Index(msg, " serving ")
                tagLen = len(" serving ")
        }
        if idx == -1 {
                return ""
        }
        rest := msg[idx+tagLen:]
        if rest == "" {
                return ""
        }
        if end := strings.Index(rest, ": "); end != -1 {
                return strings.TrimSpace(rest[:end])
        }
        if end := strings.Index(rest, " "); end != -1 {
                return strings.TrimSpace(rest[:end])
        }
        if end := strings.Index(rest, "\t"); end != -1 {
                return strings.TrimSpace(rest[:end])
        }
        return strings.TrimSpace(rest)
}

func startStdlibLogDiscard() {
        log.SetOutput(io.Discard)
}

func init() {
        startStdlibLogDiscard()
}
