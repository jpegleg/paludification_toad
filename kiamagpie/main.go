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
        "net/url"
        "os"
        "path"
        "path/filepath"
        "runtime"
        "strings"
        "sync"
        "sync/atomic"
        "time"

        "github.com/fsnotify/fsnotify"
        "github.com/google/uuid"
        "github.com/quic-go/quic-go/http3"
        "golang.org/x/sys/unix"
        "gopkg.in/yaml.v3"
)

const magpieVersion = "0.0.0"

const (
        safeMaxRAMLimitBytes = int64(2 * 1024 * 1024 * 1024)
        safeMaxRAMPercent    = 80.0

        defaultRAMPercentFloat = 10.0
        defaultRAMPercentInt   = int64(10)
        defaultAvailRAMBytes   = int64(512 * 1024 * 1024)

        hstsHeaderValue = "max-age=63072000; includeSubDomains; preload"

        remoteFetchTimeout = 10 * time.Second
)

type MagpieConfig struct {
        Magpie struct {
                QUICEnabled     bool        `yaml:"quic"`
                TLSEnabled      bool        `yaml:"tls"`
                HTTPEnabled     bool        `yaml:"http"`
                HSTS            bool        `yaml:"strict_transport_security"`
                RedirectHTTPS   bool        `yaml:"redirect_https"`
                CacheAgeSecs    int         `yaml:"cache_age_seconds"`
                RAMLimitPercent float64     `yaml:"ram_limit_percent"`
                DomainsTLS      interface{} `yaml:"domains_tls"`
                DomainsQUIC     interface{} `yaml:"domains_quic"`
                DomainsHTTP     interface{} `yaml:"domains_http"`
        } `yaml:"kiamagpie"`
}

type RewriteRule struct {
        From string
        To   string
}

type VirtualHost struct {
        Domain          string
        Addr            string
        CertPath        string
        KeyPath         string
        WebRoot         string
        Rewrites        []RewriteRule
        TransportFlavor string
}

type ParsedHosts struct {
        TLS  []VirtualHost
        QUIC []VirtualHost
        HTTP []VirtualHost
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

type cacheSizer struct {
        mu         sync.Mutex
        totalBytes int64
        byHost     map[string]int64
        limitBytes int64
        hostErr    map[string]string
}

func (c *cacheSizer) setLimit(limit int64) {
        c.mu.Lock()
        defer c.mu.Unlock()
        c.limitBytes = limit
}

func (c *cacheSizer) snapshot() (total int64, limit int64) {
        c.mu.Lock()
        defer c.mu.Unlock()
        return c.totalBytes, c.limitBytes
}

func (c *cacheSizer) getHostErr(host string) (string, bool) {
        c.mu.Lock()
        defer c.mu.Unlock()
        e, ok := c.hostErr[host]
        return e, ok
}

func (c *cacheSizer) clearHostErr(host string) {
        c.mu.Lock()
        defer c.mu.Unlock()
        delete(c.hostErr, host)
}

func (c *cacheSizer) setHostTotal(host string, newBytes int64) error {
        c.mu.Lock()
        defer c.mu.Unlock()

        old := c.byHost[host]
        nextTotal := c.totalBytes - old + newBytes
        if c.limitBytes > 0 && nextTotal > c.limitBytes {
                c.hostErr[host] = "ram_limit_exceeded"
                return errors.New("ram cache limit exceeded")
        }

        c.totalBytes = nextTotal
        c.byHost[host] = newBytes
        delete(c.hostErr, host)
        return nil
}

func (c *cacheSizer) tryAdd(host string, delta int64) bool {
        c.mu.Lock()
        defer c.mu.Unlock()

        nextTotal := c.totalBytes + delta
        if c.limitBytes > 0 && nextTotal > c.limitBytes {
                return false
        }
        c.totalBytes = nextTotal
        c.byHost[host] = c.byHost[host] + delta
        return true
}

func (c *cacheSizer) sub(host string, delta int64) {
        if delta <= 0 {
                return
        }
        c.mu.Lock()
        defer c.mu.Unlock()
        c.totalBytes -= delta
        if c.totalBytes < 0 {
                c.totalBytes = 0
        }
        c.byHost[host] = c.byHost[host] - delta
        if c.byHost[host] < 0 {
                c.byHost[host] = 0
        }
}

type localCache struct {
        sync.RWMutex
        Data map[string]map[string][]byte
}

type remoteEntry struct {
        Data     []byte
        Expiry   time.Time
        Size     int64
        MimeType string
}

type remoteCache struct {
        mu   sync.RWMutex
        data map[string]map[string]remoteEntry
}

func (rc *remoteCache) get(host, p string) (remoteEntry, bool) {
        rc.mu.RLock()
        m := rc.data[host]
        if m == nil {
                rc.mu.RUnlock()
                return remoteEntry{}, false
        }
        e, ok := m[p]
        rc.mu.RUnlock()
        if !ok {
                return remoteEntry{}, false
        }
        if !e.Expiry.IsZero() && time.Now().After(e.Expiry) {
                rc.mu.Lock()
                m2 := rc.data[host]
                if m2 != nil {
                        if e2, ok2 := m2[p]; ok2 {
                                delete(m2, p)
                                rc.mu.Unlock()
                                memGuard.sub(host, e2.Size)
                                return remoteEntry{}, false
                        }
                }
                rc.mu.Unlock()
                return remoteEntry{}, false
        }
        return e, true
}

func (rc *remoteCache) set(host, p string, e remoteEntry) bool {
        rc.mu.Lock()
        defer rc.mu.Unlock()

        if rc.data[host] == nil {
                rc.data[host] = map[string]remoteEntry{}
        }

        old, had := rc.data[host][p]
        if had {
                memGuard.sub(host, old.Size)
        }

        if !memGuard.tryAdd(host, e.Size) {
                if had {
                        rc.data[host][p] = old
                        memGuard.tryAdd(host, old.Size)
                } else {
                        delete(rc.data[host], p)
                        if len(rc.data[host]) == 0 {
                                delete(rc.data, host)
                        }
                }
                return false
        }

        rc.data[host][p] = e
        return true
}

func (rc *remoteCache) purgeExpired(host string) {
        now := time.Now()
        var reclaimed int64
        rc.mu.Lock()
        m := rc.data[host]
        if m == nil {
                rc.mu.Unlock()
                return
        }
        for k, v := range m {
                if !v.Expiry.IsZero() && now.After(v.Expiry) {
                        reclaimed += v.Size
                        delete(m, k)
                }
        }
        if len(m) == 0 {
                delete(rc.data, host)
        }
        rc.mu.Unlock()
        if reclaimed > 0 {
                memGuard.sub(host, reclaimed)
        }
}

var (
        magpieConfig *MagpieConfig

        watcher *fsnotify.Watcher
        certMap = sync.Map{}

        rewriteMu      sync.RWMutex
        rewritesByHost = map[string][]RewriteRule{}

        localFiles = &localCache{Data: map[string]map[string][]byte{}}

        remoteFiles = &remoteCache{data: map[string]map[string]remoteEntry{}}

        remoteOriginMu sync.RWMutex
        remoteOrigin   = map[string]*url.URL{}

        tcpConnIDs = &connIDStore{m: map[string]uuid.UUID{}}

        quicSessions = &quicSessionStore{
                m:       map[string]quicSession{},
                maxSize: 10000,
                ttl:     10 * time.Minute,
        }

        memGuard = &cacheSizer{
                byHost:  map[string]int64{},
                hostErr: map[string]string{},
        }

        httpClient *http.Client
)

func main() {
        const kiamagpieVersion = "0.1.2"
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
        magpieConfig = &cfg

        avail := availableRAMBytes()

        percent := magpieConfig.Magpie.RAMLimitPercent
        if percent <= 0 {
                percent = defaultRAMPercentFloat
        }
        if percent > safeMaxRAMPercent {
                percent = safeMaxRAMPercent
        }

        limit := int64(float64(avail) * (percent / 100.0))
        if limit <= 0 {
                limit = (defaultAvailRAMBytes * defaultRAMPercentInt) / 100
        }
        if limit > safeMaxRAMLimitBytes {
                limit = safeMaxRAMLimitBytes
        }
        memGuard.setLimit(limit)

        httpClient = strictHTTPClient()

        logEvent(uuid.New(), map[string]interface{}{
                "event":           "server_start",
                "version":         magpieVersion,
                "ram_limit_bytes": limit,
                "ram_percent":     percent,
                "ram_avail_bytes": avail,
        })

        watcher, err = fsnotify.NewWatcher()
        if err != nil {
                logError(uuid.New(), "watcher_create_failed", err, nil)
                os.Exit(1)
        }
        defer watcher.Close()

        go watchLoop()

        hosts := parseVHosts(magpieConfig)

        rewriteMu.Lock()
        for _, vh := range append(append(hosts.TLS, hosts.HTTP...), hosts.QUIC...) {
                if len(vh.Rewrites) > 0 {
                        rewritesByHost[vh.Domain] = vh.Rewrites
                }
        }
        rewriteMu.Unlock()

        indexRemoteOrigins(hosts)
        reloadAllLocalFiles(hosts)

        var wg sync.WaitGroup

        if magpieConfig.Magpie.HTTPEnabled {
                for _, h := range hosts.HTTP {
                        wg.Add(1)
                        go func(v VirtualHost) {
                                defer wg.Done()
                                startHTTP(v)
                        }(h)
                }
        }

        if magpieConfig.Magpie.TLSEnabled {
                for _, h := range hosts.TLS {
                        wg.Add(1)
                        go func(v VirtualHost) {
                                defer wg.Done()
                                startHTTPS(v)
                        }(h)
                }
        }

        if magpieConfig.Magpie.QUICEnabled {
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
        process := func(raw interface{}, flavor string) []VirtualHost {
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
                                vh := VirtualHost{Domain: domain, Addr: addr, TransportFlavor: flavor}
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
                                                        vh.WebRoot = strings.TrimSpace(s)
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
        res.TLS = process(cfg.Magpie.DomainsTLS, "https")
        res.QUIC = process(cfg.Magpie.DomainsQUIC, "quic")
        res.HTTP = process(cfg.Magpie.DomainsHTTP, "http")
        return res
}

func indexRemoteOrigins(hosts ParsedHosts) {
        all := append(append(hosts.TLS, hosts.HTTP...), hosts.QUIC...)
        remoteOriginMu.Lock()
        defer remoteOriginMu.Unlock()
        for _, vh := range all {
                if vh.WebRoot == "" {
                        continue
                }
                if u, ok := parseHTTPSOrigin(vh.WebRoot); ok {
                        remoteOrigin[vh.Domain] = u
                }
        }
}

func parseHTTPSOrigin(s string) (*url.URL, bool) {
        if !strings.HasPrefix(strings.ToLower(s), "https://") {
                return nil, false
        }
        u, err := url.Parse(s)
        if err != nil || u == nil {
                return nil, false
        }
        if u.Scheme != "https" || u.Host == "" {
                return nil, false
        }
        u.Fragment = ""
        if u.Path == "" {
                u.Path = "/"
        }
        u.Path = strings.TrimSuffix(u.Path, "/") + "/"
        return u, true
}

func getOriginForHost(host string) (*url.URL, bool) {
        remoteOriginMu.RLock()
        defer remoteOriginMu.RUnlock()
        u, ok := remoteOrigin[host]
        return u, ok
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
        if len(cert.Certificate) == 0 {
                return errors.New("empty certificate chain")
        }
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
                SessionTicketsDisabled: true,
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
                Handler:  securityHeadersMiddleware(middleware(vh, mux)),
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
                Handler:   securityHeadersMiddleware(middleware(vh, mux)),
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
                Handler:   securityHeadersMiddleware(middleware(vh, http.HandlerFunc(handle))),
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

func securityHeadersMiddleware(next http.Handler) http.Handler {
        applyHSTS := magpieConfig != nil && magpieConfig.Magpie.HSTS
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("X-Content-Type-Options", "nosniff")
                w.Header().Set("X-Frame-Options", "SAMEORIGIN")
                w.Header().Set("X-XSS-Protection", "1; mode=block")
                if applyHSTS && r.TLS != nil {
                        w.Header().Set("Strict-Transport-Security", hstsHeaderValue)
                }
                next.ServeHTTP(w, r)
        })
}

func middleware(vh VirtualHost, next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                id := interactionIDFromRequest(r)
                srcIP := sourceIP(r.RemoteAddr)
                start := time.Now()

                hostKey := stripPort(r.Host)
                if e, ok := memGuard.getHostErr(hostKey); ok && e == "ram_limit_exceeded" {
                        logEvent(id, map[string]interface{}{
                                "level":      "error",
                                "event":      "content_unavailable",
                                "reason":     "ram_limit_exceeded",
                                "src_ip":     srcIP,
                                "method":     r.Method,
                                "path":       r.URL.Path,
                                "host":       r.Host,
                                "sni":        tlsSNI(r),
                                "transport":  requestTransportProto(r),
                                "http_proto": r.Proto,
                        })
                        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
                        w.WriteHeader(http.StatusServiceUnavailable)
                        _, _ = w.Write([]byte("Content temporarily unavailable: cache memory limit exceeded.\n"))
                        return
                }

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
                        "transport":        requestTransportProto(r),
                        "http_proto":       r.Proto,
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

func applyRewrites(host, p string) string {
        rewriteMu.RLock()
        rules := rewritesByHost[host]
        rewriteMu.RUnlock()

        for _, rr := range rules {
                if rr.From == p && rr.To != "" {
                        return rr.To
                }
        }
        return p
}

func handle(w http.ResponseWriter, r *http.Request) {
        host := stripPort(r.Host)
        p := applyRewrites(host, r.URL.Path)

        if data, ok := getLocal(host, p); ok {
                ctype := mime.TypeByExtension(filepath.Ext(p))
                if ctype == "" {
                        ctype = "application/octet-stream"
                }
                w.Header().Set("Content-Type", ctype)
                _, _ = w.Write(data)
                return
        }

        if origin, ok := getOriginForHost(host); ok {
                remoteFiles.purgeExpired(host)

                if e, ok := remoteFiles.get(host, p); ok {
                        if e.MimeType != "" {
                                w.Header().Set("Content-Type", e.MimeType)
                        } else {
                                ctype := mime.TypeByExtension(filepath.Ext(p))
                                if ctype == "" {
                                        ctype = "application/octet-stream"
                                }
                                w.Header().Set("Content-Type", ctype)
                        }
                        _, _ = w.Write(e.Data)
                        return
                }

                body, ctype, status, err := fetchRemote(origin, p)
                if err != nil {
                        id := interactionIDFromRequest(r)
                        logError(id, "remote_fetch_failed", err, map[string]interface{}{
                                "host":   r.Host,
                                "path":   r.URL.Path,
                                "origin": origin.String(),
                                "status": status,
                        })
                        http.Error(w, "Upstream fetch failed.\n", http.StatusBadGateway)
                        return
                }
                if status == http.StatusNotFound {
                        http.NotFound(w, r)
                        return
                }
                if status < 200 || status >= 300 {
                        id := interactionIDFromRequest(r)
                        logError(id, "remote_fetch_bad_status", errors.New("bad upstream status"), map[string]interface{}{
                                "host":   r.Host,
                                "path":   r.URL.Path,
                                "origin": origin.String(),
                                "status": status,
                        })
                        http.Error(w, "Upstream fetch failed.\n", http.StatusBadGateway)
                        return
                }

                cacheSecs := 0
                if magpieConfig != nil {
                        cacheSecs = magpieConfig.Magpie.CacheAgeSecs
                }
                if cacheSecs < 0 {
                        cacheSecs = 0
                }
                exp := time.Time{}
                if cacheSecs > 0 {
                        exp = time.Now().Add(time.Duration(cacheSecs) * time.Second)
                }

                entry := remoteEntry{
                        Data:     body,
                        Expiry:   exp,
                        Size:     int64(len(body)) + int64(len(p)),
                        MimeType: ctype,
                }
                cached := remoteFiles.set(host, p, entry)

                if !cached {
                        id := interactionIDFromRequest(r)
                        total, limit := memGuard.snapshot()
                        logEvent(id, map[string]interface{}{
                                "level":        "warn",
                                "event":        "remote_cache_bypass",
                                "reason":       "ram_limit",
                                "host":         r.Host,
                                "path":         r.URL.Path,
                                "origin":       origin.String(),
                                "cache_total":  total,
                                "cache_limit":  limit,
                                "object_bytes": len(body),
                        })
                }

                if ctype != "" {
                        w.Header().Set("Content-Type", ctype)
                } else {
                        ctype2 := mime.TypeByExtension(filepath.Ext(p))
                        if ctype2 == "" {
                                ctype2 = "application/octet-stream"
                        }
                        w.Header().Set("Content-Type", ctype2)
                }
                _, _ = w.Write(body)
                return
        }

        http.NotFound(w, r)
}

func getLocal(host, p string) ([]byte, bool) {
        localFiles.RLock()
        defer localFiles.RUnlock()
        m := localFiles.Data[host]
        if m == nil {
                return nil, false
        }
        b, ok := m[p]
        return b, ok
}

func reloadAllLocalFiles(hosts ParsedHosts) {
        all := append(append(hosts.TLS, hosts.HTTP...), hosts.QUIC...)
        for _, vh := range all {
                if vh.WebRoot == "" {
                        continue
                }
                if _, ok := parseHTTPSOrigin(vh.WebRoot); ok {
                        continue
                }
                _ = loadSiteFromDiskIntoCache(vh)
        }
}

func loadSiteFromDiskIntoCache(vh VirtualHost) error {
        fsmap := map[string][]byte{}
        err := filepath.WalkDir(vh.WebRoot, func(p string, d fs.DirEntry, walkErr error) error {
                if walkErr != nil {
                        logWarn(uuid.New(), "walkdir_error", walkErr, map[string]interface{}{
                                "host": vh.Domain,
                                "path": p,
                        })
                        return nil
                }
                if d.IsDir() {
                        return nil
                }
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
                return nil
        })
        if err != nil {
                logError(uuid.New(), "disk_load_failed", err, map[string]interface{}{
                        "host":     vh.Domain,
                        "web_root": vh.WebRoot,
                })
                return err
        }

        newBytes := int64(mapBytes(fsmap))
        if err := memGuard.setHostTotal(vh.Domain, newBytes); err != nil {
                total, limit := memGuard.snapshot()
                logError(uuid.New(), "ram_limit_exceeded", err, map[string]interface{}{
                        "host":        vh.Domain,
                        "web_root":    vh.WebRoot,
                        "host_bytes":  newBytes,
                        "cache_total": total,
                        "cache_limit": limit,
                })
                return err
        }

        localFiles.Lock()
        localFiles.Data[vh.Domain] = fsmap
        localFiles.Unlock()

        logEvent(uuid.New(), map[string]interface{}{
                "event":      "disk_site_loaded",
                "host":       vh.Domain,
                "web_root":   vh.WebRoot,
                "file_count": len(fsmap),
        })

        return nil
}

func fetchRemote(origin *url.URL, reqPath string) ([]byte, string, int, error) {
        p := reqPath
        if p == "" {
                p = "/"
        }
        if !strings.HasPrefix(p, "/") {
                p = "/" + p
        }

        clean := path.Clean(p)
        if clean == "." {
                clean = "/"
        }
        if !strings.HasPrefix(clean, "/") {
                clean = "/" + clean
        }
        if strings.Contains(clean, "..") {
                return nil, "", 0, errors.New("invalid path")
        }

        u := *origin
        basePath := u.Path
        if basePath == "" {
                basePath = "/"
        }
        if !strings.HasSuffix(basePath, "/") {
                basePath += "/"
        }
        joined := path.Join(strings.TrimSuffix(basePath, "/"), clean)
        if !strings.HasPrefix(joined, "/") {
                joined = "/" + joined
        }
        u.Path = joined
        u.RawQuery = ""
        u.Fragment = ""

        ctx, cancel := context.WithTimeout(context.Background(), remoteFetchTimeout)
        defer cancel()

        req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
        if err != nil {
                return nil, "", 0, err
        }

        resp, err := httpClient.Do(req)
        if err != nil {
                return nil, "", 0, err
        }
        defer resp.Body.Close()

        if resp.StatusCode == http.StatusNotFound {
                return nil, "", http.StatusNotFound, nil
        }

        b, err := io.ReadAll(resp.Body)
        if err != nil {
                return nil, "", resp.StatusCode, err
        }

        ctype := resp.Header.Get("Content-Type")
        if ctype == "" {
                ctype = mime.TypeByExtension(filepath.Ext(clean))
        }

        return b, ctype, resp.StatusCode, nil
}

func strictHTTPClient() *http.Client {
        tlsConf := &tls.Config{
                MinVersion: tls.VersionTLS13,
                CurvePreferences: []tls.CurveID{
                        tls.X25519MLKEM768,
                        tls.X25519,
                        tls.CurveP256,
                        tls.CurveP384,
                        tls.CurveP521,
                },
                SessionTicketsDisabled: true,
        }

        tr := &http.Transport{
                TLSClientConfig:       tlsConf,
                ForceAttemptHTTP2:     true,
                DisableCompression:    false,
                MaxIdleConns:          128,
                MaxIdleConnsPerHost:   16,
                IdleConnTimeout:       30 * time.Second,
                TLSHandshakeTimeout:   5 * time.Second,
                ResponseHeaderTimeout: 8 * time.Second,
                ExpectContinueTimeout: 1 * time.Second,
        }

        return &http.Client{
                Transport: tr,
                Timeout:   remoteFetchTimeout,
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

func availableRAMBytes() int64 {
        if runtime.GOOS == "linux" {
                var info unix.Sysinfo_t
                if err := unix.Sysinfo(&info); err == nil {
                        unit := int64(info.Unit)
                        if unit <= 0 {
                                unit = 1
                        }
                        free := int64(info.Freeram) * unit
                        if free > 0 {
                                return free
                        }
                }
        }
        return defaultAvailRAMBytes
}

func mapBytes(m map[string][]byte) int {
        n := 0
        for k, v := range m {
                n += len(k)
                n += len(v)
        }
        return n
}

func init() {
        log.SetOutput(io.Discard)
}
