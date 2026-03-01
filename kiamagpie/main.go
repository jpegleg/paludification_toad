package main

import (
        "crypto/ecdsa"
        "crypto/ed25519"
        "crypto/tls"
        "crypto/x509"
        "encoding/hex"
        "encoding/json"
        "errors"
        "fmt"
        "io/fs"
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
        "github.com/zeebo/blake3"
        "gopkg.in/yaml.v3"
)

const ipSalt = "F0000004ACCEPTEDFIXEDSALTFFFFFFF0"

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

type VirtualHost struct {
        Domain   string
        Addr     string
        CertPath string
        KeyPath  string
        WebRoot  string
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

type Interaction struct {
        ID       uuid.UUID
        HashIP   string
        Start    time.Time
        Protocol string
}

var (
        config  *MagpieConfig
        cache   = &fileCache{Data: map[string]map[string][]byte{}}
        watcher *fsnotify.Watcher
        certMap = sync.Map{}
)

func main() {
        data, err := os.ReadFile("domains.yaml")
        if err != nil {
                panic(err)
        }
        var cfg MagpieConfig
        if err := yaml.Unmarshal(data, &cfg); err != nil {
                panic(err)
        }
        config = &cfg

        watcher, err = fsnotify.NewWatcher()
        if err != nil {
                panic(err)
        }
        defer watcher.Close()

        go watchLoop()

        hosts := parseVHosts(config)
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
                                                vh.CertPath = v.(string)
                                        }
                                        if v, ok := props["key"]; ok {
                                                vh.KeyPath = v.(string)
                                        }
                                        if v, ok := props["web_content"]; ok {
                                                vh.WebRoot = v.(string)
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
        case <-watcher.Errors:
        }
    }
}

func reloadCert(cs *certStore) {
    cert, err := tls.LoadX509KeyPair(cs.certPath, cs.keyPath)
    if err != nil {
        return
    }

    if err := validateIdentity(cert); err != nil {
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

    watcher.Add(vh.CertPath)
    watcher.Add(vh.KeyPath)

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
                        logEvent(uuid.New(), map[string]interface{}{
                                "event": "tls_client_hello",
                                "sni":   chi.ServerName,
                        })
                        return cs.cert.Load(), nil
                },
        }, nil
}

func startHTTP(vh VirtualHost) {
        mux := http.NewServeMux()
        mux.HandleFunc("/", handle)
        http.ListenAndServe(vh.Addr, middleware(vh, mux))
}

func startHTTPS(vh VirtualHost) {
        conf, err := tlsConfigForHost(vh)
        if err != nil {
                fmt.Println("TLS Config Error:", err)
                return
        }

        mux := http.NewServeMux()
        mux.HandleFunc("/", handle)

        srv := &http.Server{
                Addr:      vh.Addr,
                TLSConfig: conf,
                Handler:   middleware(vh, mux),
        }

        ln, err := tls.Listen("tcp", vh.Addr, conf)
        if err != nil {
                fmt.Printf("Failed to start HTTPS on %s: %v\n", vh.Addr, err)
                return
        }

        if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
                fmt.Printf("HTTPS Server Error on %s: %v\n", vh.Addr, err)
        }
}

func startQUIC(vh VirtualHost) {
        conf, err := tlsConfigForHost(vh)
        if err != nil {
                panic(err)
        }
        conf.NextProtos = []string{"h3"}
        srv := &http3.Server{
                Addr:      vh.Addr,
                TLSConfig: conf,
                Handler:   middleware(vh, http.HandlerFunc(handle)),
        }

        addr, err := net.ResolveUDPAddr("udp", vh.Addr)
        if err != nil {
                panic(err)
        }

        const receiveBufferSize = 1024 * 1024

        packetConn, err := net.ListenUDP("udp", addr)
        if err != nil {
                panic(err)
        }

        if err := packetConn.SetReadBuffer(receiveBufferSize); err != nil {
                fmt.Fprintf(os.Stderr, "Warning: failed to set UDP read buffer on %s: %v\n", vh.Addr, err)
        }

        if err := srv.Serve(packetConn); err != nil {
                fmt.Println("QUIC Server Error:", err)
        }
}

func middleware(vh VirtualHost, next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                id := uuid.New()
                hashIP := hashSourceIP(r.RemoteAddr)
                start := time.Now()
                lrw := &respWrap{ResponseWriter: w, status: 200}
                next.ServeHTTP(lrw, r)

                logEvent(id, map[string]interface{}{
                        "remote_src_hash": hashIP,
                        "method":      r.Method,
                        "path":        r.URL.Path,
                        "host":        r.Host,
                        "sni":         tlsSNI(r),
                        "status":      lrw.status,
                        "wait_duration_ms": time.Since(start).Milliseconds(),
                })
        })
}

type respWrap struct {
        http.ResponseWriter
        status int
}

func (r *respWrap) WriteHeader(code int) {
        r.status = code
        r.ResponseWriter.WriteHeader(code)
}

func handle(w http.ResponseWriter, r *http.Request) {
        host := stripPort(r.Host)
        cache.RLock()
        data := cache.Data[host]
        cache.RUnlock()
        path := r.URL.Path
        if path == "/" {
                path = "/index.html"
        }
        if path == "/art" {
                path = "/art.html"
        }
        if path == "/shows" {
                path = "/shows.html"
        }
        if path == "/music" {
                path = "/music.html"
        }
        if path == "/about" {
                path = "/index.html"
        }
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
        w.Write(content)
}

func reloadAllFiles(hosts ParsedHosts) {
        all := append(append(hosts.TLS, hosts.HTTP...), hosts.QUIC...)
        for _, vh := range all {
                if vh.WebRoot == "" {
                        continue
                }
                fsmap := map[string][]byte{}
                filepath.WalkDir(vh.WebRoot, func(p string, d fs.DirEntry, err error) error {
                        if !d.IsDir() {
                                rel, _ := filepath.Rel(vh.WebRoot, p)
                                rel = "/" + strings.ReplaceAll(rel, "\\", "/")
                                b, _ := os.ReadFile(p)
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

func hashSourceIP(addr string) string {
        h, _, _ := net.SplitHostPort(addr)
        sum := blake3.Sum256([]byte(h + ipSalt))
        return hex.EncodeToString(sum[:])
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
