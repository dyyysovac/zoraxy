// Package acme handles the acme issuing process
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/challenge/http01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/netutils"
	"imuslab.com/zoraxy/mod/utils"
)

var defaultNameservers = []string{
	"8.8.8.8:53", // Google DNS
	"8.8.4.4:53", // Google DNS
	"1.1.1.1:53", // Cloudflare DNS
	"1.0.0.1:53", // Cloudflare DNS
}

type CertificateInfoJSON struct {
	AcmeName                     string   `json:"acme_name"`                       // ACME provider name
	AcmeUrl                      string   `json:"acme_url"`                        // Custom ACME URL (if any)
	SkipTLS                      bool     `json:"skip_tls"`                        // Skip TLS verification of upstream
	UseDNS                       bool     `json:"dns"`                             // Use DNS challenge
	PropTimeout                  int      `json:"prop_time"`                       // Propagation timeout
	DNSServers                   []string `json:"dnsServers"`                      // DNS servers
	DisableRecursiveNssCheck     bool     `json:"disable_recursive_nss_check"`     // Disable Recursive NSs Propagation Check
	DisableAuthoritativeNssCheck bool     `json:"disable_authoritative_nss_check"` // Disable Authoritative NSs Propagation Check
}

type EABConfig struct {
	Kid     string `json:"kid"`
	HmacKey string `json:"HmacKey"`
}

// ACMEHandler handles ACME-related operations.
type ACMEHandler struct {
	Port           string
	Database       *database.Database
	Logger         *logger.Logger
	TestMode       bool
	KeyFileMode    os.FileMode
	PublicFileMode os.FileMode

	// PrepareHTTP01Challenge, if set, is called before every HTTP-01
	// challenge, whatever started it (manual request, auto renew, Renew Now),
	// e.g. to make sure port 80 is served. The returned function is called
	// once the challenge is done
	PrepareHTTP01Challenge func() (release func())

	// Tokens of the HTTP-01 challenges Zoraxy is presenting right now
	httpChallengeTokens     map[string]int
	httpChallengeTokensLock sync.Mutex
}

// NewACME creates a new ACMEHandler instance.
func NewACME(
	port string, database *database.Database,
	logger *logger.Logger, testMode bool, keyFileMode os.FileMode, publicFileMode os.FileMode,
) *ACMEHandler {
	return &ACMEHandler{
		Port:           port,
		Database:       database,
		Logger:         logger,
		TestMode:       testMode,
		KeyFileMode:    keyFileMode,
		PublicFileMode: publicFileMode,
	}
}

func (a *ACMEHandler) Logf(message string, err error) {
	a.Logger.PrintAndLog("ACME", message, err)
}

// Close closes the ACMEHandler.
// ACME Handler does not need to close anything
// Function defined for future compatibility
func (a *ACMEHandler) Close() error {
	return nil
}

func (a *ACMEHandler) writeFileWithMode(filename string, data []byte, mode os.FileMode) error {
	err := os.WriteFile(filename, data, mode)
	if err != nil {
		return err
	}

	return os.Chmod(filename, mode)
}

// ObtainCert obtains a certificate for the specified domains.
func (a *ACMEHandler) ObtainCert(domains []string, certificateName string, email string, caName string, caUrl string, skipTLS bool, useDNS bool, propagationTimeout int, dnsServers string, disableRecursiveNssCheck bool, disableAuthoritativeNssCheck bool) (bool, error) {
	ctx := context.TODO()

	a.Logf("Obtaining certificate for: "+strings.Join(domains, ", "), nil)

	// Resolve the CA directory URL before creating an account or config,
	// so we can check for an existing account before generating a new key.
	//
	// Fallback to Let's Encrypt if it is not set
	if caName == "" {
		caName = "Let's Encrypt"
	}

	// setup the custom ACME url endpoint.
	if caName == "custom" {
		a.Logf("Using Custom ACME "+caUrl+" for CA Directory URL", nil)
	} else if caUrl == "" {
		// if not custom ACME url, load it from ca.json
		caLinkOverwrite, err := loadCAApiServerFromName(caName, a.TestMode)
		if err == nil {
			caUrl = caLinkOverwrite
			a.Logf("Using "+caLinkOverwrite+" for CA Directory URL", nil)
		} else {
			caUrl, _ = loadCAApiServerFromName("Let's Encrypt", a.TestMode)
			a.Logf("Using Default ACME "+caUrl+" for CA Directory URL", nil)
		}
	} else {
		a.Logf("Using "+caUrl+" for CA Directory URL", nil)
	}

	// Reuse a previously registered ACME account for this CA if one is stored
	// in the database. Only generate a new account key if no stored account
	// is found.
	var adminUser ACMEUser
	accountLoaded := false
	if loadedKey, loadedReg, ok := a.loadACMEAccount(caUrl, email); ok {
		adminUser = ACMEUser{
			Email:        email,
			key:          loadedKey,
			Registration: loadedReg,
		}
		accountLoaded = true
		a.Logf("Reusing existing ACME account for "+caUrl, nil)
	} else {
		// generate private key
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			a.Logf("Private key generation failed", err)
			return false, err
		}
		// create a admin user for our new generation
		adminUser = ACMEUser{
			Email: email,
			key:   privateKey,
		}
	}

	// create config
	config := lego.NewConfig(&adminUser)
	config.CADirURL = caUrl

	// skip TLS verify if need
	// Ref: https://github.com/go-acme/lego/blob/6af2c756ac73a9cb401621afca722d0f4112b1b8/lego/client_config.go#L74
	if skipTLS {
		a.Logf("Ignoring TLS/SSL Verification Error for ACME Server", nil)
		config.HTTPClient.Transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	client, err := lego.NewClient(config)
	if err != nil {
		a.Logf("Failed to spawn new ACME client from current config", err)
		return false, err
	}

	// Load certificate info from JSON file
	// The challenge type is chosen by the caller, see RequestUsesDNSChallenge
	certInfo, err := LoadCertInfoJSON(fmt.Sprintf("./conf/certs/%s.json", certificateName))
	if err == nil {
		if dnsServers == "" && certInfo.DNSServers != nil && len(certInfo.DNSServers) > 0 {
			dnsServers = strings.Join(certInfo.DNSServers, ",")
		}
		if certInfo.PropTimeout > 0 {
			propagationTimeout = certInfo.PropTimeout
		}
		if certInfo.DisableRecursiveNssCheck {
			disableRecursiveNssCheck = certInfo.DisableRecursiveNssCheck
		}
		if certInfo.DisableAuthoritativeNssCheck {
			disableAuthoritativeNssCheck = certInfo.DisableAuthoritativeNssCheck
		}
	}

	// Ensure at least one NSs propagation check is enabled
	// When disabling authoritative NSs check, recursive NSs check must stay enabled
	if disableAuthoritativeNssCheck && disableRecursiveNssCheck {
		a.Logf("DisableAuthoritativeNssCheck requires recursive NSs check to be enabled; forcing DisableRecursiveNssCheck = false", nil)
		disableRecursiveNssCheck = false
	}

	// Clean DNS servers
	dnsNameservers := strings.Split(dnsServers, ",")
	for i := range dnsNameservers {
		dnsNameservers[i] = strings.TrimSpace(dnsNameservers[i])
	}

	// setup how to receive challenge
	if useDNS {
		if !a.Database.TableExists("acme") {
			a.Database.NewTable("acme")
			return false, errors.New("DNS Provider and DNS Credential configuration required for ACME Provider (Error -1)")
		}

		if !a.Database.KeyExists("acme", certificateName+"_dns_provider") || !a.Database.KeyExists("acme", certificateName+"_dns_credentials") {
			return false, errors.New("DNS Provider and DNS Credential configuration required for ACME Provider (Error -2)")
		}

		var dnsCredentials string
		err := a.Database.Read("acme", certificateName+"_dns_credentials", &dnsCredentials)
		if err != nil {
			a.Logf("Read DNS credential failed", err)
			return false, err
		}

		var dnsProvider string
		err = a.Database.Read("acme", certificateName+"_dns_provider", &dnsProvider)
		if err != nil {
			a.Logf("Read DNS Provider failed", err)
			return false, err
		}

		provider, err := GetDnsChallengeProviderByName(dnsProvider, dnsCredentials, propagationTimeout)
		if err != nil {
			a.Logf("Unable to resolve DNS challenge provider", err)
			return false, err
		}

		opts := &dns01.Options{}

		if len(dnsNameservers) > 0 && dnsNameservers[0] != "" {
			a.Logf("Using DNS servers: "+strings.Join(dnsNameservers, ", "), nil)
			opts.RecursiveNameservers = dnsNameservers
		} else {
			// Use default DNS-01 nameservers if dnsServers is empty
			opts.RecursiveNameservers = defaultNameservers
		}

		dns01.SetDefaultClient(dns01.NewClient(opts))

		dnsOpts := []dns01.ChallengeOption{}
		if disableRecursiveNssCheck {
			dnsOpts = append(dnsOpts, dns01.DisableRecursiveNSsPropagationRequirement())
		}
		if disableAuthoritativeNssCheck {
			dnsOpts = append(dnsOpts, dns01.DisableAuthoritativeNssPropagationRequirement())
		}
		err = client.Challenge.SetDNS01Provider(provider, dnsOpts...)
		if err != nil {
			a.Logf("Failed to resolve DNS01 Provider", err)
			return false, err
		}
	} else {
		err = client.Challenge.SetHTTP01Provider(&http01TokenTracker{
			Provider: http01.NewProviderServer("", a.Port),
			handler:  a,
		})
		if err != nil {
			a.Logf("Failed to resolve HTTP01 Provider", err)
			return false, err
		}
		if a.PrepareHTTP01Challenge != nil {
			release := a.PrepareHTTP01Challenge()
			defer release()
		}
	}

	// New users will need to register
	/*
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Println(err)
			return false, err
		}
	*/
	var reg *acme.ExtendedAccount
	// New users will need to register. If we reused an account loaded from
	// disk, it is already registered - registering again would count against
	// the CA's "new registrations per IP" rate limit, so skip it entirely.
	if accountLoaded {
		reg = adminUser.Registration
	} else if client.GetServerMetadata().ExternalAccountRequired {
		a.Logf("External Account Required for this ACME Provider", nil)
		// IF KID and HmacEncoded is overidden

		if !a.Database.TableExists("acme") {
			a.Database.NewTable("acme")
			return false, errors.New("kid and HmacEncoded configuration required for ACME Provider (Error -1)")
		}

		if !a.Database.KeyExists("acme", config.CADirURL+"_kid") || !a.Database.KeyExists("acme", config.CADirURL+"_hmacEncoded") {
			return false, errors.New("kid and HmacEncoded configuration required for ACME Provider (Error -2)")
		}

		var kid string
		var hmacEncoded string
		err := a.Database.Read("acme", config.CADirURL+"_kid", &kid)
		if err != nil {
			a.Logf("Failed to read kid from database", err)
			return false, err
		}

		err = a.Database.Read("acme", config.CADirURL+"_hmacEncoded", &hmacEncoded)
		if err != nil {
			a.Logf("Failed to read HMAC from database", err)
			return false, err
		}

		a.Logf("EAB Credential retrieved: "+kid+" / "+hmacEncoded, nil)
		if kid != "" && hmacEncoded != "" {
			reg, err = client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
				TermsOfServiceAgreed: true,
				Kid:                  kid,
				HmacEncoded:          hmacEncoded,
			})
		}
		if err != nil {
			a.Logf("Register with external account binder failed", err)
			return false, err
		}
		// return false, errors.New("External Account Required for this ACME Provider.")
	} else {
		reg, err = client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			a.Logf("Unable to register client", err)
			return false, err
		}
	}
	adminUser.Registration = reg

	// Persist a freshly registered account so future certificate requests and
	// renewals reuse it instead of registering a brand new account each time.
	if !accountLoaded && reg != nil {
		if serr := a.saveACMEAccount(config.CADirURL, &adminUser); serr != nil {
			a.Logf("Failed to persist ACME account (may hit account create limits, try a different IP)", serr)
		} else {
			a.Logf("Persisted ACME account for reuse on "+config.CADirURL, nil)
		}
	}

	// obtain the certificate
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
		KeyType: certcrypto.RSA2048,
	}

	certificates, err := client.Certificate.Obtain(ctx, request)
	if err != nil {
		a.Logf("Obtain certificate failed", err)
		return false, err
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL.
	err = a.writeFileWithMode("./conf/certs/"+certificateName+".pem", certificates.Certificate, a.PublicFileMode)
	if err != nil {
		a.Logf("Failed to write public key to disk", err)
		return false, err
	}
	err = a.writeFileWithMode("./conf/certs/"+certificateName+".key", certificates.PrivateKey, a.KeyFileMode)
	if err != nil {
		a.Logf("Failed to write private key to disk", err)
		return false, err
	}

	// Save certificate's ACME info for renew usage
	certInfo = &CertificateInfoJSON{
		AcmeName:                     caName,
		AcmeUrl:                      caUrl,
		SkipTLS:                      skipTLS,
		UseDNS:                       useDNS,
		PropTimeout:                  propagationTimeout,
		DNSServers:                   dnsNameservers,
		DisableRecursiveNssCheck:     disableRecursiveNssCheck,
		DisableAuthoritativeNssCheck: disableAuthoritativeNssCheck,
	}

	certInfoBytes, err := json.Marshal(certInfo)
	if err != nil {
		a.Logf("Marshal certificate renew config failed", err)
		return false, err
	}

	err = a.writeFileWithMode("./conf/certs/"+certificateName+".json", certInfoBytes, a.PublicFileMode)
	if err != nil {
		a.Logf("Failed to write certificate renew config to file", err)
		return false, err
	}

	return true, nil
}

// CheckCertificate returns a list of domains that are in expired certificates.
// It will return all domains that is in expired certificates
// *** if there is a vaild certificate contains the domain and there is a expired certificate contains the same domain
// it will said expired as well!
func (a *ACMEHandler) CheckCertificate() []string {
	// read from dir
	filenames, err := os.ReadDir("./conf/certs/")

	expiredCerts := []string{}

	if err != nil {
		a.Logf("Failed to load certificate folder", err)
		return []string{}
	}

	for _, filename := range filenames {
		certFilepath := filepath.Join("./conf/certs/", filename.Name())

		certBytes, err := os.ReadFile(certFilepath)
		if err != nil {
			// Unable to load this file
			continue
		} else {
			// Cert loaded. Check its expiry time
			block, _ := pem.Decode(certBytes)
			if block != nil {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					elapsed := time.Since(cert.NotAfter)
					if elapsed > 0 {
						// if it is expired then add it in
						// make sure it's uniqueless
						for _, dnsName := range cert.DNSNames {
							if !contains(expiredCerts, dnsName) {
								expiredCerts = append(expiredCerts, dnsName)
							}
						}
						if !contains(expiredCerts, cert.Subject.CommonName) {
							expiredCerts = append(expiredCerts, cert.Subject.CommonName)
						}
					}
				}
			}
		}
	}

	return expiredCerts
}

// return the current port number
func (a *ACMEHandler) Getport() string {
	return a.Port
}

// IsPresentingHTTP01Token returns true if Zoraxy is presenting the HTTP-01
// challenge with this token right now, i.e. if a request for
// /.well-known/acme-challenge/<token> must be answered by Zoraxy instead of
// being forwarded to the proxy backend. Challenges of backends that run their
// own ACME client have other tokens, so they still reach the backend (#1342)
func (a *ACMEHandler) IsPresentingHTTP01Token(token string) bool {
	a.httpChallengeTokensLock.Lock()
	defer a.httpChallengeTokensLock.Unlock()
	return a.httpChallengeTokens[token] > 0
}

func (a *ACMEHandler) addHTTP01Token(token string) {
	a.httpChallengeTokensLock.Lock()
	defer a.httpChallengeTokensLock.Unlock()
	if a.httpChallengeTokens == nil {
		a.httpChallengeTokens = map[string]int{}
	}
	a.httpChallengeTokens[token]++
}

func (a *ACMEHandler) removeHTTP01Token(token string) {
	a.httpChallengeTokensLock.Lock()
	defer a.httpChallengeTokensLock.Unlock()
	if a.httpChallengeTokens[token] <= 1 {
		delete(a.httpChallengeTokens, token)
		return
	}
	a.httpChallengeTokens[token]--
}

// http01TokenTracker wraps the lego HTTP-01 provider and records the tokens
// it presents (see IsPresentingHTTP01Token)
type http01TokenTracker struct {
	challenge.Provider
	handler *ACMEHandler
}

func (t *http01TokenTracker) Present(ctx context.Context, domain, token, keyAuth string) error {
	t.handler.addHTTP01Token(token)
	err := t.Provider.Present(ctx, domain, token, keyAuth)
	if err != nil {
		t.handler.removeHTTP01Token(token)
	}
	return err
}

func (t *http01TokenTracker) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	defer t.handler.removeHTTP01Token(token)
	return t.Provider.CleanUp(ctx, domain, token, keyAuth)
}

// contains checks if a string is present in a slice.
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// parseDomainList splits a comma separated domain list and normalizes each
// domain. Empty entries, e.g. from a trailing comma or an empty alias, are
// skipped
func parseDomainList(domainList string) ([]string, error) {
	domains := []string{}
	for _, d := range strings.Split(domainList, ",") {
		if strings.TrimSpace(d) == "" {
			continue
		}
		nd, err := netutils.NormalizeDomain(d)
		if err != nil {
			return nil, err
		}
		domains = append(domains, nd)
	}
	if len(domains) == 0 {
		return nil, errors.New("no valid domain given")
	}
	return domains, nil
}

// RequestUsesDNSChallenge returns whether the certificate request r uses the
// DNS-01 challenge: the dns parameter if it is given, otherwise the challenge
// type stored for the certificate. So the host editor, which does not send
// it, keeps a certificate that was obtained with DNS-01 on DNS-01, while an
// explicit choice (e.g. DNS-01 for a wildcard in the ACME tool) is used
// instead of the stored one
func RequestUsesDNSChallenge(r *http.Request) bool {
	if dnsPara, err := utils.PostPara(r, "dns"); err == nil && strings.TrimSpace(dnsPara) != "" {
		useDNS, _ := utils.PostBool(r, "dns")
		return useDNS
	}
	filename, err := utils.PostPara(r, "filename")
	if err != nil {
		return false
	}
	filename = strings.ReplaceAll(filename, "*", "_")
	certInfo, err := LoadCertInfoJSON(fmt.Sprintf("./conf/certs/%s.json", filename))
	if err != nil {
		return false
	}
	return certInfo.UseDNS
}

// HandleGetExpiredDomains handles the HTTP GET request to retrieve the list of expired domains.
// It calls the CheckCertificate method to obtain the expired domains and sends a JSON response
// containing the list of expired domains.
func (a *ACMEHandler) HandleGetExpiredDomains(w http.ResponseWriter, r *http.Request) {
	type ExpiredDomains struct {
		Domain []string `json:"domain"`
	}

	info := ExpiredDomains{
		Domain: a.CheckCertificate(),
	}

	js, _ := json.MarshalIndent(info, "", " ")
	utils.SendJSONResponse(w, string(js))
}

// HandleRenewCertificate handles the HTTP GET request to renew a certificate for the provided domains.
// It retrieves the domains and filename parameters from the request, calls the ObtainCert method
// to renew the certificate, and sends a JSON response indicating the result of the renewal process.
func (a *ACMEHandler) HandleRenewCertificate(w http.ResponseWriter, r *http.Request) {
	domainPara, err := utils.PostPara(r, "domains")

	// Clean each domain
	cleanedDomains := []string{}
	if domainPara != "" {
		var parseErr error
		cleanedDomains, parseErr = parseDomainList(domainPara)
		if parseErr != nil {
			utils.SendErrorResponse(w, jsonEscape(parseErr.Error()))
			return
		}
	}

	if err != nil {
		utils.SendErrorResponse(w, jsonEscape(err.Error()))
		return
	}

	filename, err := utils.PostPara(r, "filename")
	if err != nil {
		utils.SendErrorResponse(w, jsonEscape(err.Error()))
		return
	}
	// Make sure the wildcard * do not goes into the filename
	filename = strings.ReplaceAll(filename, "*", "_")

	email, err := utils.PostPara(r, "email")
	if err != nil {
		utils.SendErrorResponse(w, jsonEscape(err.Error()))
		return
	}

	var caUrl string

	ca, err := utils.PostPara(r, "ca")
	if err != nil {
		a.Logf("CA not set. Using default", nil)
		ca, caUrl = "", ""
	}

	if ca == "custom" {
		caUrl, err = utils.PostPara(r, "caURL")
		if err != nil {
			a.Logf("Custom CA set but no URL provide, Using default", nil)
			ca, caUrl = "", ""
		}
	}

	if ca == "" {
		// default. Use Let's Encrypt
		ca = "Let's Encrypt"
	}

	skipTLS, _ := utils.PostBool(r, "skipTLS")
	dns := RequestUsesDNSChallenge(r)

	// Default propagation timeout is 600 seconds (10 minutes)
	propagationTimeout := 600
	if dns {
		ppgTimeout, err := utils.PostPara(r, "ppgTimeout")
		if err == nil {
			propagationTimeout, err = strconv.Atoi(ppgTimeout)
			if err != nil {
				utils.SendErrorResponse(w, "Invalid propagation timeout value")
				return
			}
			if propagationTimeout < 60 {
				// Minimum propagation timeout is 60 seconds
				propagationTimeout = 60
			}
		}
	}

	// The certificate gets exactly the requested domains. The SANs of the
	// existing certificate are not added back: the certificate list sends
	// them itself when renewing, and adding them made a removed alias come
	// back on every request, failing it once its DNS moved away

	// Extract DNS servers from the request
	var dnsServers []string
	dnsServersPara, err := utils.PostPara(r, "dnsServers")
	if err == nil && dnsServersPara != "" {
		dnsServers = strings.Split(dnsServersPara, ",")
		for i := range dnsServers {
			dnsServers[i] = strings.TrimSpace(dnsServers[i])
		}
	}

	// Convert DNS servers slice to a single string
	dnsServersString := strings.Join(dnsServers, ",")

	// PostBool returns false if the key is missing or not a valid bool
	disableRecursiveNssCheck, _ := utils.PostBool(r, "disable_recursive_nss_check")
	disableAuthoritativeNssCheck, _ := utils.PostBool(r, "disable_authoritative_nss_check")

	result, err := a.ObtainCert(cleanedDomains, filename, email, ca, caUrl, skipTLS, dns, propagationTimeout, dnsServersString, disableRecursiveNssCheck, disableAuthoritativeNssCheck)
	if err != nil {
		utils.SendErrorResponse(w, jsonEscape(err.Error()))
		return
	}
	utils.SendJSONResponse(w, strconv.FormatBool(result))
}

// Escape JSON string
func jsonEscape(i string) string {
	b, err := json.Marshal(i)
	if err != nil {
		// log.Println("Unable to escape json data: " + err.Error())
		return i
	}
	s := string(b)
	return s[1 : len(s)-1]
}

// Helper function to check if a port is in use
func IsPortInUse(port int) bool {
	address := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return true // Port is in use
	}
	defer listener.Close()
	return false // Port is not in use
}

// Load cert information from json file
func LoadCertInfoJSON(filename string) (*CertificateInfoJSON, error) {
	certInfoBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	certInfo := &CertificateInfoJSON{}
	if err = json.Unmarshal(certInfoBytes, certInfo); err != nil {
		return nil, err
	}

	// Clean DNS servers
	for i := range certInfo.DNSServers {
		certInfo.DNSServers[i] = strings.TrimSpace(certInfo.DNSServers[i])
	}

	return certInfo, nil
}
