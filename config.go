package main

const (
	AlbyBackendType   = "ALBY"
	LNDBackendType    = "LND"
	StrikeBackendType = "STRIKE"
	CookieName        = "alby_nwc_session"
)

type Config struct {
	NostrSecretKey          string `envconfig:"NOSTR_PRIVKEY"`
	CookieSecret            string `envconfig:"COOKIE_SECRET" required:"true"`
	CookieDomain            string `envconfig:"COOKIE_DOMAIN"`
	ClientPubkey            string `envconfig:"CLIENT_NOSTR_PUBKEY"`
	Relay                   string `envconfig:"RELAY" default:"wss://relay.getalby.com/v1"`
	PublicRelay             string `envconfig:"PUBLIC_RELAY"`
	LNBackendType           string `envconfig:"LN_BACKEND_TYPE" default:"ALBY"`
	LNDAddress              string `envconfig:"LND_ADDRESS"`
	LNDCertFile             string `envconfig:"LND_CERT_FILE"`
	LNDMacaroonFile         string `envconfig:"LND_MACAROON_FILE"`
	ClientId                string `envconfig:"CLIENT_ID"`
	ClientSecret            string `envconfig:"CLIENT_SECRET"`
	OAuthAPIURL             string `envconfig:"OAUTH_API_URL"`
	OAuthRedirectUrl        string `envconfig:"OAUTH_REDIRECT_URL"`
	OAuthAuthUrl            string `envconfig:"OAUTH_AUTH_URL"`
	OAuthTokenUrl           string `envconfig:"OAUTH_TOKEN_URL"`
	Port                    string `envconfig:"PORT" default:"8080"`
	DatabaseUri             string `envconfig:"DATABASE_URI" default:"nostr-wallet-connect.db"`
	DatabaseMaxConns        int    `envconfig:"DATABASE_MAX_CONNS" default:"10"`
	DatabaseMaxIdleConns    int    `envconfig:"DATABASE_MAX_IDLE_CONNS" default:"5"`
	DatabaseConnMaxLifetime int    `envconfig:"DATABASE_CONN_MAX_LIFETIME" default:"1800"` // 30 minutes
	IdentityPubkey          string
}
