package gssapi

// ClientConfig holds the client configuration for GSSAPI.
type ClientConfig struct {
	// Authz is the authorization identity to use.
	Authz string
	// Username is the name of the user. If this is left blank,
	// the user in the default TGT will be used.
	Username string
	// Password is the password of the user. If this is left blank,
	// then there must be a default TGT.
	Password string
	// ServiceName is the name of the service to connect to.
	ServiceName string
	// ServiceFQDN is the FQDN of the service to connect to.
	ServiceFQDN string
	// Delegate indicates whether or not the client's credentials
	// should be delegated to the server.
	Delegate bool
}

// ServerConfig holds the server configuration for GSSAPI.
type ServerConfig struct {
	// ServiceName is the name of the service. If this is left
	// blank, then the default TGT will be used.
	ServiceName string
	// ServiceFQDN is the FQDN of the service. If this is left
	// blank, then the default TGT will be used.
	ServiceFQDN string
}
