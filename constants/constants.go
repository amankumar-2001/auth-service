package constants

// Header keys extracted by middleware into the request context.
const (
	HeaderAuthorization = "Authorization"
	HeaderRequestID     = "X-Request-Id"
	HeaderDeviceID      = "X-Device-Id"
	HeaderUserAgent     = "User-Agent"
	HeaderForwardedFor  = "X-Forwarded-For"
	HeaderRealIP        = "X-Real-Ip"
	// HeaderInternalKey carries the shared secret for service-to-service calls to
	// the /v1/internal routes (e.g. expense-service's WhatsApp worker).
	HeaderInternalKey = "X-Internal-Key"
)

// Context keys for values stored by middleware. Using a dedicated type avoids
// collisions with other packages writing to the same context.
type ContextKey string

const (
	CtxRequestID ContextKey = "requestID"
	CtxDeviceID  ContextKey = "deviceID"
	CtxIPAddress ContextKey = "ipAddress"
	CtxUserAgent ContextKey = "userAgent"
	CtxUserID    ContextKey = "userID"
	CtxRoles     ContextKey = "roles"
	CtxSessionID ContextKey = "sessionID"
	CtxVerified  ContextKey = "verified"
)

// BearerPrefix is the scheme prefix on the Authorization header.
const BearerPrefix = "Bearer "

// Provider identifies how an account was created.
const (
	ProviderLocal  = "local"
	ProviderGoogle = "google"
	ProviderApple  = "apple"
)

// Default seeded RBAC roles.
const (
	RoleAdmin   = "admin"
	RoleSupport = "support"
	RoleUser    = "user"
)
