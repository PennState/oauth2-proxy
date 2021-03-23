package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// AzureProvider represents an Azure based Identity Provider
type AzureProvider struct {
	*ProviderData
	Tenant string
}

// azureUserProfile represents data returned from the /me graph api
type azureUserProfile struct {
	BusinessPhones    []string `json:"businessPhones"`
	DisplayName       string   `json:"displayName"`
	GivenName         string   `json:"givenName"`
	ID                string   `json:"id"`
	JobTitle          string   `json:"jobTitle"`
	Mail              string   `json:"mail"`
	MobilePhone       string   `json:"mobilePhone"`
	OfficeLocation    string   `json:"officeLocation"`
	PreferredLanguage string   `json:"preferredLanguage"`
	Surname           string   `json:"surname"`
	UserPrincipalName string   `json:"userPrincipalName"`
}

var _ Provider = (*AzureProvider)(nil)

const (
	azureProviderName = "Azure"
	azureDefaultScope = "openid"
	azureUserClaim    = "upn"
)

var (
	// Default Login URL for Azure.
	// Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/authorize.
	azureDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   "/common/oauth2/authorize",
	}

	// Default Redeem URL for Azure.
	// Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/token.
	azureDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   "/common/oauth2/token",
	}

	// Default Profile URL for Azure.
	// Pre-parsed URL of https://graph.microsoft.com/v1.0/me.
	azureDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "graph.microsoft.com",
		Path:   "/v1.0/me",
	}

	// Default ProtectedResource URL for Azure.
	// Pre-parsed URL of https://graph.microsoft.com.
	azureDefaultProtectResourceURL = &url.URL{
		Scheme: "https",
		Host:   "graph.microsoft.com",
	}
)

// NewAzureProvider initiates a new AzureProvider
func NewAzureProvider(p *ProviderData) *AzureProvider {
	p.setProviderDefaults(providerDefaults{
		name:        azureProviderName,
		loginURL:    azureDefaultLoginURL,
		redeemURL:   azureDefaultRedeemURL,
		profileURL:  azureDefaultProfileURL,
		validateURL: nil,
		scope:       azureDefaultScope,
	})

	if p.ProtectedResource == nil || p.ProtectedResource.String() == "" {
		p.ProtectedResource = azureDefaultProtectResourceURL
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}

	return &AzureProvider{
		ProviderData: p,
		Tenant:       "common",
	}
}

// Configure defaults the AzureProvider configuration options
func (p *AzureProvider) Configure(tenant string) {
	if tenant == "" || tenant == "common" {
		// tenant is empty or default, remain on the default "common" tenant
		return
	}

	// Specific tennant specified, override the Login and RedeemURLs
	p.Tenant = tenant
	overrideTenantURL(p.LoginURL, azureDefaultLoginURL, tenant, "authorize")
	overrideTenantURL(p.RedeemURL, azureDefaultRedeemURL, tenant, "token")
}

func overrideTenantURL(current, defaultURL *url.URL, tenant, path string) {
	if current == nil || current.String() == "" || current.String() == defaultURL.String() {
		*current = url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + tenant + "/oauth2/" + path}
	}
}

// GetLoginURL returns a login url with state
func (p *AzureProvider) GetLoginURL(redirectURI, state string) string {
	extraParams := url.Values{}
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		extraParams.Add("resource", p.ProtectedResource.String())
	}
	a := makeLoginURL(p.ProviderData, redirectURI, state, extraParams)
	return a.String()
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *AzureProvider) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
	params, err := p.prepareRedeem(redirectURL, code)
	if err != nil {
		return nil, err
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_on,string"`
		IDToken      string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	created := time.Now()
	expires := time.Unix(jsonResponse.ExpiresOn, 0)

	session := &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		IDToken:      jsonResponse.IDToken,
		CreatedAt:    &created,
		ExpiresOn:    &expires,
		RefreshToken: jsonResponse.RefreshToken,
	}

	err = p.populateSessionFromToken(ctx, session)
	if err != nil {
		logger.Errorf("error populating session from tokens: %s", err)
	}

	return session, nil
}

func (p *AzureProvider) populateSessionFromToken(ctx context.Context, session *sessions.SessionState) error {
	// https://github.com/oauth2-proxy/oauth2-proxy/pull/914#issuecomment-782285814
	// https://github.com/AzureAD/azure-activedirectory-library-for-java/issues/117
	// due to above issues, id_token may not be signed by AAD
	// in that case, we will fallback to access token
	for n, token := range map[string]string{"IDToken": session.IDToken, "AccessToken": session.AccessToken} {
		if session.User == "" || session.Email == "" {
			claims, err := p.verifyTokenAndExtractClaims(ctx, token)
			if err != nil {
				return fmt.Errorf("unable to get claims from %s: %v", n, err)
			}

			if session.Email == "" {
				// otherwise fall back to email claim
				if claims.Email != "" {
					session.Email = claims.Email
				}
			}

			if session.User == "" {
				// set User from azureUserClaim, or from Email if it's set
				if claims.raw[azureUserClaim] != "" {
					session.User = fmt.Sprint(claims.raw[azureUserClaim])
				} else if session.Email != "" {
					session.User = session.Email
				}
			}

			for _, c := range p.ExtraClaims {
				logger.Printf("Checking for extra claim %s", c)
				if v, ok := claims.raw[c].(string); ok {
					logger.Printf("Found extra claim, storing in session %s = %s", c, v)
					session.ExtraClaims[c] = v
				}
			}
		}
	}

	return nil
}

// EnrichSession finds the email and UPN to enrich the session state if they are not already set
func (p *AzureProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// skip if Email and User are already set
	if s.Email != "" && s.User != "" {
		return nil
	}

	user, err := p.getUserFromProfileAPI(ctx, s.AccessToken)
	if err != nil {
		return fmt.Errorf("unable to get user profile from api: %v", err)
	}

	if user.Mail != "" {
		s.Email = user.Mail
	}

	if user.UserPrincipalName != "" {
		s.User = user.UserPrincipalName
	}

	return nil
}

func (p *AzureProvider) prepareRedeem(redirectURL, code string) (url.Values, error) {
	params := url.Values{}
	if code == "" {
		return params, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return params, err
	}

	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}
	return params, nil
}

// verifyTokenAndExtractEmail tries to extract email claim from either id_token or access token
// when oidc verifier is configured
func (p *AzureProvider) verifyTokenAndExtractClaims(ctx context.Context, token string) (*OIDCClaims, error) {
	claims := &OIDCClaims{}

	if token != "" && p.Verifier != nil {
		token, err := p.Verifier.Verify(ctx, token)
		// due to issues mentioned above, id_token may not be signed by AAD
		if err != nil {
			return nil, fmt.Errorf("unable to verify token: %v", err)
		}

		claims, err = p.getClaims(token)
		if err != nil {
			return nil, fmt.Errorf("unable to get claims from token: %v", err)
		}
	}

	return claims, nil
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *AzureProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	logger.Printf("refreshed id token %s (expired on %s)\n", s, origExpiration)
	return true, nil
}

func (p *AzureProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) (err error) {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_on,string"`
		IDToken      string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)

	if err != nil {
		return
	}

	now := time.Now()
	expires := time.Unix(jsonResponse.ExpiresOn, 0)
	s.AccessToken = jsonResponse.AccessToken
	s.IDToken = jsonResponse.IDToken
	s.RefreshToken = jsonResponse.RefreshToken
	s.CreatedAt = &now
	s.ExpiresOn = &expires

	err = p.populateSessionFromToken(ctx, s)
	if err != nil {
		logger.Errorf("error populating session from tokens: %s", err)
	}

	return
}

func makeAzureHeader(accessToken string) http.Header {
	return makeAuthorizationHeader(tokenTypeBearer, accessToken, nil)
}

func (p *AzureProvider) getUserFromProfileAPI(ctx context.Context, accessToken string) (azureUserProfile, error) {
	if accessToken == "" {
		return azureUserProfile{}, errors.New("missing access token")
	}

	user := azureUserProfile{}
	err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeAzureHeader(accessToken)).
		Do().
		UnmarshalInto(&user)
	if err != nil {
		return azureUserProfile{}, err
	}

	return user, nil
}

// ValidateSession validates the AccessToken
func (p *AzureProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeAzureHeader(s.AccessToken))
}
