// Package policy evaluates per-route access rules loaded from YAML.
//
// Routes are checked in file order and the first match wins. A request that
// matches no route gets the file's default decision, which is deny unless
// stated otherwise.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// File is the on-disk policy document.
type File struct {
	// Default applies when no route matches: "deny" (default) or
	// "authenticated".
	Default string  `yaml:"default"`
	Routes  []Route `yaml:"routes"`
}

// Route pairs a matcher with requirements.
type Route struct {
	Name           string      `yaml:"name"`
	Match          Match       `yaml:"match"`
	AllowAnonymous bool        `yaml:"allow_anonymous"`
	Require        Requirement `yaml:"require"`
}

// Match selects requests. Every non-empty field must match.
type Match struct {
	// Hosts are exact host names or "*.example.com" wildcards.
	Hosts []string `yaml:"hosts"`
	// Paths are exact paths, or prefixes when they end in "*".
	Paths     []string `yaml:"paths"`
	PathRegex string   `yaml:"path_regex"`
	Methods   []string `yaml:"methods"`
}

// Requirement lists what an authenticated identity must satisfy.
type Requirement struct {
	// GroupsAny passes when the user is in at least one of the groups.
	GroupsAny []string `yaml:"groups_any"`
	// GroupsAll passes when the user is in every group.
	GroupsAll []string `yaml:"groups_all"`
	// Claims maps a claim name to the accepted values. A scalar claim must
	// equal one of them; a list claim must contain one of them.
	Claims map[string]Values `yaml:"claims"`
	// EmailDomains restricts access to verified emails in these domains.
	EmailDomains []string `yaml:"email_domains"`
	// StepUp requires a passkey verification within StepUpMaxAge.
	StepUp       bool          `yaml:"step_up"`
	StepUpMaxAge time.Duration `yaml:"step_up_max_age"`
}

// Values is one or more accepted claim values. It accepts a YAML scalar or
// sequence.
type Values []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (v *Values) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*v = Values{n.Value}
		return nil
	case yaml.SequenceNode:
		out := make(Values, 0, len(n.Content))
		for _, c := range n.Content {
			if c.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: claim values must be scalars", c.Line)
			}
			out = append(out, c.Value)
		}
		*v = out
		return nil
	default:
		return fmt.Errorf("line %d: claim value must be a scalar or a list", n.Line)
	}
}

// Identity is what the policy engine knows about the caller.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Groups        []string
	Claims        map[string]any
	// StepUpAt is when the user last verified a passkey; zero if never.
	StepUpAt time.Time
}

// Outcome is the result of evaluating a request.
type Outcome int

const (
	// Allow forwards the request.
	Allow Outcome = iota
	// Login means the request needs an authenticated session.
	Login
	// StepUp means the session is valid but needs a fresh passkey check.
	StepUp
	// Deny rejects the request.
	Deny
)

func (o Outcome) String() string {
	switch o {
	case Allow:
		return "allow"
	case Login:
		return "login"
	case StepUp:
		return "step_up"
	default:
		return "deny"
	}
}

// Decision explains an Outcome.
type Decision struct {
	Outcome Outcome
	Route   string
	Reason  string
	// Anonymous is true when the matched route allows unauthenticated access.
	Anonymous bool
}

// Engine is a compiled, immutable policy.
type Engine struct {
	defaultAuth bool
	routes      []compiled
}

type compiled struct {
	Route
	exactPaths []string
	prefixes   []string
	re         *regexp.Regexp
	methods    []string
}

// DefaultStepUpMaxAge applies when a route sets step_up without a max age.
const DefaultStepUpMaxAge = 15 * time.Minute

// Load reads and compiles a policy file.
func Load(path string) (*Engine, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return Parse(b)
}

// Parse compiles a policy document. Unknown fields are rejected so typos do
// not silently weaken a rule.
func Parse(b []byte) (*Engine, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return Compile(f)
}

// Compile validates and compiles a File.
func Compile(f File) (*Engine, error) {
	e := &Engine{}
	switch f.Default {
	case "", "deny":
	case "authenticated":
		e.defaultAuth = true
	default:
		return nil, fmt.Errorf("policy: default must be deny or authenticated, got %q", f.Default)
	}

	var errs []error
	seen := map[string]bool{}
	for i, r := range f.Routes {
		if r.Name == "" {
			r.Name = fmt.Sprintf("route[%d]", i)
		}
		if seen[r.Name] {
			errs = append(errs, fmt.Errorf("route %q: duplicate name", r.Name))
		}
		seen[r.Name] = true
		c, err := compile(r)
		if err != nil {
			errs = append(errs, fmt.Errorf("route %q: %w", r.Name, err))
			continue
		}
		e.routes = append(e.routes, c)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return e, nil
}

func compile(r Route) (compiled, error) {
	c := compiled{Route: r}
	if r.AllowAnonymous && !r.Require.empty() {
		return c, errors.New("allow_anonymous cannot be combined with require")
	}
	if r.Require.StepUp && r.Require.StepUpMaxAge == 0 {
		c.Require.StepUpMaxAge = DefaultStepUpMaxAge
	}
	if r.Require.StepUpMaxAge < 0 {
		return c, errors.New("step_up_max_age must not be negative")
	}
	for _, p := range r.Match.Paths {
		if !strings.HasPrefix(p, "/") {
			return c, fmt.Errorf("path %q must start with /", p)
		}
		if strings.HasSuffix(p, "*") {
			c.prefixes = append(c.prefixes, strings.TrimSuffix(p, "*"))
		} else {
			c.exactPaths = append(c.exactPaths, p)
		}
	}
	if r.Match.PathRegex != "" {
		re, err := regexp.Compile(r.Match.PathRegex)
		if err != nil {
			return c, fmt.Errorf("path_regex: %w", err)
		}
		c.re = re
	}
	for _, m := range r.Match.Methods {
		c.methods = append(c.methods, strings.ToUpper(m))
	}
	for _, h := range r.Match.Hosts {
		if strings.Contains(h, "*") && !strings.HasPrefix(h, "*.") {
			return c, fmt.Errorf("host %q: only a leading *. wildcard is supported", h)
		}
	}
	return c, nil
}

func (r Requirement) empty() bool {
	return len(r.GroupsAny) == 0 && len(r.GroupsAll) == 0 && len(r.Claims) == 0 &&
		len(r.EmailDomains) == 0 && !r.StepUp
}

// Routes returns the number of compiled routes.
func (e *Engine) Routes() int { return len(e.routes) }

// Evaluate decides what to do with r for the given identity, which is nil
// for unauthenticated requests.
func (e *Engine) Evaluate(r *http.Request, id *Identity, now time.Time) Decision {
	host := hostOnly(r.Host)
	for i := range e.routes {
		c := &e.routes[i]
		if !c.matches(host, r.URL.Path, r.Method) {
			continue
		}
		if c.AllowAnonymous {
			return Decision{Outcome: Allow, Route: c.Name, Reason: "anonymous route", Anonymous: true}
		}
		return c.authorize(id, now)
	}
	if e.defaultAuth {
		if id == nil {
			return Decision{Outcome: Login, Route: "default", Reason: "no session"}
		}
		return Decision{Outcome: Allow, Route: "default", Reason: "authenticated"}
	}
	return Decision{Outcome: Deny, Route: "default", Reason: "no matching route"}
}

func (c *compiled) matches(host, path, method string) bool {
	if len(c.Match.Hosts) > 0 && !slices.ContainsFunc(c.Match.Hosts, func(h string) bool { return hostMatch(h, host) }) {
		return false
	}
	if len(c.methods) > 0 && !slices.Contains(c.methods, method) {
		return false
	}
	if len(c.exactPaths) > 0 || len(c.prefixes) > 0 {
		ok := slices.Contains(c.exactPaths, path) ||
			slices.ContainsFunc(c.prefixes, func(p string) bool { return strings.HasPrefix(path, p) })
		if !ok {
			return false
		}
	}
	if c.re != nil && !c.re.MatchString(path) {
		return false
	}
	return true
}

func (c *compiled) authorize(id *Identity, now time.Time) Decision {
	d := Decision{Route: c.Name}
	if id == nil {
		d.Outcome, d.Reason = Login, "no session"
		return d
	}
	req := c.Require
	if len(req.GroupsAny) > 0 && !slices.ContainsFunc(req.GroupsAny, func(g string) bool { return slices.Contains(id.Groups, g) }) {
		d.Outcome, d.Reason = Deny, "not in any required group"
		return d
	}
	for _, g := range req.GroupsAll {
		if !slices.Contains(id.Groups, g) {
			d.Outcome, d.Reason = Deny, "missing group "+g
			return d
		}
	}
	for name, accepted := range req.Claims {
		if !claimMatches(id.Claims[name], accepted) {
			d.Outcome, d.Reason = Deny, "claim "+name+" not satisfied"
			return d
		}
	}
	if len(req.EmailDomains) > 0 {
		at := strings.LastIndexByte(id.Email, '@')
		if !id.EmailVerified || at < 0 || !slices.Contains(req.EmailDomains, strings.ToLower(id.Email[at+1:])) {
			d.Outcome, d.Reason = Deny, "email domain not allowed"
			return d
		}
	}
	if req.StepUp && (id.StepUpAt.IsZero() || now.Sub(id.StepUpAt) > req.StepUpMaxAge) {
		d.Outcome, d.Reason = StepUp, "passkey verification required"
		return d
	}
	d.Outcome, d.Reason = Allow, "requirements met"
	return d
}

func claimMatches(v any, accepted Values) bool {
	switch x := v.(type) {
	case nil:
		return false
	case []any:
		return slices.ContainsFunc(x, func(e any) bool { return claimMatches(e, accepted) })
	case []string:
		return slices.ContainsFunc(x, func(e string) bool { return slices.Contains(accepted, e) })
	case string:
		return slices.Contains(accepted, x)
	default:
		return slices.Contains(accepted, fmt.Sprint(x))
	}
}

func hostMatch(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	if suffix, ok := strings.CutPrefix(pattern, "*"); ok {
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return pattern == host
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(h)
}
