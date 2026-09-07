package opcore

import (
	"fmt"
	"math"
	"net/http"
	"strings"

	"forgejo.coilysiren.me/coilyco-flight-deck/umbra/http/guardfile"
	"forgejo.coilysiren.me/coilyco-flight-deck/umbra/http/respfmt"
	kdl "github.com/calico32/kdl-go"
)

// ParseInline states the ward-mcp inline grammar as the same []Descriptor the
// OpenAPI source feeds, plus the request RuntimeConfig. See docs/opcore-inline.md.
func ParseInline(src []byte) ([]Descriptor, RuntimeConfig, error) {
	descs, cfg, _, err := ParseInlineWithWarnings(src)
	return descs, cfg, err
}

// ParseInlineWithWarnings is [ParseInline] plus the non-fatal notes a caller
// should surface, one per grant whose method was inferred rather than known.
func ParseInlineWithWarnings(src []byte) ([]Descriptor, RuntimeConfig, []string, error) {
	// Accept the inline body grammar's boolean shorthand (`required=true`,
	// `raw=true`) even though KDL itself spells booleans as `#true`.
	doc, err := kdl.ParseString(normalizeInlineBooleans(string(src)))
	if err != nil {
		return nil, RuntimeConfig{}, nil, fmt.Errorf("opcore: parse KDL: %w", err)
	}
	wrap := doc.GetNode("wrap")
	if wrap == nil {
		return nil, RuntimeConfig{}, nil, fmt.Errorf("opcore: missing top-level `wrap` node")
	}
	p := &inlineParser{}
	for _, a := range wrap.Arguments() {
		p.group = append(p.group, a.String())
	}
	if len(p.group) == 0 {
		return nil, RuntimeConfig{}, nil, fmt.Errorf("opcore: `wrap` needs a command path, e.g. `wrap ward mcp forgejo`")
	}
	for _, n := range wrap.Children().Nodes {
		if aerr := p.applyNode(n); aerr != nil {
			return nil, RuntimeConfig{}, nil, aerr
		}
	}
	if verr := p.validate(); verr != nil {
		return nil, RuntimeConfig{}, nil, verr
	}
	return p.descs, p.cfg, p.warnings, nil
}

// normalizeInlineBooleans keeps the added body grammar readable in KDL source
// while still feeding kdl-go the boolean literal form it accepts.
func normalizeInlineBooleans(src string) string {
	repl := strings.NewReplacer(
		"required=true", "required=#true",
		"required=false", "required=#false",
		"raw=true", "raw=#true",
		"raw=false", "raw=#false",
	)
	return repl.Replace(src)
}

// inlineParser accumulates the wrap header, the RuntimeConfig, and the stated
// descriptors as it walks the wrap body.
type inlineParser struct {
	group    []string
	cfg      RuntimeConfig
	descs    []Descriptor
	warnings []string
}

// applyNode dispatches one child of the wrap block, failing closed on anything
// outside the frozen grammar.
func (p *inlineParser) applyNode(n *kdl.Node) error {
	switch n.Name() {
	case "base-url":
		return p.parseBaseURL(n)
	case "auth":
		a, err := guardfile.ParseAuthNode(n)
		if err != nil {
			return err
		}
		p.cfg.Auth = a
		return nil
	case "header":
		return p.parseHeader(n)
	case "database":
		return p.parseDatabase(n)
	case "can":
		return p.parseGrant(n)
	case "proxy":
		return p.parseProxy(n)
	default:
		return p.applyGateNode(n)
	}
}

// applyGateNode handles the wrap-body nodes that shape the gates, split off
// from applyNode to hold the cyclo cap.
func (p *inlineParser) applyGateNode(n *kdl.Node) error {
	switch n.Name() {
	case "restrict":
		r, err := guardfile.ParseRestrictNode(n)
		if err != nil {
			return err
		}
		p.cfg.Restrict = append(p.cfg.Restrict, r)
		return nil
	case "allow-metacharacters":
		params, err := guardfile.ParseAllowMetaNode(n)
		if err != nil {
			return err
		}
		p.cfg.AllowMeta = append(p.cfg.AllowMeta, params...)
		return nil
	default:
		return fmt.Errorf("opcore: unknown node %q in wrap body (want base-url | auth | header | database | restrict | allow-metacharacters | can | proxy; fail-closed)", n.Name())
	}
}

// reservedHeaders name headers the wrap grammar refuses. `auth` owns the first
// and the runtime sets the second; see docs/specverb-request.md.
var reservedHeaders = map[string]string{
	"authorization": "`auth` owns it, and a second path to it would be an unreviewed credential surface",
	"content-type":  "the runtime sets it from the request body, so a declared one would be overwritten",
}

// parseHeader states one wrap-level request header, applied to every leaf.
func (p *inlineParser) parseHeader(n *kdl.Node) error {
	args := n.Arguments()
	if len(args) != 2 {
		return fmt.Errorf("opcore: `header` needs a name and a value, e.g. `header \"User-Agent\" \"app/1.0\"` (got %d arg(s))", len(args))
	}
	name, value := args[0].String(), args[1].String()
	if name == "" || value == "" {
		return fmt.Errorf("opcore: `header` needs a non-empty name and value")
	}
	if why, bad := reservedHeaders[strings.ToLower(name)]; bad {
		return fmt.Errorf("opcore: `header %q` is refused: %s (fail-closed)", name, why)
	}
	if p.cfg.Headers == nil {
		p.cfg.Headers = map[string]string{}
	}
	if _, dup := p.cfg.Headers[http.CanonicalHeaderKey(name)]; dup {
		return fmt.Errorf("opcore: duplicate `header %q` (fail-closed)", name)
	}
	p.cfg.Headers[http.CanonicalHeaderKey(name)] = value
	return nil
}

// parseBaseURL assigns only the form this node carried, so a second base-url in
// the other form accumulates into both fields and validate catches the conflict.
func (p *inlineParser) parseBaseURL(n *kdl.Node) error {
	raw, chain, err := guardfile.ParseBaseURL(n)
	if err != nil {
		return err
	}
	if raw != "" {
		p.cfg.BaseURL = raw
	}
	if !chain.IsZero() {
		p.cfg.BaseURLValue = chain
	}
	return nil
}

// validate enforces the cross-node invariants after every wrap child is applied.
func (p *inlineParser) validate() error {
	// `auth` authenticates an HTTP upstream, so a wrap serving only `sql`
	// grants has nothing to authenticate: the DSN carries the credential.
	if p.cfg.Auth.Scheme == "" && !p.everyGrantIsSQL() {
		return fmt.Errorf("opcore: `auth` block is required")
	}
	if p.needsDatabase() && p.cfg.Database.IsZero() {
		return fmt.Errorf("opcore: a `sql` grant needs a wrap-level `database <driver> { value ... }` (fail-closed)")
	}
	if p.cfg.BaseURL != "" && !p.cfg.BaseURLValue.IsZero() {
		return fmt.Errorf("opcore: base-url set both as a string and a `{ value }` block; pick one")
	}
	if len(p.descs) == 0 {
		return fmt.Errorf("opcore: no `can` or `proxy` operations (nothing to mount)")
	}
	return nil
}

// everyGrantIsSQL reports whether nothing in this wrap reaches an HTTP upstream.
func (p *inlineParser) everyGrantIsSQL() bool {
	for _, d := range p.descs {
		if d.SQL == nil {
			return false
		}
	}
	return len(p.descs) > 0
}

// needsDatabase reports whether any grant reaches a database.
func (p *inlineParser) needsDatabase() bool {
	for _, d := range p.descs {
		if d.SQL != nil {
			return true
		}
	}
	return false
}

// parseGrant states one `can <verb> <resource> { ... }` operation as a Descriptor:
// method from the verb, path params from the `{template}`, children to the shape.
func (p *inlineParser) parseGrant(n *kdl.Node) error {
	args := n.Arguments()
	if len(args) != 2 {
		return fmt.Errorf("opcore: `can` needs a verb and a resource, e.g. `can create issue { ... }` (got %d arg(s))", len(args))
	}
	verb, resource := args[0].String(), args[1].String()
	if verb == "" || resource == "" {
		return fmt.Errorf("opcore: `can` needs a non-empty verb and resource")
	}
	method, known := MethodForVerb(verb)
	d := Descriptor{
		VerbName:       strings.Join(p.group, ".") + "." + resource + "." + verb,
		Group:          resource,
		Leaf:           verb,
		Method:         method,
		MethodInferred: !known,
		Destructive:    DestructiveVerb(verb),
		Grant:          "can " + verb + " " + resource,
	}
	if err := checkOnceOnlyChildren(n, verb, resource); err != nil {
		return err
	}
	for _, c := range n.Children().Nodes {
		if err := applyInlineGrantChild(&d, c); err != nil {
			return fmt.Errorf("opcore: can %s %s: %w", verb, resource, err)
		}
	}
	if err := shapeGrant(&d, verb, resource); err != nil {
		return err
	}
	if err := validateGrant(d, verb, resource); err != nil {
		return err
	}
	if d.MethodInferred {
		p.warnings = append(p.warnings, inferredMethodWarning(d, verb, resource))
	}
	p.descs = append(p.descs, d)
	return nil
}

// shapeGrant settles the request shape once every child is applied: a sql
// grant has no URL to template, and a pin is checked against any mapping.
func shapeGrant(d *Descriptor, verb, resource string) error {
	if d.SQL != nil {
		d.Method, d.MethodInferred = "", false
	} else if d.Path == "" {
		return fmt.Errorf("opcore: can %s %s: `path \"...\"` is required (the request path template)", verb, resource)
	}
	d.PathParams = PathParamsInOrder(d.Path)
	if len(d.FixedBody) > 0 {
		if err := validateFixedBodyMappings(d.FixedBody, d.BodyMappings); err != nil {
			return fmt.Errorf("opcore: can %s %s: %w", verb, resource, err)
		}
	}
	return nil
}

// parseProxy states one `proxy <tool> { upstream <server> <tool>; ... }` grant.
// The runtime uses the upstream mapping to fetch the tool schema and forward the call.
func (p *inlineParser) parseProxy(n *kdl.Node) error {
	name, err := singleInlineArg(n, "proxy")
	if err != nil {
		return fmt.Errorf("opcore: proxy: %w (name it `proxy browser_snapshot { ... }`)", err)
	}
	if name == "" {
		return fmt.Errorf("opcore: proxy needs a non-empty tool name")
	}
	d := Descriptor{
		VerbName: strings.Join(p.group, ".") + ".proxy." + name,
		Group:    "mcp",
		Leaf:     name,
		Grant:    "proxy " + name,
		Proxy:    &Proxy{Name: name},
	}
	for _, c := range n.Children().Nodes {
		if err := applyProxyChild(&d, c); err != nil {
			return fmt.Errorf("opcore: proxy %s: %w", name, err)
		}
	}
	if d.Proxy.Upstream.Server == "" || d.Proxy.Upstream.Tool == "" {
		return fmt.Errorf("opcore: proxy %s: `upstream <server> <tool>` is required", name)
	}
	p.descs = append(p.descs, d)
	return nil
}

// applyInlineGrantChild dispatches one child of a `can` body onto d, failing
// closed outside the grammar in docs/opcore-inline.md.
func applyInlineGrantChild(d *Descriptor, c *kdl.Node) error {
	switch c.Name() {
	case "path":
		if d.Path != "" {
			return fmt.Errorf("duplicate `path` (fail-closed)")
		}
		v, err := singleInlineArg(c, "path")
		if err != nil {
			return err
		}
		d.Path = v
	case "query":
		fields, exclusive, err := inlineQueryFields(c)
		if err != nil {
			return err
		}
		d.QueryFlags = append(d.QueryFlags, fields...)
		d.QueryExclusive = append(d.QueryExclusive, exclusive...)
	case "body":
		return applyInlineBody(d, c)
	case "method":
		return applyInlineMethod(d, c)
	case "raw-response":
		return applyInlineRawResponse(d, c)
	case "graphql":
		return applyInlineGraphQL(d, c)
	case "sql":
		return applyInlineSQL(d, c)
	default:
		return applyInlineGrantControlChild(d, c)
	}
	return nil
}

// parseDatabase states the wrap's database: a registered database/sql driver
// name plus the chain its DSN resolves through. umbra imports no driver.
func (p *inlineParser) parseDatabase(n *kdl.Node) error {
	if !p.cfg.Database.IsZero() {
		return fmt.Errorf("opcore: duplicate `database` (fail-closed)")
	}
	driver, err := singleInlineArg(n, "database")
	if err != nil {
		return fmt.Errorf("opcore: `database` needs a driver name, e.g. `database pgx { value env \"DATABASE_URL\" }`: %w", err)
	}
	chain, err := guardfile.ParseValueBlock(n, "database")
	if err != nil {
		return err
	}
	p.cfg.Database = Database{Driver: driver, DSN: chain}
	return nil
}

// applyInlineSQL mounts the `sql` block, which reaches a database rather than
// a URL, so validateGrant refuses every HTTP construct beside it.
func applyInlineSQL(d *Descriptor, c *kdl.Node) error {
	spec, err := parseSQL(c)
	if err != nil {
		return err
	}
	d.SQL = spec
	return nil
}

// applyInlineGraphQL mounts the `graphql` block. It owns the whole request
// body, so validateGrant refuses any other body construct beside it.
func applyInlineGraphQL(d *Descriptor, c *kdl.Node) error {
	gql, err := parseGraphQL(c)
	if err != nil {
		return err
	}
	d.GraphQL = gql
	return nil
}

func applyInlineBody(d *Descriptor, c *kdl.Node) error {
	fields, mappings, err := inlineBodyFields(c)
	if err != nil {
		return err
	}
	if len(fields) > 0 && len(d.BodyMappings) > 0 {
		return fmt.Errorf("body fields and body `map` declarations cannot be combined (fail-closed)")
	}
	if len(mappings) > 0 && len(d.BodyFlags) > 0 {
		return fmt.Errorf("body fields and body `map` declarations cannot be combined (fail-closed)")
	}
	d.BodyFlags = append(d.BodyFlags, fields...)
	d.BodyMappings = append(d.BodyMappings, mappings...)
	return nil
}

func applyInlineGrantControlChild(d *Descriptor, c *kdl.Node) error {
	switch c.Name() {
	case "describe":
		if d.Describe != "" {
			return fmt.Errorf("duplicate `describe` (fail-closed)")
		}
		v, err := singleInlineArg(c, "describe")
		if err != nil {
			return err
		}
		if v == "" {
			return fmt.Errorf("`describe` needs a non-empty note")
		}
		d.Describe = v
		return nil
	case "set":
		return applyInlineSet(d, c)
	case "fail-when":
		if d.FailWhen != "" {
			return fmt.Errorf("duplicate `fail-when` (fail-closed)")
		}
		expr, err := singleInlineArg(c, "fail-when")
		if err != nil {
			return err
		}
		if expr == "" {
			return fmt.Errorf("`fail-when` needs a non-empty JMESPath expression")
		}
		if err := respfmt.Validate(expr); err != nil {
			return fmt.Errorf("fail-when: %w", err)
		}
		d.FailWhen = expr
		return nil
	default:
		return fmt.Errorf("unknown node %q (want path | query | body | method | raw-response | set | fail-when | describe; fail-closed)", c.Name())
	}
}

// validateGrant runs the cross-field checks a finished grant must pass.
func validateGrant(d Descriptor, verb, resource string) error {
	// A raw body is never decoded, so fail-when would have nothing to evaluate
	// and would sit inert rather than guarding anything.
	if d.RawResponse && d.FailWhen != "" {
		return fmt.Errorf("opcore: can %s %s: `raw-response` cannot be combined with `fail-when`, which needs a decoded response (fail-closed)", verb, resource)
	}
	if err := validateSQLGrant(d, verb, resource); err != nil {
		return err
	}
	if err := validateGraphQLGrant(d, verb, resource); err != nil {
		return err
	}
	if err := validateBodyMappings(d.BodyMappings); err != nil {
		return fmt.Errorf("opcore: can %s %s: %w", verb, resource, err)
	}
	if err := validateQueryExclusive(d); err != nil {
		return err
	}
	return CheckFlagCollisions(d)
}

// inferredMethodWarning names a grant whose method was guessed from a verb the
// convention table has never seen. See docs/specverb-resolution.md.
func inferredMethodWarning(d Descriptor, verb, resource string) string {
	return fmt.Sprintf(
		"opcore: can %s %s: %q is not a known verb, so the method was inferred as %s; state it with `method \"...\"` if that is wrong",
		verb, resource, verb, d.Method)
}

// applyInlineRawResponse declares the success body non-JSON, written through
// undecoded. Bare by design: see docs/specverb-request.md.
func applyInlineRawResponse(d *Descriptor, c *kdl.Node) error {
	if len(c.Arguments()) != 0 || len(c.Properties()) != 0 {
		return fmt.Errorf("`raw-response` takes no arguments (write it bare; fail-closed)")
	}
	if len(c.Children().Nodes) != 0 {
		return fmt.Errorf("`raw-response` takes no block (write it bare; fail-closed)")
	}
	d.RawResponse = true
	return nil
}

// checkOnceOnlyChildren refuses a repeated `method` or `raw-response`. Both
// carry a meaningful zero, so neither is caught by an already-set field.
func checkOnceOnlyChildren(n *kdl.Node, verb, resource string) error {
	for _, once := range []string{"method", "raw-response", "graphql", "sql"} {
		if countChildren(n, once) > 1 {
			return fmt.Errorf("opcore: can %s %s: duplicate `%s` (fail-closed)", verb, resource, once)
		}
	}
	return nil
}

// countChildren reports how many direct children of n carry name.
func countChildren(n *kdl.Node, name string) int {
	count := 0
	for _, c := range n.Children().Nodes {
		if c.Name() == name {
			count++
		}
	}
	return count
}

// applyInlineMethod states the HTTP method outright, which is how a verb the
// convention table has never seen avoids being guessed at.
func applyInlineMethod(d *Descriptor, c *kdl.Node) error {
	v, err := singleInlineArg(c, "method")
	if err != nil {
		return err
	}
	m := strings.ToUpper(v)
	if !ValidMethod(m) {
		return fmt.Errorf("`method` %q is not an HTTP method (want GET | POST | PUT | PATCH | DELETE | HEAD; fail-closed)", v)
	}
	d.Method = m
	// Stated, so nothing was inferred and no warning is owed.
	d.MethodInferred = false
	// A stated DELETE is destructive even when the verb name is not "delete".
	if m == "DELETE" {
		d.Destructive = true
	}
	return nil
}

// applyProxyChild dispatches one child of a proxy grant body onto d, failing
// closed on anything outside upstream | allow | deny | post-call | describe.
func applyProxyChild(d *Descriptor, c *kdl.Node) error {
	if d.Proxy == nil {
		d.Proxy = &Proxy{Name: d.Leaf}
	}
	switch c.Name() {
	case "upstream":
		return setProxyUpstream(d.Proxy, c)
	case "allow":
		return appendProxyRule(&d.Proxy.Allow, c, proxyRuleAllow)
	case "deny":
		return appendProxyRule(&d.Proxy.Deny, c, proxyRuleDeny)
	case "post-call":
		return appendProxyRule(&d.Proxy.PostCall, c, proxyRulePostCall)
	case "describe":
		return setProxyDescribe(d.Proxy, c)
	default:
		return fmt.Errorf("unknown node %q (want upstream | allow | deny | post-call | describe; fail-closed)", c.Name())
	}
}

func setProxyUpstream(proxy *Proxy, n *kdl.Node) error {
	if proxy.Upstream.Server != "" || proxy.Upstream.Tool != "" {
		return fmt.Errorf("duplicate `upstream` (fail-closed)")
	}
	server, tool, err := proxyUpstream(n)
	if err != nil {
		return err
	}
	proxy.Upstream = UpstreamTool{Server: server, Tool: tool}
	return nil
}

func appendProxyRule(dst *[]ProxyRule, n *kdl.Node, mode proxyRuleMode) error {
	rule, err := parseProxyRule(n, mode)
	if err != nil {
		return err
	}
	*dst = append(*dst, rule)
	return nil
}

func setProxyDescribe(proxy *Proxy, n *kdl.Node) error {
	v, err := singleInlineArg(n, "describe")
	if err != nil {
		return err
	}
	proxy.Describe = v
	return nil
}

type proxyRuleMode string

const (
	proxyRuleAllow    proxyRuleMode = "allow"
	proxyRuleDeny     proxyRuleMode = "deny"
	proxyRulePostCall proxyRuleMode = "post-call"
)

// proxyUpstream reads `upstream <server> <tool>` into the exact upstream tool
// mapping the consumer should proxy to.
func proxyUpstream(n *kdl.Node) (string, string, error) {
	if len(n.Children().Nodes) > 0 || len(n.Properties()) > 0 {
		return "", "", fmt.Errorf("`upstream` takes only positional args, no children or properties (fail-closed)")
	}
	args := n.Arguments()
	if len(args) != 2 {
		return "", "", fmt.Errorf("`upstream` needs a server and a tool, e.g. `upstream playwright browser_snapshot`")
	}
	server, tool := args[0].String(), args[1].String()
	if server == "" || tool == "" {
		return "", "", fmt.Errorf("`upstream` needs a non-empty server and tool")
	}
	return server, tool, nil
}

// parseProxyRule reads one `allow`/`deny`/`post-call` guard clause. The first arg
// is the selector, and `matches` separates it from one or more regex patterns.
func parseProxyRule(n *kdl.Node, mode proxyRuleMode) (ProxyRule, error) {
	args := n.Arguments()
	if len(args) < 3 || args[1].String() != "matches" {
		return ProxyRule{}, fmt.Errorf("opcore: %s needs `matches` regexes, e.g. `%s url matches \"^https://grubhub\\.com/\"`", n.Name(), n.Name())
	}
	field := args[0].String()
	if field == "" {
		return ProxyRule{}, fmt.Errorf("opcore: %s needs a non-empty selector", n.Name())
	}
	if !proxySelectorAllowed(field, mode) {
		return ProxyRule{}, fmt.Errorf("opcore: %s selector %q unsupported (fail-closed)", n.Name(), field)
	}
	rule := ProxyRule{Field: field}
	for _, a := range args[2:] {
		pat := a.String()
		if pat == "" {
			return ProxyRule{}, fmt.Errorf("opcore: %s %q has an empty regex (fail-closed)", n.Name(), field)
		}
		rule.Patterns = append(rule.Patterns, pat)
	}
	if len(rule.Patterns) == 0 {
		return ProxyRule{}, fmt.Errorf("opcore: %s %q needs at least one regex", n.Name(), field)
	}
	if len(n.Children().Nodes) > 0 || len(n.Properties()) > 0 {
		return ProxyRule{}, fmt.Errorf("opcore: %s takes only positional args, no children or properties (fail-closed)", n.Name())
	}
	return rule, nil
}

func proxySelectorAllowed(selector string, mode proxyRuleMode) bool {
	switch mode {
	case proxyRuleAllow, proxyRuleDeny:
		switch selector {
		case "url", "target", "element", "text", "key":
			return true
		}
	case proxyRulePostCall:
		switch selector {
		case "url", "content", "text", "state":
			return true
		}
	}
	return false
}

// applyInlineSet reads `set k=v...` and `set { key value }` into FixedBody,
// keeping each value's KDL-native type (a boolean stays a boolean) via RawValue.
func applyInlineSet(d *Descriptor, c *kdl.Node) error {
	props := c.Properties()
	children := c.Children()
	nested := children != nil && len(children.Nodes) > 0
	if len(props) == 0 && !nested {
		return fmt.Errorf("`set` needs at least one key=value (e.g. `set state=\"closed\"`) or a block of keys")
	}
	if d.FixedBody == nil {
		d.FixedBody = map[string]any{}
	}
	for k, val := range props {
		d.FixedBody[k] = val.RawValue()
	}
	if !nested {
		return nil
	}
	block, err := pinnedObject(children.Nodes)
	if err != nil {
		return err
	}
	for k, value := range block {
		if _, clash := props[k]; clash {
			return fmt.Errorf("`set` key %q is given twice (fail-closed)", k)
		}
		d.FixedBody[k] = value
	}
	return nil
}

// pinnedObject reads a `set` block. A KDL property is scalar-only, so a block
// is how a pin carries a shape. See docs/opcore-body.md.
func pinnedObject(nodes []*kdl.Node) (map[string]any, error) {
	out := make(map[string]any, len(nodes))
	for _, n := range nodes {
		if _, dup := out[n.Name()]; dup {
			return nil, fmt.Errorf("duplicate `set` key %q (fail-closed)", n.Name())
		}
		value, err := pinnedValue(n)
		if err != nil {
			return nil, err
		}
		out[n.Name()] = value
	}
	return out, nil
}

func pinnedValue(n *kdl.Node) (any, error) {
	args := n.Arguments()
	children := n.Children()
	if children != nil && len(children.Nodes) > 0 {
		if len(args) > 0 || len(n.Properties()) > 0 {
			return nil, fmt.Errorf("`set` key %q takes a value or a block, not both (fail-closed)", n.Name())
		}
		return pinnedObject(children.Nodes)
	}
	// One spelling per shape: a nested key states its value positionally.
	if len(n.Properties()) > 0 {
		return nil, fmt.Errorf("`set` key %q takes a value or a block, not key=value (fail-closed)", n.Name())
	}
	switch len(args) {
	case 0:
		return nil, fmt.Errorf("`set` key %q needs a value (fail-closed)", n.Name())
	case 1:
		return args[0].RawValue(), nil
	}
	values := make([]any, 0, len(args))
	for _, arg := range args {
		values = append(values, arg.RawValue())
	}
	return values, nil
}

// inlineFields reads query or flat body strings into Fields. Query upstream=
// maps one safe local name to a different outgoing parameter.
func inlineFields(c *kdl.Node, kind string) ([]Field, error) {
	if children := c.Children(); children != nil && len(children.Nodes) > 0 {
		return nil, fmt.Errorf("`%s` takes flat field names, not a block (fail-closed)", kind)
	}
	upstreamName, err := inlineUpstreamName(c, kind)
	if err != nil {
		return nil, err
	}
	args := c.Arguments()
	if len(args) == 0 {
		return nil, fmt.Errorf("`%s` needs at least one field name (e.g. `%s \"state\"`)", kind, kind)
	}
	if upstreamName != "" && len(args) != 1 {
		return nil, fmt.Errorf("`query` with upstream= maps exactly one local field name (fail-closed)")
	}
	out := make([]Field, 0, len(args))
	for _, a := range args {
		name := a.String()
		if name == "" {
			return nil, fmt.Errorf("`%s` field name is empty (fail-closed)", kind)
		}
		if upstreamName == name {
			return nil, fmt.Errorf("`query` field %q repeats its local name in upstream= (use the unaliased form)", name)
		}
		out = append(out, Field{Name: name, UpstreamName: upstreamName, Type: "string"})
	}
	return out, nil
}

// inlineQueryFields reads either the historical flat query shorthand or a
// typed query block. The shorthand stays on its original parsing path.
func inlineQueryFields(c *kdl.Node) ([]Field, [][]string, error) {
	hasChildren := c.Children() != nil && len(c.Children().Nodes) > 0
	hasArgs := len(c.Arguments()) > 0
	if hasChildren && hasArgs {
		return nil, nil, fmt.Errorf("`query` takes either flat field names or a block, not both (fail-closed)")
	}
	if hasArgs {
		fields, err := inlineFields(c, "query")
		return fields, nil, err
	}
	if len(c.Properties()) > 0 {
		return nil, nil, fmt.Errorf("a `query` block takes no properties (put properties on its fields, fail-closed)")
	}
	if !hasChildren {
		return nil, nil, fmt.Errorf("`query` needs at least one field name or a block")
	}
	return parseQueryChildren(c.Children().Nodes)
}

// parseQueryChildren reads a query block in declaration order and rejects
// duplicate local names before the descriptor reaches collision validation.
func parseQueryChildren(nodes []*kdl.Node) ([]Field, [][]string, error) {
	out := make([]Field, 0, len(nodes))
	var exclusive [][]string
	seen := map[string]bool{}
	for _, n := range nodes {
		if n.Name() == "mutually-exclusive" {
			group, err := parseQueryExclusive(n)
			if err != nil {
				return nil, nil, err
			}
			exclusive = append(exclusive, group)
			continue
		}
		f, err := parseQueryFieldNode(n)
		if err != nil {
			return nil, nil, err
		}
		if seen[f.Name] {
			return nil, nil, fmt.Errorf("duplicate `query` field %q (fail-closed)", f.Name)
		}
		seen[f.Name] = true
		out = append(out, f)
	}
	return out, exclusive, nil
}

// parseQueryExclusive reads one at-most-one declaration over local query names.
func parseQueryExclusive(n *kdl.Node) ([]string, error) {
	if len(n.Properties()) > 0 || (n.Children() != nil && len(n.Children().Nodes) > 0) {
		return nil, fmt.Errorf("`mutually-exclusive` takes only local query names (fail-closed)")
	}
	args := n.Arguments()
	if len(args) < 2 {
		return nil, fmt.Errorf("`mutually-exclusive` needs at least two local query names")
	}
	out := make([]string, 0, len(args))
	seen := map[string]bool{}
	for _, arg := range args {
		name := arg.String()
		if name == "" {
			return nil, fmt.Errorf("`mutually-exclusive` query name is empty (fail-closed)")
		}
		if seen[name] {
			return nil, fmt.Errorf("`mutually-exclusive` repeats query name %q (fail-closed)", name)
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}

// validateQueryExclusive resolves every declaration against the descriptor's
// local query names and rejects duplicate groups.
func validateQueryExclusive(d Descriptor) error {
	declared := map[string]bool{}
	for _, f := range d.QueryFlags {
		declared[f.Name] = true
	}
	seenGroups := map[string]bool{}
	for _, group := range d.QueryExclusive {
		for _, name := range group {
			if !declared[name] {
				return fmt.Errorf("opcore: %s: mutually-exclusive query name %q is not declared (fail-closed)", d.VerbName, name)
			}
		}
		key := strings.Join(group, "\x00")
		if seenGroups[key] {
			return fmt.Errorf("opcore: %s: duplicate mutually-exclusive query group (fail-closed)", d.VerbName)
		}
		seenGroups[key] = true
	}
	return nil
}

// parseQueryFieldNode accepts typed scalars and scalar arrays only. Query
// objects are not URL encodings and therefore fail closed.
func parseQueryFieldNode(n *kdl.Node) (Field, error) {
	switch n.Name() {
	case "field":
		return parseTypedQueryField(n, "")
	case "array":
		return parseTypedQueryField(n, "array")
	case "object":
		return Field{}, fmt.Errorf("object query field %q is unsupported (use scalar fields or arrays, fail-closed)", queryFieldName(n))
	default:
		return Field{}, fmt.Errorf("unknown node %q in `query` block (want field | array, fail-closed)", n.Name())
	}
}

// parseTypedQueryField reads one query field and validates its shape and bounds.
func parseTypedQueryField(n *kdl.Node, defaultType string) (Field, error) {
	args := n.Arguments()
	if len(args) != 1 || args[0].String() == "" {
		return Field{}, fmt.Errorf("`%s` expects exactly one non-empty field name", n.Name())
	}
	f := Field{Name: args[0].String(), Type: defaultType}
	if err := applyQueryFieldProperties(&f, n); err != nil {
		return Field{}, err
	}
	if f.Type == "" {
		return Field{}, fmt.Errorf("`field` needs a `type=...` property")
	}
	if err := validateQueryFieldShape(n, &f); err != nil {
		return Field{}, err
	}
	return f, nil
}

// applyQueryFieldProperties reads the closed property set for typed query
// fields. Numeric bounds stay distinct from array-length bounds.
func applyQueryFieldProperties(f *Field, n *kdl.Node) error {
	for k, v := range n.Properties() {
		if err := applyQueryFieldProperty(f, n.Name(), k, v); err != nil {
			return err
		}
	}
	return nil
}

func applyQueryFieldProperty(f *Field, nodeName, key string, value kdl.Value) error {
	switch key {
	case "type", "items", "upstream", "encode":
		return applyQueryStringFieldProperty(f, nodeName, key, value)
	case "required":
		b, ok := value.RawValue().(bool)
		if !ok {
			return fmt.Errorf("query field %q needs `required=true|false`", f.Name)
		}
		f.Required = b
	case "minimum", "maximum":
		return applyQueryNumericBound(f, key, value.RawValue())
	case "min-items", "max-items":
		return applyQueryArrayBound(f, key, value.RawValue())
	default:
		return fmt.Errorf("unknown property %q on query field %q (fail-closed)", key, f.Name)
	}
	return nil
}

func applyQueryStringFieldProperty(f *Field, nodeName, key string, value kdl.Value) error {
	raw, ok := queryStringProperty(value)
	if !ok {
		return fmt.Errorf("query field %q needs a non-empty string %s value", f.Name, key)
	}
	switch key {
	case "type":
		if f.Type != "" {
			return fmt.Errorf("`%s` sets type twice (fail-closed)", nodeName)
		}
		f.Type = raw
	case "items":
		f.Items = raw
	case "upstream":
		f.UpstreamName = raw
	case "encode":
		f.ArrayEncode = raw
	}
	return nil
}

func queryStringProperty(value kdl.Value) (string, bool) {
	raw, ok := value.RawValue().(string)
	return raw, ok && raw != ""
}

func applyQueryNumericBound(f *Field, property string, raw any) error {
	bound, err := queryNumericBound(raw, property, f.Name)
	if err != nil {
		return err
	}
	if property == "minimum" {
		f.Minimum = &bound
	} else {
		f.Maximum = &bound
	}
	return nil
}

func applyQueryArrayBound(f *Field, property string, raw any) error {
	bound, err := queryItemBound(raw, property, f.Name)
	if err != nil {
		return err
	}
	if property == "min-items" {
		f.MinItems = &bound
	} else {
		f.MaxItems = &bound
	}
	return nil
}

// validateQueryFieldShape enforces the typed query grammar after properties
// have been parsed.
func validateQueryFieldShape(n *kdl.Node, f *Field) error {
	if n.Children() != nil && len(n.Children().Nodes) > 0 {
		return fmt.Errorf("query field %q does not take a nested block (fail-closed)", f.Name)
	}
	switch f.Type {
	case "string", "boolean":
		return validateQueryScalarShape(*f)
	case "integer", "number":
		return validateQueryNumberShape(*f)
	case "array":
		return validateQueryArrayShape(f)
	default:
		return fmt.Errorf("unsupported query field type %q (want string | boolean | integer | number | array, fail-closed)", f.Type)
	}
}

func validateQueryScalarShape(f Field) error {
	if f.Minimum != nil || f.Maximum != nil {
		return fmt.Errorf("query field %q sets numeric bounds on type %q (fail-closed)", f.Name, f.Type)
	}
	if err := validateNoQueryArrayProperties(f); err != nil {
		return err
	}
	return validateQueryAliasShape(f)
}

func validateQueryNumberShape(f Field) error {
	if err := validateNoQueryArrayProperties(f); err != nil {
		return err
	}
	if f.Minimum != nil && f.Maximum != nil && *f.Minimum > *f.Maximum {
		return fmt.Errorf("query field %q has minimum greater than maximum (fail-closed)", f.Name)
	}
	return validateQueryAliasShape(f)
}

func validateQueryArrayShape(f *Field) error {
	if f.Minimum != nil || f.Maximum != nil {
		return fmt.Errorf("query array %q sets scalar numeric bounds (fail-closed)", f.Name)
	}
	if f.Items == "" {
		f.Items = "string"
	}
	if !queryScalarType(f.Items) {
		return fmt.Errorf("query array %q has unsupported items type %q (want string | boolean | integer | number, fail-closed)", f.Name, f.Items)
	}
	if f.MinItems != nil && f.MaxItems != nil && *f.MinItems > *f.MaxItems {
		return fmt.Errorf("query array %q has min-items greater than max-items (fail-closed)", f.Name)
	}
	switch f.ArrayEncode {
	case "", "repeat", "brackets":
	default:
		return fmt.Errorf("query array %q has unsupported encode %q (want repeat | brackets, fail-closed)", f.Name, f.ArrayEncode)
	}
	return validateQueryAliasShape(*f)
}

func validateNoQueryArrayProperties(f Field) error {
	if f.Items != "" || f.MinItems != nil || f.MaxItems != nil || f.ArrayEncode != "" {
		return fmt.Errorf("query field %q sets array properties on type %q (fail-closed)", f.Name, f.Type)
	}
	return nil
}

func validateQueryAliasShape(f Field) error {
	if f.UpstreamName == f.Name && f.UpstreamName != "" {
		return fmt.Errorf("query field %q repeats its local name in upstream= (use the unaliased form)", f.Name)
	}
	return nil
}

func queryScalarType(t string) bool {
	switch t {
	case "string", "boolean", "integer", "number":
		return true
	}
	return false
}

// queryNumericBound converts the KDL numeric kinds used by minimum and maximum.
func queryNumericBound(raw any, property, field string) (float64, error) {
	var out float64
	switch v := raw.(type) {
	case int:
		out = float64(v)
	case float64:
		out = v
	default:
		return 0, fmt.Errorf("query field %q property %s must be a finite number (fail-closed)", field, property)
	}
	if math.IsNaN(out) || math.IsInf(out, 0) {
		return 0, fmt.Errorf("query field %q property %s must be a finite number (fail-closed)", field, property)
	}
	return out, nil
}

// queryItemBound accepts a non-negative KDL integer for min-items/max-items.
func queryItemBound(raw any, property, field string) (int, error) {
	out, ok := raw.(int)
	if !ok || out < 0 {
		return 0, fmt.Errorf("query array %q property %s must be a non-negative integer (fail-closed)", field, property)
	}
	return out, nil
}

func queryFieldName(n *kdl.Node) string {
	args := n.Arguments()
	if len(args) == 1 {
		return args[0].String()
	}
	return ""
}

// inlineUpstreamName reads the one property accepted by a query declaration.
// Body shorthand and every unknown property fail closed.
func inlineUpstreamName(c *kdl.Node, kind string) (string, error) {
	upstreamName := ""
	for k, v := range c.Properties() {
		if kind != "query" || k != "upstream" {
			return "", fmt.Errorf("unknown property %q on `%s` (want upstream on query only; fail-closed)", k, kind)
		}
		raw, ok := v.RawValue().(string)
		if !ok || raw == "" {
			return "", fmt.Errorf("`query` needs a non-empty string upstream name")
		}
		upstreamName = raw
	}
	return upstreamName, nil
}

// inlineBodyFields reads either `body "title" "body"` shorthand, a nested
// field block, or a block containing only exact `map <path> to=<key>` nodes.
func inlineBodyFields(c *kdl.Node) ([]Field, []BodyMapping, error) {
	hasChildren := c.Children() != nil && len(c.Children().Nodes) > 0
	hasArgs := len(c.Arguments()) > 0
	if hasChildren && hasArgs {
		return nil, nil, fmt.Errorf("`body` takes either flat field names or a block, not both (fail-closed)")
	}
	if hasArgs {
		fields, err := inlineFields(c, "body")
		return fields, nil, err
	}
	if !hasChildren {
		return nil, nil, fmt.Errorf("`body` needs at least one field name or a block")
	}
	nodes := c.Children().Nodes
	hasMap := false
	hasField := false
	for _, n := range nodes {
		if n.Name() == "map" {
			hasMap = true
		} else {
			hasField = true
		}
	}
	if hasMap && hasField {
		return nil, nil, fmt.Errorf("body fields and body `map` declarations cannot be combined (fail-closed)")
	}
	if hasMap {
		mappings, err := parseBodyMappings(nodes)
		return nil, mappings, err
	}
	fields, err := parseBodyChildren(nodes)
	return fields, nil, err
}

// parseBodyChildren reads a body block's child nodes into Fields, preserving
// the declared order and failing closed on duplicate sibling names.
func parseBodyChildren(nodes []*kdl.Node) ([]Field, error) {
	out := make([]Field, 0, len(nodes))
	seen := map[string]bool{}
	for _, n := range nodes {
		f, err := parseBodyFieldNode(n)
		if err != nil {
			return nil, err
		}
		if f.Name == "" {
			return nil, fmt.Errorf("`body` field name is empty (fail-closed)")
		}
		if seen[f.Name] {
			return nil, fmt.Errorf("duplicate `body` field %q (fail-closed)", f.Name)
		}
		seen[f.Name] = true
		out = append(out, f)
	}
	return out, nil
}

// parseBodyFieldNode reads one nested body field declaration into a Field.
func parseBodyFieldNode(n *kdl.Node) (Field, error) {
	switch n.Name() {
	case "field":
		return parseTypedBodyField(n, "")
	case "object":
		return parseTypedBodyField(n, "object")
	case "array":
		return parseTypedBodyField(n, "array")
	default:
		return Field{}, fmt.Errorf("unknown node %q in `body` block (want field | object | array; fail-closed)", n.Name())
	}
}

// parseTypedBodyField reads one body field declaration, allowing only the
// frozen property set used by the inline body grammar.
func parseTypedBodyField(n *kdl.Node, defaultType string) (Field, error) {
	args := n.Arguments()
	if len(args) != 1 || args[0].String() == "" {
		return Field{}, fmt.Errorf("`%s` expects exactly one non-empty field name", n.Name())
	}
	f := Field{Name: args[0].String()}
	if defaultType != "" {
		f.Type = defaultType
	}
	if err := applyBodyFieldProperties(&f, n); err != nil {
		return Field{}, err
	}
	if f.Type == "" {
		if n.Name() == "field" {
			return Field{}, fmt.Errorf("`field` needs a `type=...` property")
		}
		f.Type = defaultType
	}
	if err := validateBodyFieldShape(n, &f); err != nil {
		return Field{}, err
	}
	return f, nil
}

// applyBodyFieldProperties reads the allowed `field` / `object` / `array`
// properties into the working Field, failing closed on anything else.
func applyBodyFieldProperties(f *Field, n *kdl.Node) error {
	for k, v := range n.Properties() {
		switch k {
		case "type":
			if f.Type != "" {
				return fmt.Errorf("`%s` sets type twice (fail-closed)", n.Name())
			}
			f.Type = v.String()
		case "items":
			f.Items = v.String()
		case "required":
			b, ok := v.RawValue().(bool)
			if !ok {
				return fmt.Errorf("`%s` needs `required=true|false`", n.Name())
			}
			f.Required = b
		case "raw":
			b, ok := v.RawValue().(bool)
			if !ok {
				return fmt.Errorf("`%s` needs `raw=true|false`", n.Name())
			}
			f.Raw = b
		default:
			return fmt.Errorf("unknown property %q on `body` field %q (want type | items | required | raw; fail-closed)", k, f.Name)
		}
	}
	return nil
}

// validateBodyFieldShape enforces the type-specific body grammar for one field.
func validateBodyFieldShape(n *kdl.Node, f *Field) error {
	switch f.Type {
	case "string", "boolean", "integer", "number":
		return validateScalarBodyField(n, *f)
	case "object":
		return validateObjectBodyField(n, f)
	case "array":
		return validateArrayBodyField(n, f)
	default:
		return fmt.Errorf("unsupported body field type %q (want string | boolean | integer | number | array | object; fail-closed)", f.Type)
	}
}

// validateScalarBodyField rejects nested blocks and raw markers on scalars.
func validateScalarBodyField(n *kdl.Node, f Field) error {
	if n.Children() != nil && len(n.Children().Nodes) > 0 {
		return fmt.Errorf("`%s` does not take a block when it is scalar (fail-closed)", n.Name())
	}
	if f.Raw {
		return fmt.Errorf("`%s` only accepts `raw=true` on `object` or `array` fields (fail-closed)", n.Name())
	}
	return nil
}

// validateObjectBodyField wires nested object children into the Field tree.
func validateObjectBodyField(n *kdl.Node, f *Field) error {
	if f.Raw {
		if n.Children() != nil && len(n.Children().Nodes) > 0 {
			return fmt.Errorf("`object` with `raw=true` cannot also declare nested fields (fail-closed)")
		}
		return nil
	}
	if n.Children() == nil || len(n.Children().Nodes) == 0 {
		return fmt.Errorf("`object` needs a nested block or `raw=true`")
	}
	children, err := parseBodyChildren(n.Children().Nodes)
	if err != nil {
		return err
	}
	f.Fields = children
	return nil
}

// validateArrayBodyField keeps v1 arrays scalar or raw, never nested.
func validateArrayBodyField(n *kdl.Node, f *Field) error {
	if f.Raw {
		if n.Children() != nil && len(n.Children().Nodes) > 0 {
			return fmt.Errorf("`array` with `raw=true` cannot also declare nested fields (fail-closed)")
		}
		if f.Items != "" {
			return fmt.Errorf("`%s` with `raw=true` cannot also set `items` (fail-closed)", n.Name())
		}
		return nil
	}
	if f.Items == "" {
		f.Items = "string"
	}
	if n.Children() != nil && len(n.Children().Nodes) > 0 {
		return fmt.Errorf("`array` does not take a block in v1 (use `items=...` or `raw=true`; fail-closed)")
	}
	return nil
}

// singleInlineArg reads the lone string argument of an inline grant child.
func singleInlineArg(c *kdl.Node, kind string) (string, error) {
	args := c.Arguments()
	if len(args) != 1 || args[0].String() == "" {
		return "", fmt.Errorf("`%s` expects exactly one non-empty value", kind)
	}
	return args[0].String(), nil
}

// PathParamsInOrder returns the `{...}` names in path-template order, the order
// the leaf takes them positionally. Shared with the CLI projection's binder.
func PathParamsInOrder(path string) []string {
	matches := pathParamRe.FindAllStringSubmatch(path, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}
