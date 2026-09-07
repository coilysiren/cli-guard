package opcore

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	neturl "net/url"
	"reflect"
	"strconv"

	"forgejo.coilysiren.me/coilyco-flight-deck/umbra/http/respfmt"
	"forgejo.coilysiren.me/coilyco-flight-deck/umbra/pkg/exitcode"
)

// Operation is one resolved leaf plus the runtime that fires it: the unit a
// non-CLI consumer (ward-mcp) drives via the self-guarding Execute.
type Operation struct {
	Desc Descriptor
	RT   *Runtime
}

// Args splits an Operation's inputs by URL and body location. Query is the
// compatible scalar surface, while QueryValues carries typed values and arrays.
type Args struct {
	Path        map[string]string
	Query       map[string]string
	QueryValues map[string]any
	Body        map[string]any
}

// Request is a resolved-but-unfired call: the exact method, URL, and body the
// runtime would send. Preview returns one for a consumer's dry-run.
type Request struct {
	Method      string
	URL         string
	Body        []byte
	ContentType string
}

// Response is a fired call's outcome: the decoded JSON value, the raw bytes
// (for a consumer's own rendering), and the HTTP status line.
type Response struct {
	Decoded any
	Raw     []byte
	Status  string
}

// Resolve validates, gates, and assembles one request without firing it.
// Consumers use it when they need the resolved request shape.
func (o Operation) Resolve(ctx context.Context, a Args, dry bool) (Request, error) {
	return o.resolve(ctx, a, dry)
}

// Execute runs the leaf under the full security floor (gate, restrict, assemble,
// base-url, auth, fire) and returns the decoded response, rendering nothing.
func (o Operation) Execute(ctx context.Context, a Args) (Response, error) {
	// An mcp leaf fires a session call, so it leaves before the HTTP floor for
	// the same reason a sql grant does, and rejoins at the same postcondition.
	if o.Desc.MCP != nil {
		resp, err := o.executeMCP(ctx, a)
		if err != nil {
			return Response{}, err
		}
		if err := o.checkResponse(resp.Decoded, a); err != nil {
			return Response{}, err
		}
		return resp, nil
	}
	// A sql grant never assembles a URL, so it leaves before the HTTP floor.
	if o.Desc.SQL != nil {
		resp, err := o.executeSQL(ctx, a)
		if err != nil {
			return Response{}, err
		}
		if err := o.checkResponse(resp.Decoded, a); err != nil {
			return Response{}, err
		}
		return resp, nil
	}
	req, err := o.Resolve(ctx, a, false)
	if err != nil {
		return Response{}, err
	}
	// A declared non-JSON body has no decoded form, so it never reaches the
	// decode or the fail-when postcondition. Raw carries it out.
	if o.Desc.RawResponse {
		raw, status, rerr := o.RT.FireCaptureRaw(ctx, req.Method, req.URL, req.Body, req.ContentType)
		if rerr != nil {
			return Response{}, rerr
		}
		return Response{Raw: raw, Status: status}, nil
	}
	decoded, raw, status, err := o.RT.FireCapture(ctx, req.Method, req.URL, req.Body, req.ContentType)
	if err != nil {
		return Response{}, err
	}
	if err := o.checkResponse(decoded, a); err != nil {
		return Response{}, err
	}
	return Response{Decoded: decoded, Raw: raw, Status: status}, nil
}

// checkResponse evaluates an inline grant's semantic response postcondition.
// Request inputs are exposed as native JMESPath variables.
func (o Operation) checkResponse(decoded any, a Args) error {
	if o.Desc.FailWhen == "" {
		return nil
	}
	fail, err := respfmt.EvalBool(decoded, o.Desc.FailWhen, responseVars(o.Desc, a))
	if err != nil {
		return exitcode.New(exitcode.Internal, "internal", err,
			"check the inline grant's `fail-when` expression against the response shape")
	}
	if fail {
		return exitcode.New(exitcode.UpstreamFailed, "upstream_failed",
			fmt.Errorf("%s response matched fail-when %q", o.Desc.Leaf, o.Desc.FailWhen),
			"the API returned success but did not satisfy the declared response postcondition")
	}
	return nil
}

func responseVars(d Descriptor, a Args) map[string]any {
	out := make(map[string]any, len(a.Path)+len(a.Query)+len(a.QueryValues)+len(a.Body)+len(d.FixedBody))
	for name, value := range a.Path {
		out[name] = value
	}
	for name, value := range a.Query {
		out[name] = value
	}
	for name, value := range a.QueryValues {
		out[name] = value
	}
	// Mirrors assembleBody: only a flagless, mappingless leaf loses its caller
	// body to the pins, so a postcondition reads what actually went upstream.
	body := a.Body
	if len(d.FixedBody) > 0 && len(d.BodyMappings) == 0 && len(d.BodyFlags) == 0 {
		body = d.FixedBody
	}
	for name, value := range body {
		out[name] = value
	}
	if len(d.FixedBody) > 0 && (len(d.BodyMappings) > 0 || len(d.BodyFlags) > 0) {
		for name, value := range d.FixedBody {
			out[name] = value
		}
	}
	return out
}

// Preview resolves the request without firing it (same gate/restrict/assembly as
// Execute) for a dry-run; a value-resolved base-url stays an offline placeholder.
func (o Operation) Preview(a Args) (Request, error) {
	return o.Resolve(context.Background(), a, true)
}

// ResolveQuery validates, aliases, and serializes query inputs without
// assembling or firing. Encode makes them unable to alter the URL, so no gate.
func (o Operation) ResolveQuery(a Args) (neturl.Values, error) {
	return o.outgoingQuery(a)
}

// resolve runs the gate, restrictions, and assembly shared by Execute and
// Preview, returning the resolved request. dry keeps base-url resolution offline.
func (o Operation) resolve(ctx context.Context, a Args, dry bool) (Request, error) {
	d := o.Desc
	// Gate the unescaped surface only: FillPath substitutes path values verbatim.
	// Re-runs verb.Wrap's gate for a CLI leaf, idempotent when stacked.
	query, err := o.ResolveQuery(a)
	if err != nil {
		return Request{}, err
	}
	pathVals, err := o.orderedPathValues(a.Path)
	if err != nil {
		return Request{}, err
	}
	if err := o.RT.gatePathValues(d.PathParams, pathVals); err != nil {
		return Request{}, err
	}
	if err := o.RT.CheckRestrictions(d.PathParams, pathVals); err != nil {
		return Request{}, err
	}
	body, err := o.assembleBody(a.Body)
	if err != nil {
		return Request{}, err
	}
	base, err := o.RT.BaseForRequest(ctx, dry)
	if err != nil {
		return Request{}, err
	}
	url := base + FillPath(d.Path, pathVals) + assembleQuery(query)
	return Request{Method: d.Method, URL: url, Body: body, ContentType: contentTypeJSON}, nil
}

// outgoingQuery maps both query input surfaces onto repeated upstream values.
// Unknown scalar names retain the historical pass-through behavior.
func (o Operation) outgoingQuery(a Args) (neturl.Values, error) {
	fields := queryFieldsByName(o.Desc.QueryFlags)
	suppliedNames, err := queryInputNames(a)
	if err != nil {
		return nil, err
	}
	if err := o.validateQueryPresence(suppliedNames); err != nil {
		return nil, err
	}

	encoder := queryEncoder{
		fields: fields,
		out:    neturl.Values{},
		owners: make(map[string]string, len(suppliedNames)),
	}
	for localName, value := range a.Query {
		if err := encoder.addLegacy(localName, value); err != nil {
			return nil, err
		}
	}
	for localName, value := range a.QueryValues {
		if err := encoder.addTyped(localName, value); err != nil {
			return nil, err
		}
	}
	return encoder.out, nil
}

func queryFieldsByName(fields []Field) map[string]Field {
	out := make(map[string]Field, len(fields))
	for _, f := range fields {
		out[f.Name] = f
	}
	return out
}

func queryInputNames(a Args) (map[string]bool, error) {
	out := make(map[string]bool, len(a.Query)+len(a.QueryValues))
	for name := range a.Query {
		out[name] = true
	}
	for name := range a.QueryValues {
		if out[name] {
			return nil, queryUserError(
				fmt.Errorf("query input %q was supplied through both Query and QueryValues", name),
				"supply each query input through only one Args field")
		}
		out[name] = true
	}
	return out, nil
}

type queryEncoder struct {
	fields map[string]Field
	out    neturl.Values
	owners map[string]string
}

func (e *queryEncoder) addLegacy(name, value string) error {
	values, err := legacyQueryValues(e.fields, name, value)
	if err != nil {
		return err
	}
	return e.add(name, values)
}

func (e *queryEncoder) addTyped(name string, value any) error {
	values, err := typedQueryValues(e.fields, name, value)
	if err != nil {
		return err
	}
	return e.add(name, values)
}

func (e *queryEncoder) add(localName string, values []string) error {
	wireName := localName
	if f, ok := e.fields[localName]; ok {
		wireName = f.QueryWireName()
	}
	if prior, exists := e.owners[wireName]; exists {
		return queryUserError(
			fmt.Errorf("query inputs %q and %q both resolve to upstream parameter %q", prior, localName, wireName),
			"supply only the declared local query input name")
	}
	e.owners[wireName] = localName
	for _, value := range values {
		e.out.Add(wireName, value)
	}
	return nil
}

// validateQueryPresence enforces required and at-most-one query declarations
// using local input names, before any values reach the URL.
func (o Operation) validateQueryPresence(supplied map[string]bool) error {
	for _, f := range o.Desc.QueryFlags {
		if f.Required && !supplied[f.Name] {
			return queryUserError(
				fmt.Errorf("required query field %q is missing", f.Name),
				"supply the required query field")
		}
	}
	for _, group := range o.Desc.QueryExclusive {
		var present []string
		for _, name := range group {
			if supplied[name] {
				present = append(present, name)
			}
		}
		if len(present) > 1 {
			return queryUserError(
				fmt.Errorf("query fields %q are mutually exclusive", present),
				"supply at most one field from the mutually-exclusive group")
		}
	}
	return nil
}

// legacyQueryValues preserves the scalar wire spelling used by Args.Query. New
// typed declarations still validate that spelling against their contract.
func legacyQueryValues(fields map[string]Field, name, value string) ([]string, error) {
	f, declared := fields[name]
	if !declared || f.Type == "" || f.Type == "string" {
		return []string{value}, nil
	}
	if f.Type == "array" {
		if err := validateArrayLength(f, 1); err != nil {
			return nil, err
		}
		if _, _, err := queryScalarValue(f.Items, value); err != nil {
			return nil, fieldQueryError(f, err)
		}
		return []string{value}, nil
	}
	_, numeric, err := queryScalarValue(f.Type, value)
	if err != nil {
		return nil, fieldQueryError(f, err)
	}
	if err := validateNumericBounds(f, numeric); err != nil {
		return nil, err
	}
	return []string{value}, nil
}

// typedQueryValues lowers one QueryValues entry while preserving array order.
func typedQueryValues(fields map[string]Field, name string, value any) ([]string, error) {
	f, declared := fields[name]
	if !declared {
		return untypedQueryValues(name, value)
	}
	if f.Type == "" {
		f.Type = "string"
	}
	if f.Type == "array" {
		return typedQueryArrayValues(f, value)
	}
	return typedQueryScalarValues(f, value)
}

func typedQueryScalarValues(f Field, value any) ([]string, error) {
	if isQuerySlice(value) {
		return nil, fieldQueryError(f, fmt.Errorf("expected one %s value, got an array", f.Type))
	}
	if _, isString := value.(string); isString && f.Type != "string" {
		return nil, fieldQueryError(f, fmt.Errorf("expected typed %s, got string", f.Type))
	}
	wire, numeric, err := queryScalarValue(f.Type, value)
	if err != nil {
		return nil, fieldQueryError(f, err)
	}
	if err := validateNumericBounds(f, numeric); err != nil {
		return nil, err
	}
	return []string{wire}, nil
}

func typedQueryArrayValues(f Field, value any) ([]string, error) {
	items, ok := querySlice(value)
	if !ok {
		return nil, fieldQueryError(f, fmt.Errorf("expected an array of %s values", f.Items))
	}
	if err := validateArrayLength(f, len(items)); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(items))
	for i, item := range items {
		if _, isString := item.(string); isString && f.Items != "string" {
			return nil, fieldQueryError(f, fmt.Errorf("item %d: expected typed %s, got string", i, f.Items))
		}
		wire, _, err := queryScalarValue(f.Items, item)
		if err != nil {
			return nil, fieldQueryError(f, fmt.Errorf("item %d: %w", i, err))
		}
		out = append(out, wire)
	}
	return out, nil
}

// untypedQueryValues keeps typed-map pass-through limited to scalar URL values
// and scalar arrays. Objects and nested arrays fail closed.
func untypedQueryValues(name string, value any) ([]string, error) {
	if items, ok := querySlice(value); ok {
		out := make([]string, 0, len(items))
		for i, item := range items {
			if isQuerySlice(item) {
				return nil, queryUserError(
					fmt.Errorf("query input %q item %d is a nested array", name, i),
					"supply only scalar query values or scalar arrays")
			}
			wire, _, err := queryScalarValue("", item)
			if err != nil {
				return nil, queryUserError(
					fmt.Errorf("query input %q item %d: %w", name, i, err),
					"supply only string, boolean, integer, or number query values")
			}
			out = append(out, wire)
		}
		return out, nil
	}
	wire, _, err := queryScalarValue("", value)
	if err != nil {
		return nil, queryUserError(
			fmt.Errorf("query input %q: %w", name, err),
			"supply only string, boolean, integer, number, or scalar-array query values")
	}
	return []string{wire}, nil
}

// queryScalarValue validates one scalar and returns its URL spelling. numeric
// is non-nil only for integer and number values.
func queryScalarValue(want string, value any) (wire string, numeric *float64, err error) {
	switch want {
	case "string":
		return stringQueryValue(value)
	case "boolean":
		return booleanQueryValue(value)
	case "integer":
		wire, number, ok := integerQueryValue(value)
		if !ok {
			return "", nil, fmt.Errorf("expected integer, got %T", value)
		}
		return wire, &number, nil
	case "number":
		wire, number, ok := numberQueryValue(value)
		if !ok {
			return "", nil, fmt.Errorf("expected finite number, got %T", value)
		}
		return wire, &number, nil
	case "":
		return inferredQueryValue(value)
	default:
		return "", nil, fmt.Errorf("unsupported query scalar type %q", want)
	}
}

func stringQueryValue(value any) (string, *float64, error) {
	v, ok := value.(string)
	if !ok {
		return "", nil, fmt.Errorf("expected string, got %T", value)
	}
	return v, nil, nil
}

func booleanQueryValue(value any) (string, *float64, error) {
	switch v := value.(type) {
	case bool:
		return strconv.FormatBool(v), nil, nil
	case string:
		if v == "true" || v == "false" {
			return v, nil, nil
		}
	}
	return "", nil, fmt.Errorf("expected boolean, got %T", value)
}

func inferredQueryValue(value any) (string, *float64, error) {
	switch value.(type) {
	case string:
		return stringQueryValue(value)
	case bool:
		return booleanQueryValue(value)
	}
	if wire, number, ok := integerQueryValue(value); ok {
		return wire, &number, nil
	}
	if wire, number, ok := numberQueryValue(value); ok {
		return wire, &number, nil
	}
	return "", nil, fmt.Errorf("unsupported query value type %T", value)
}

func integerQueryValue(value any) (string, float64, bool) {
	switch v := value.(type) {
	case float32:
		return floatIntegerQueryValue(float64(v))
	case float64:
		return floatIntegerQueryValue(v)
	case json.Number:
		return stringIntegerQueryValue(v.String())
	case string:
		return stringIntegerQueryValue(v)
	}
	rv := reflect.ValueOf(value)
	kind := rv.Kind()
	if kind >= reflect.Int && kind <= reflect.Int64 {
		v := rv.Int()
		return strconv.FormatInt(v, 10), float64(v), true
	}
	if kind >= reflect.Uint && kind <= reflect.Uint64 {
		v := rv.Uint()
		return strconv.FormatUint(v, 10), float64(v), true
	}
	return "", 0, false
}

func floatIntegerQueryValue(value float64) (string, float64, bool) {
	if !finiteIntegral(value) {
		return "", 0, false
	}
	return strconv.FormatFloat(value, 'f', -1, 64), value, true
}

func stringIntegerQueryValue(value string) (string, float64, bool) {
	integer, err := strconv.ParseInt(value, 10, 64)
	if err == nil {
		return value, float64(integer), true
	}
	number, err := strconv.ParseFloat(value, 64)
	if err != nil || !finiteIntegral(number) {
		return "", 0, false
	}
	return value, number, true
}

func numberQueryValue(value any) (string, float64, bool) {
	if wire, number, ok := integerQueryValue(value); ok {
		return wire, number, true
	}
	switch v := value.(type) {
	case float32:
		return finiteNumberQueryValue(float64(v), "")
	case float64:
		return finiteNumberQueryValue(v, "")
	case json.Number:
		return stringNumberQueryValue(v.String())
	case string:
		return stringNumberQueryValue(v)
	default:
		return "", 0, false
	}
}

func stringNumberQueryValue(value string) (string, float64, bool) {
	number, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return "", 0, false
	}
	return finiteNumberQueryValue(number, value)
}

func finiteNumberQueryValue(number float64, wire string) (string, float64, bool) {
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return "", 0, false
	}
	if wire != "" {
		return wire, number, true
	}
	return strconv.FormatFloat(number, 'g', -1, 64), number, true
}

func finiteIntegral(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && math.Trunc(v) == v
}

func querySlice(value any) ([]any, bool) {
	if value == nil {
		return nil, false
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, false
	}
	out := make([]any, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		out[i] = rv.Index(i).Interface()
	}
	return out, true
}

func isQuerySlice(value any) bool {
	_, ok := querySlice(value)
	return ok
}

func validateNumericBounds(f Field, numeric *float64) error {
	if numeric == nil {
		return nil
	}
	if f.Minimum != nil && *numeric < *f.Minimum {
		return fieldQueryError(f, fmt.Errorf("value %g is below minimum %g", *numeric, *f.Minimum))
	}
	if f.Maximum != nil && *numeric > *f.Maximum {
		return fieldQueryError(f, fmt.Errorf("value %g is above maximum %g", *numeric, *f.Maximum))
	}
	return nil
}

func validateArrayLength(f Field, length int) error {
	if f.MinItems != nil && length < *f.MinItems {
		return fieldQueryError(f, fmt.Errorf("array length %d is below min-items %d", length, *f.MinItems))
	}
	if f.MaxItems != nil && length > *f.MaxItems {
		return fieldQueryError(f, fmt.Errorf("array length %d is above max-items %d", length, *f.MaxItems))
	}
	return nil
}

func fieldQueryError(f Field, err error) error {
	return queryUserError(
		fmt.Errorf("query field %q: %w", f.Name, err),
		"supply a query value matching the declared type and bounds")
}

func queryUserError(err error, advice string) error {
	return exitcode.New(exitcode.UserError, "user_error", err, advice)
}

// orderedPathValues lowers the path-arg map to the leaf's declared path-param
// order, failing closed when any declared param is unbound.
func (o Operation) orderedPathValues(path map[string]string) ([]string, error) {
	vals := make([]string, len(o.Desc.PathParams))
	for i, p := range o.Desc.PathParams {
		v, ok := path[p]
		if !ok || v == "" {
			return nil, exitcode.New(exitcode.UserError, "user_error",
				fmt.Errorf("%s: path param %q was not supplied", o.Desc.Leaf, p),
				"supply every path parameter this operation names")
		}
		vals[i] = v
	}
	return vals, nil
}

// assembleQuery encodes the query map as a ?-prefixed string, "" when empty.
// url.Values sorts keys, so the result is deterministic.
func assembleQuery(q neturl.Values) string {
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

// AssembleBody builds one descriptor's outgoing JSON body. Exported so a caller
// assembling a request by hand cannot order the body modes differently.
func AssembleBody(d Descriptor, body map[string]any) ([]byte, error) {
	return Operation{Desc: d}.assembleBody(body)
}

// assembleBody builds the body JSON, in the four modes docs/opcore-body.md
// describes. Empty is nil.
func (o Operation) assembleBody(body map[string]any) ([]byte, error) {
	if err := validateBodyMappingMode(o.Desc); err != nil {
		return nil, exitcode.New(exitcode.Internal, "internal", err,
			"fix the operation's body mapping declaration")
	}
	if o.Desc.GraphQL != nil {
		return assembleGraphQLBody(body, o.Desc.GraphQL)
	}
	// Mappings first: a mapped body carries the pins rather than losing to them.
	if len(o.Desc.BodyMappings) > 0 {
		return projectMappedBody(body, o.Desc.BodyMappings, o.Desc.FixedBody)
	}
	// No flags to fill means a state-toggle leaf that owns its whole body.
	if len(o.Desc.FixedBody) > 0 && len(o.Desc.BodyFlags) == 0 {
		return json.Marshal(o.Desc.FixedBody)
	}
	if err := validateBodyFields(body, o.Desc.BodyFlags, ""); err != nil {
		return nil, err
	}
	if len(o.Desc.FixedBody) > 0 {
		return json.Marshal(pinnedOver(body, o.Desc.FixedBody))
	}
	if len(body) == 0 {
		return nil, nil
	}
	return json.Marshal(body)
}

// pinnedOver lays the pins over a caller body, the precedence
// projectMappedBody already gives a mapped one.
func pinnedOver(body, fixed map[string]any) map[string]any {
	out := make(map[string]any, len(body)+len(fixed))
	maps.Copy(out, body)
	maps.Copy(out, fixed)
	return out
}

// validateBodyFields enforces required body fields recursively. Optional
// nested fields only matter when their parent object or array is present.
func validateBodyFields(body map[string]any, fields []Field, prefix string) error {
	for _, f := range fields {
		if err := validateBodyField(body, f, prefix); err != nil {
			return err
		}
	}
	return nil
}

// validateBodyField enforces one required field and recurses into nested shapes.
func validateBodyField(body map[string]any, f Field, prefix string) error {
	path := f.Name
	if prefix != "" {
		path = prefix + "." + f.Name
	}
	v, present := body[f.Name]
	if !present {
		if f.Required {
			return exitcode.New(exitcode.UserError, "user_error",
				fmt.Errorf("required body field %q is missing", path),
				"supply the required body field")
		}
		return nil
	}
	if f.Raw {
		return nil
	}
	switch f.Type {
	case "object":
		return validateObjectBodyValue(v, f, path)
	case "array":
		return validateArrayBodyValue(v, f, path)
	default:
		return nil
	}
}

// validateObjectBodyValue walks a nested object value when the field declares
// child requirements.
func validateObjectBodyValue(v any, f Field, path string) error {
	child, ok := v.(map[string]any)
	if !ok || len(f.Fields) == 0 {
		return nil
	}
	return validateBodyFields(child, f.Fields, path)
}

// validateArrayBodyValue walks an array of object items when the field declares
// an item schema.
func validateArrayBodyValue(v any, f Field, path string) error {
	if f.Item == nil || len(f.Item.Fields) == 0 {
		return nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	for i, item := range items {
		child, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if err := validateBodyFields(child, f.Item.Fields, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

// gateDenied wraps a shell-metachar rejection as a coded PolicyDenied error.
func gateDenied(err error) error {
	return exitcode.New(exitcode.PolicyDenied, "policy_denied", err,
		"move the argument with the metacharacter into a file and pass it by path, "+
			"or name the param in the wrap's `allow-metacharacters` if it is known-safe")
}
