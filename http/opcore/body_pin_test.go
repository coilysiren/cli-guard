package opcore_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"forgejo.coilysiren.me/coilyco-flight-deck/umbra/http/opcore"
	"forgejo.coilysiren.me/coilyco-flight-deck/umbra/pkg/valuesource"
)

// bodyEcho captures the one outgoing body a grant sends.
func bodyEcho(t *testing.T, desc opcore.Descriptor) (*opcore.Operation, *map[string]any) {
	t.Helper()
	got := map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	rt := opcore.NewRuntime(opcore.RuntimeConfig{
		BaseURL:   srv.URL,
		Auth:      tokenAuth("s3cret"),
		Providers: valuesource.Merge(nil),
		Client:    srv.Client(),
	})
	return &opcore.Operation{RT: rt, Desc: desc}, &got
}

// The Exa shape from #311: a required parameter colliding with a reserved engine
// flag, so it must be mapped, beside a constant the model must not name or vary.
func TestExecuteMappedBodyCarriesPinnedConstants(t *testing.T) {
	op, got := bodyEcho(t, opcore.Descriptor{
		Method:       http.MethodPost,
		Path:         "/search",
		Leaf:         "search",
		BodyMappings: []opcore.BodyMapping{{SourcePath: []string{"search_text"}, Target: "query"}},
		FixedBody: map[string]any{
			"contents": map[string]any{"text": true},
			"numimic":  10,
		},
	})
	if _, err := op.Execute(context.Background(), opcore.Args{Body: map[string]any{
		// A caller naming the pinned keys must not reach them, which is the
		// property the whole construct exists for.
		"search_text": "recent umbra releases",
		"contents":    map[string]any{"text": false},
		"numimic":     9999,
	}}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	want := map[string]any{
		"query":    "recent umbra releases",
		"contents": map[string]any{"text": true},
		"numimic":  float64(10),
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("outgoing body = %#v, want %#v", *got, want)
	}
}

// A pin is an object where a mapped value can only be a string, which is the
// half of #311 that `map` alone could not express at all.
func TestExecutePinnedBodyKeepsNonStringShapes(t *testing.T) {
	op, got := bodyEcho(t, opcore.Descriptor{
		Method:       http.MethodPost,
		Path:         "/search",
		Leaf:         "search",
		BodyMappings: []opcore.BodyMapping{{SourcePath: []string{"search_text"}, Target: "query"}},
		FixedBody: map[string]any{
			"livecrawl": "always",
			"enabled":   true,
			"depth":     3,
		},
	})
	if _, err := op.Execute(context.Background(), opcore.Args{
		Body: map[string]any{"search_text": "q"},
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for name, want := range map[string]any{
		"livecrawl": "always",
		"enabled":   true,
		"depth":     float64(3),
	} {
		if (*got)[name] != want {
			t.Errorf("%s = %#v, want %#v", name, (*got)[name], want)
		}
	}
}

// The pins must not become model-facing inputs, or the construct has bought
// nothing over declaring the parameter as a caller field.
func TestPinnedBodyKeysStayOutOfTheInputSchema(t *testing.T) {
	desc := opcore.Descriptor{
		Method:       http.MethodPost,
		Path:         "/search",
		Leaf:         "search",
		BodyMappings: []opcore.BodyMapping{{SourcePath: []string{"search_text"}, Target: "query"}},
		FixedBody:    map[string]any{"contents": map[string]any{"text": true}},
	}
	schema := desc.InputSchema()
	if _, named := schema.Properties["contents"]; named {
		t.Errorf("the pinned key reached the input schema, so the model can name it")
	}
	if _, named := schema.Properties["search_text"]; !named {
		t.Errorf("the mapped source is absent from the input schema: %#v", schema.Properties)
	}
}

// One key cannot be both pinned and mapped: a silent winner is the outcome
// neither an operator nor a reader could predict.
func TestPinnedKeyCollidingWithAMapTargetFailsClosedWithoutFiring(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}))
	defer srv.Close()
	rt := opcore.NewRuntime(opcore.RuntimeConfig{
		BaseURL:   srv.URL,
		Auth:      tokenAuth("s3cret"),
		Providers: valuesource.Merge(nil),
		Client:    srv.Client(),
	})
	op := opcore.Operation{RT: rt, Desc: opcore.Descriptor{
		Method:       http.MethodPost,
		Path:         "/search",
		Leaf:         "search",
		BodyMappings: []opcore.BodyMapping{{SourcePath: []string{"search_text"}, Target: "query"}},
		FixedBody:    map[string]any{"query": "pinned"},
	}}
	_, err := op.Execute(context.Background(), opcore.Args{
		Body: map[string]any{"search_text": "q"},
	})
	if err == nil {
		t.Fatal("a pinned key that a mapping also targets should fail closed")
	}
	if calls != 0 {
		t.Errorf("the request fired %d times before failing closed", calls)
	}
}

// A grant with pins and no mappings is the state toggle, unchanged by #311.
func TestPinnedBodyWithoutMappingsStillSendsPinsAlone(t *testing.T) {
	op, got := bodyEcho(t, opcore.Descriptor{
		Method:    http.MethodPost,
		Path:      "/toggle",
		Leaf:      "close",
		FixedBody: map[string]any{"state": "closed"},
	})
	if _, err := op.Execute(context.Background(), opcore.Args{
		Body: map[string]any{"state": "open"},
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if want := (map[string]any{"state": "closed"}); !reflect.DeepEqual(*got, want) {
		t.Fatalf("outgoing body = %#v, want %#v", *got, want)
	}
}

// The whole #311 shape end to end in guardfile spelling: a colliding required
// parameter renamed through `map`, beside an object constant `set` pins.
func TestInlineMappedBodyWithPinnedObjectReachesTheWire(t *testing.T) {
	src := `wrap ward mcp exa {
        base-url "https://api.exa.ai"
        auth header-token { header "x-api-key"; value env "EXA_API_KEY" }
        can search result {
            path "/search"
            body { map "search_text" to="query" }
            set numResults=5 {
                contents {
                    text #true
                    highlights { numSentences 2 }
                }
                categories "news" "papers"
            }
        }
    }`
	descs, _, err := opcore.ParseInline([]byte(src))
	if err != nil {
		t.Fatalf("ParseInline: %v", err)
	}
	op, got := bodyEcho(t, descs[0])
	if _, err := op.Execute(context.Background(), opcore.Args{Body: map[string]any{
		"search_text": "umbra guardfiles",
		"contents":    "model tries to override",
		"numResults":  999,
	}}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	want := map[string]any{
		"query":      "umbra guardfiles",
		"numResults": float64(5),
		"contents": map[string]any{
			"text":       true,
			"highlights": map[string]any{"numSentences": float64(2)},
		},
		"categories": []any{"news", "papers"},
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("outgoing body = %#v,\n want %#v", *got, want)
	}
}

// A pin block fails closed on the shapes that have no single reading.
func TestInlinePinnedObjectFailsClosed(t *testing.T) {
	cases := map[string]string{
		"value and block":   `set { contents "x" { text #true } }`,
		"key with no value": `set { contents }`,
		"nested key=value":  `set { contents text=#true }`,
		"empty set":         `set`,
		"duplicate key":     `set numResults=1 { numResults 2 }`,
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			src := `wrap x {
                auth bearer { value env "T" }
                can search message { path "/search"; ` + set + ` }
            }`
			_, _, err := opcore.ParseInline([]byte(src))
			if err == nil {
				t.Fatal("an ambiguous or empty pin should fail closed")
			}
			// A KDL syntax error would pass this test while proving nothing
			// about the rule, which is how the case this replaced went vacuous.
			if strings.Contains(err.Error(), "parse KDL") {
				t.Fatalf("failed on KDL syntax rather than the pin rule: %v", err)
			}
			t.Logf("refused with: %v", err)
		})
	}
}

// The Exa case umbra#312 measured: `contents` wants an object, and a mapped
// leaf could only ever send a string, so every call was an upstream 400.
func TestMappedBodyCarriesADeclaredNonStringType(t *testing.T) {
	op, got := bodyEcho(t, opcore.Descriptor{
		Method: http.MethodPost,
		Path:   "/search",
		Leaf:   "search",
		BodyMappings: []opcore.BodyMapping{
			{SourcePath: []string{"search_text"}, Target: "query", Type: "string"},
			{SourcePath: []string{"contents"}, Target: "contents", Type: "object"},
			{SourcePath: []string{"limit"}, Target: "numResults", Type: "integer"},
			{SourcePath: []string{"live"}, Target: "livecrawl", Type: "boolean"},
			{SourcePath: []string{"domains"}, Target: "includeDomains", Type: "array", Items: "string"},
		},
	})
	if _, err := op.Execute(context.Background(), opcore.Args{Body: map[string]any{
		"search_text": "recent umbra releases",
		"contents":    map[string]any{"text": true},
		"limit":       float64(10),
		"live":        true,
		"domains":     []any{"example.com", "example.org"},
	}}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	want := map[string]any{
		"query":          "recent umbra releases",
		"contents":       map[string]any{"text": true},
		"numResults":     float64(10),
		"livecrawl":      true,
		"includeDomains": []any{"example.com", "example.org"},
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("outgoing body = %#v, want %#v", *got, want)
	}
}

// A caller supplying the wrong shape is refused here rather than by the
// upstream, which is the whole point: the 400 was the first and only notice.
func TestMappedBodyRefusesTheWrongShapeWithoutFiring(t *testing.T) {
	cases := map[string]struct {
		mapping opcore.BodyMapping
		value   any
	}{
		"object given a string":    {opcore.BodyMapping{SourcePath: []string{"c"}, Target: "c", Type: "object"}, "text"},
		"integer given a string":   {opcore.BodyMapping{SourcePath: []string{"c"}, Target: "c", Type: "integer"}, "10"},
		"integer given a fraction": {opcore.BodyMapping{SourcePath: []string{"c"}, Target: "c", Type: "integer"}, 1.5},
		"boolean given a string":   {opcore.BodyMapping{SourcePath: []string{"c"}, Target: "c", Type: "boolean"}, "true"},
		"array given an object":    {opcore.BodyMapping{SourcePath: []string{"c"}, Target: "c", Type: "array", Items: "string"}, map[string]any{}},
		"array element mistyped":   {opcore.BodyMapping{SourcePath: []string{"c"}, Target: "c", Type: "array", Items: "integer"}, []any{"nope"}},
		"string given an object":   {opcore.BodyMapping{SourcePath: []string{"c"}, Target: "c", Type: "string"}, map[string]any{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
			defer upstream.Close()
			op := &opcore.Operation{
				Desc: opcore.Descriptor{Method: http.MethodPost, Path: "/search", Leaf: "search", BodyMappings: []opcore.BodyMapping{tc.mapping}},
				RT:   opcore.NewRuntime(opcore.RuntimeConfig{BaseURL: upstream.URL}),
			}
			if _, err := op.Execute(context.Background(), opcore.Args{Body: map[string]any{"c": tc.value}}); err == nil {
				t.Fatal("a mistyped mapped value must be refused")
			}
			if calls != 0 {
				t.Errorf("upstream was called %d times; the refusal must happen before the request", calls)
			}
		})
	}
}

// The tracker shape: a caller fills the declared flags while the guardfile pins
// the argument that arms upstream schema auto-create.
func TestPinnedBodyRidesBesideBodyFlags(t *testing.T) {
	op, got := bodyEcho(t, opcore.Descriptor{
		Method: http.MethodPost,
		Path:   "/record",
		Leaf:   "record",
		BodyFlags: []opcore.Field{
			{Name: "fieldKeyType", Type: "string"},
			{Name: "records", Type: "array", Items: "string", Required: true},
		},
		FixedBody: map[string]any{"typecast": false},
	})
	if _, err := op.Execute(context.Background(), opcore.Args{Body: map[string]any{
		"fieldKeyType": "name",
		"records":      []any{"one"},
		// A caller naming the pinned key must not reach it.
		"typecast": true,
	}}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	want := map[string]any{
		"fieldKeyType": "name",
		"records":      []any{"one"},
		"typecast":     false,
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("outgoing body = %#v, want %#v", *got, want)
	}
}

// Pins buy no leaf out of its own validation: a missing required flag still
// fails closed, and nothing reaches the wire.
func TestPinnedBodyStillEnforcesRequiredFlags(t *testing.T) {
	op, got := bodyEcho(t, opcore.Descriptor{
		Method:    http.MethodPost,
		Path:      "/record",
		Leaf:      "record",
		BodyFlags: []opcore.Field{{Name: "records", Type: "array", Items: "string", Required: true}},
		FixedBody: map[string]any{"typecast": false},
	})
	if _, err := op.Execute(context.Background(), opcore.Args{Body: map[string]any{
		"fieldKeyType": "name",
	}}); err == nil {
		t.Fatal("a missing required body flag should fail closed")
	}
	if len(*got) != 0 {
		t.Errorf("body reached the wire: %#v", *got)
	}
}
