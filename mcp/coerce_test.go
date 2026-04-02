package mcp

import (
	"encoding/json"
	"reflect"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── register ────────────────────────────────────────────────────────────────

type sampleArgs struct {
	Service         string `json:"service"`
	LookbackMinutes int    `json:"lookback_minutes,omitempty"`
	Limit           int    `json:"limit,omitempty"`
	Verbose         bool   `json:"verbose"`
	Rate            float64 `json:"rate"`
	ignored         string // unexported — must be skipped
}

func TestRegister_RecordsNonStringScalars(t *testing.T) {
	r := newToolTypeRegistry()
	register[sampleArgs](r, "test_tool")

	fields, ok := r.fields["test_tool"]
	if !ok {
		t.Fatal("expected test_tool to be registered")
	}

	want := map[string]reflect.Kind{
		"lookback_minutes": reflect.Int,
		"limit":            reflect.Int,
		"verbose":          reflect.Bool,
		"rate":             reflect.Float64,
	}

	for name, kind := range want {
		got, ok := fields[name]
		if !ok {
			t.Errorf("field %q not registered", name)
			continue
		}
		if got != kind {
			t.Errorf("field %q: got kind %v, want %v", name, got, kind)
		}
	}

	// string fields must NOT be registered
	if _, ok := fields["service"]; ok {
		t.Error("string field 'service' should not be registered")
	}
}

func TestRegister_SkipsNonStructTypes(t *testing.T) {
	r := newToolTypeRegistry()
	register[map[string]any](r, "map_tool")

	if _, ok := r.fields["map_tool"]; ok {
		t.Error("non-struct type should not be registered")
	}
}

func TestRegister_HandlesPointerFields(t *testing.T) {
	type ptrArgs struct {
		Count *int `json:"count"`
	}
	r := newToolTypeRegistry()
	register[ptrArgs](r, "ptr_tool")

	fields, ok := r.fields["ptr_tool"]
	if !ok {
		t.Fatal("expected ptr_tool to be registered")
	}
	if fields["count"] != reflect.Int {
		t.Errorf("pointer-to-int field: got kind %v, want Int", fields["count"])
	}
}

// ── coerceArgs ──────────────────────────────────────────────────────────────

func makeCallToolRequest(toolName string, argsJSON string) *sdkmcp.CallToolRequest {
	return &sdkmcp.CallToolRequest{
		Params: &sdkmcp.CallToolParamsRaw{
			Name:      toolName,
			Arguments: json.RawMessage(argsJSON),
		},
	}
}

func TestCoerceArgs_StringToInt(t *testing.T) {
	r := newToolTypeRegistry()
	register[sampleArgs](r, "get_logs")

	ctr := makeCallToolRequest("get_logs", `{"service":"api","lookback_minutes":"60","limit":"20"}`)
	r.coerceArgs(ctr)

	raw := ctr.Params.Arguments
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	if v, ok := m["lookback_minutes"].(float64); !ok || v != 60 {
		t.Errorf("lookback_minutes: got %v (%T), want 60 (float64)", m["lookback_minutes"], m["lookback_minutes"])
	}
	if v, ok := m["limit"].(float64); !ok || v != 20 {
		t.Errorf("limit: got %v (%T), want 20 (float64)", m["limit"], m["limit"])
	}
	if v := m["service"]; v != "api" {
		t.Errorf("service: got %v, want 'api'", v)
	}
}

func TestCoerceArgs_StringToBool(t *testing.T) {
	r := newToolTypeRegistry()
	register[sampleArgs](r, "test_tool")

	ctr := makeCallToolRequest("test_tool", `{"service":"x","verbose":"true"}`)
	r.coerceArgs(ctr)

	raw := ctr.Params.Arguments
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	if v, ok := m["verbose"].(bool); !ok || v != true {
		t.Errorf("verbose: got %v (%T), want true (bool)", m["verbose"], m["verbose"])
	}
}

func TestCoerceArgs_StringToFloat(t *testing.T) {
	r := newToolTypeRegistry()
	register[sampleArgs](r, "test_tool")

	ctr := makeCallToolRequest("test_tool", `{"service":"x","rate":"1.5"}`)
	r.coerceArgs(ctr)

	raw := ctr.Params.Arguments
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	if v, ok := m["rate"].(float64); !ok || v != 1.5 {
		t.Errorf("rate: got %v (%T), want 1.5 (float64)", m["rate"], m["rate"])
	}
}

func TestCoerceArgs_NoOpWhenTypesCorrect(t *testing.T) {
	r := newToolTypeRegistry()
	register[sampleArgs](r, "test_tool")

	original := `{"service":"api","lookback_minutes":60,"verbose":true,"rate":1.5}`
	ctr := makeCallToolRequest("test_tool", original)
	r.coerceArgs(ctr)

	raw := ctr.Params.Arguments
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["lookback_minutes"].(float64); !ok || v != 60 {
		t.Errorf("lookback_minutes: got %v, want 60", m["lookback_minutes"])
	}
}

func TestCoerceArgs_NoOpForUnregisteredTool(t *testing.T) {
	r := newToolTypeRegistry()
	// Don't register anything

	original := `{"lookback_minutes":"60"}`
	ctr := makeCallToolRequest("unknown_tool", original)
	r.coerceArgs(ctr)

	raw := ctr.Params.Arguments
	if string(raw) != original {
		t.Errorf("arguments were modified for unregistered tool: got %s", raw)
	}
}

func TestCoerceArgs_InvalidStringNotCoerced(t *testing.T) {
	r := newToolTypeRegistry()
	register[sampleArgs](r, "test_tool")

	ctr := makeCallToolRequest("test_tool", `{"service":"x","lookback_minutes":"abc"}`)
	r.coerceArgs(ctr)

	raw := ctr.Params.Arguments
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	if _, ok := m["lookback_minutes"].(string); !ok {
		t.Errorf("unparseable string should remain a string, got %T", m["lookback_minutes"])
	}
}

func TestCoerceArgs_BoolOnlyExactStrings(t *testing.T) {
	r := newToolTypeRegistry()
	register[sampleArgs](r, "test_tool")

	ctr := makeCallToolRequest("test_tool", `{"service":"x","verbose":"yes"}`)
	r.coerceArgs(ctr)

	raw := ctr.Params.Arguments
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	if _, ok := m["verbose"].(string); !ok {
		t.Errorf("'yes' should not be coerced to bool, got %T", m["verbose"])
	}
}

func TestCoerceArgs_NilArguments(t *testing.T) {
	r := newToolTypeRegistry()
	register[sampleArgs](r, "test_tool")

	ctr := &sdkmcp.CallToolRequest{
		Params: &sdkmcp.CallToolParamsRaw{
			Name:      "test_tool",
			Arguments: nil,
		},
	}

	r.coerceArgs(ctr)
}

// ── jsonFieldName ───────────────────────────────────────────────────────────

func TestJsonFieldName_Tag(t *testing.T) {
	type s struct {
		Foo int `json:"bar"`
	}
	f, _ := reflect.TypeOf(s{}).FieldByName("Foo")
	if got := jsonFieldName(f); got != "bar" {
		t.Errorf("got %q, want %q", got, "bar")
	}
}

func TestJsonFieldName_TagWithOmitempty(t *testing.T) {
	type s struct {
		Foo int `json:"baz,omitempty"`
	}
	f, _ := reflect.TypeOf(s{}).FieldByName("Foo")
	if got := jsonFieldName(f); got != "baz" {
		t.Errorf("got %q, want %q", got, "baz")
	}
}

func TestJsonFieldName_NoTag(t *testing.T) {
	type s struct {
		Foo int
	}
	f, _ := reflect.TypeOf(s{}).FieldByName("Foo")
	if got := jsonFieldName(f); got != "Foo" {
		t.Errorf("got %q, want %q", got, "Foo")
	}
}

func TestJsonFieldName_DashTag(t *testing.T) {
	type s struct {
		Foo int `json:"-"`
	}
	f, _ := reflect.TypeOf(s{}).FieldByName("Foo")
	if got := jsonFieldName(f); got != "-" {
		t.Errorf("got %q, want %q", got, "-")
	}
}
