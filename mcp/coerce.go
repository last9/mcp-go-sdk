package mcp

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"sync"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// toolTypeRegistry maps tool name → JSON field name → expected Go reflect.Kind.
// Only non-string scalar types (int*, uint*, float*, bool) are stored — string
// fields need no coercion and are omitted to avoid false positives.
type toolTypeRegistry struct {
	mu     sync.RWMutex
	fields map[string]map[string]reflect.Kind // toolName -> jsonField -> kind
}

func newToolTypeRegistry() *toolTypeRegistry {
	return &toolTypeRegistry{fields: make(map[string]map[string]reflect.Kind)}
}

// register extracts the JSON field names and their Go kinds from the struct
// type In and stores non-string scalars for the given tool name.
func register[In any](r *toolTypeRegistry, toolName string) {
	t := reflect.TypeFor[In]()
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}

	m := make(map[string]reflect.Kind)
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}

		name := jsonFieldName(f)
		if name == "-" {
			continue
		}

		kind := f.Type.Kind()
		if kind == reflect.Ptr {
			kind = f.Type.Elem().Kind()
		}

		switch kind {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			m[name] = kind
		case reflect.Float32, reflect.Float64:
			m[name] = kind
		case reflect.Bool:
			m[name] = kind
		}
	}

	if len(m) == 0 {
		return
	}

	r.mu.Lock()
	r.fields[toolName] = m
	r.mu.Unlock()
}

// jsonFieldName returns the JSON key for a struct field, respecting the `json`
// tag. Falls back to the Go field name when no tag is set.
func jsonFieldName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" {
		return f.Name
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return f.Name
	}
	return name
}

// coerceArgs rewrites the raw JSON arguments of a CallToolRequest in place,
// converting string values to their schema-expected types (int, float, bool).
// It is a no-op when no registered fields need coercion or the arguments cannot
// be parsed.
//
// Arguments is typed `any` in CallToolParams but holds a json.RawMessage after
// the SDK unmarshals the wire JSON (see CallToolParams.UnmarshalJSON).
func (r *toolTypeRegistry) coerceArgs(ctr *sdkmcp.CallToolRequest) {
	if ctr.Params == nil || ctr.Params.Arguments == nil {
		return
	}

	r.mu.RLock()
	fieldKinds, ok := r.fields[ctr.Params.Name]
	r.mu.RUnlock()
	if !ok || len(fieldKinds) == 0 {
		return
	}

	raw, ok := ctr.Params.Arguments.(json.RawMessage)
	if !ok {
		return
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return
	}

	changed := false
	for field, kind := range fieldKinds {
		val, exists := m[field]
		if !exists {
			continue
		}
		str, isStr := val.(string)
		if !isStr {
			continue
		}

		switch {
		case isIntKind(kind):
			if n, err := strconv.ParseInt(str, 10, 64); err == nil {
				m[field] = n
				changed = true
			}
		case isUintKind(kind):
			if n, err := strconv.ParseUint(str, 10, 64); err == nil {
				m[field] = n
				changed = true
			}
		case isFloatKind(kind):
			if f, err := strconv.ParseFloat(str, 64); err == nil {
				m[field] = f
				changed = true
			}
		case kind == reflect.Bool:
			switch strings.ToLower(str) {
			case "true":
				m[field] = true
				changed = true
			case "false":
				m[field] = false
				changed = true
			}
		}
	}

	if !changed {
		return
	}

	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	ctr.Params.Arguments = json.RawMessage(data)
}

func isIntKind(k reflect.Kind) bool {
	return k == reflect.Int || k == reflect.Int8 || k == reflect.Int16 || k == reflect.Int32 || k == reflect.Int64
}

func isUintKind(k reflect.Kind) bool {
	return k == reflect.Uint || k == reflect.Uint8 || k == reflect.Uint16 || k == reflect.Uint32 || k == reflect.Uint64
}

func isFloatKind(k reflect.Kind) bool {
	return k == reflect.Float32 || k == reflect.Float64
}
