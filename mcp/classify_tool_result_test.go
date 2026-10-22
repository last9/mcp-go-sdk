package mcp

import (
	"encoding/json"
	"errors"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestClassifyToolResult(t *testing.T) {
	tests := []struct {
		name        string
		result      sdkmcp.Result
		err         error
		wantSuccess bool
		wantType    string
		wantMsg     string
	}{
		{"success", &sdkmcp.CallToolResult{}, nil, true, "", ""},
		{"returned error", nil, errors.New("connection reset"), false, errTypeSystem, "connection reset"},
		{"IsError with text", &sdkmcp.CallToolResult{IsError: true,
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "city not found"}}},
			nil, false, errTypeUser, "city not found"},
		{"IsError with no content", &sdkmcp.CallToolResult{IsError: true},
			nil, false, errTypeUser, ""},
		{"IsError with text after non-text content", &sdkmcp.CallToolResult{IsError: true,
			Content: []sdkmcp.Content{&sdkmcp.ImageContent{MIMEType: "image/png"}, &sdkmcp.TextContent{Text: "render failed"}}},
			nil, false, errTypeUser, "render failed"},
		{"IsError with only non-text content", &sdkmcp.CallToolResult{IsError: true,
			Content: []sdkmcp.Content{&sdkmcp.ImageContent{MIMEType: "image/png"}}},
			nil, false, errTypeUser, ""},
		{"IsError tagged system", &sdkmcp.CallToolResult{IsError: true,
			Meta:    sdkmcp.Meta{"last9/error-type": "system_error"},
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "upstream timeout"}}},
			nil, false, errTypeSystem, "upstream timeout"},
		{"IsError tagged user", &sdkmcp.CallToolResult{IsError: true,
			Meta: sdkmcp.Meta{"last9/error-type": "user_error"}},
			nil, false, errTypeUser, ""},
		{"IsError with unknown tag", &sdkmcp.CallToolResult{IsError: true,
			Meta: sdkmcp.Meta{"last9/error-type": "System_Error"}},
			nil, false, errTypeUser, ""},
		{"IsError with non-string tag", &sdkmcp.CallToolResult{IsError: true,
			Meta: sdkmcp.Meta{"last9/error-type": true}},
			nil, false, errTypeUser, ""},
		{"IsError with unrelated meta", &sdkmcp.CallToolResult{IsError: true,
			Meta: sdkmcp.Meta{"error_type": "system_error"}},
			nil, false, errTypeUser, ""},
		{"SystemErrorResult", SystemErrorResult("upstream returned 503"),
			nil, false, errTypeSystem, "upstream returned 503"},
		{"success tagged system", &sdkmcp.CallToolResult{
			Meta: sdkmcp.Meta{"last9/error-type": "system_error"}},
			nil, true, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			success, errType, errMsg := classifyToolResult(tc.result, tc.err)
			if success != tc.wantSuccess || errType != tc.wantType || errMsg != tc.wantMsg {
				t.Errorf("got (%v, %q, %q), want (%v, %q, %q)",
					success, errType, errMsg, tc.wantSuccess, tc.wantType, tc.wantMsg)
			}
		})
	}
}

// The tag must survive the wire so instrumented clients classify the same way.
func TestSystemErrorResult_SurvivesJSONRoundTrip(t *testing.T) {
	data, err := json.Marshal(SystemErrorResult("upstream timeout"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got sdkmcp.CallToolResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, errType, _ := classifyToolResult(&got, nil); errType != errTypeSystem {
		t.Errorf("errType after round trip: got %q, want %q (wire: %s)", errType, errTypeSystem, data)
	}
}
