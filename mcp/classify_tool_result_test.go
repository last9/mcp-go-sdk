package mcp

import (
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
