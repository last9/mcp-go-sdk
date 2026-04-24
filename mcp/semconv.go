package mcp

import "go.opentelemetry.io/otel/attribute"

// Semantic convention attribute keys.
//
// gen_ai.* keys follow the OpenTelemetry GenAI semantic conventions:
// https://opentelemetry.io/docs/specs/semconv/gen-ai/
//
// mcp.* keys are MCP-specific extensions that mirror and extend the GenAI
// conventions with protocol-level detail.
var (
	// GenAI standard keys
	keyGenAISystem        = attribute.Key("gen_ai.system")
	keyGenAIOperationName = attribute.Key("gen_ai.operation.name")
	keyGenAIToolName      = attribute.Key("gen_ai.tool.name")
	keyGenAIToolCallID    = attribute.Key("gen_ai.tool.call.id")
	keyGenAIRequestModel  = attribute.Key("gen_ai.request.model")

	// MCP server identity
	keyMCPServerName      = attribute.Key("mcp.server.name")
	keyMCPServerVersion   = attribute.Key("mcp.server.version")
	keyMCPServerTransport = attribute.Key("mcp.server.transport")

	// MCP client identity
	keyMCPClientName    = attribute.Key("mcp.client.name")
	keyMCPClientVersion = attribute.Key("mcp.client.version")
	keyMCPClientID      = attribute.Key("mcp.client.id")

	// MCP session
	keyMCPSessionID = attribute.Key("mcp.session.id")

	// MCP tool
	keyMCPToolName   = attribute.Key("mcp.tool.name")
	keyMCPToolCallID = attribute.Key("mcp.tool.call.id")

	// MCP resource
	keyMCPResourceURI  = attribute.Key("mcp.resource.uri")
	keyMCPResourceName = attribute.Key("mcp.resource.name")

	// MCP prompt
	keyMCPPromptName = attribute.Key("mcp.prompt.name")

	// MCP sampling
	keyMCPSamplingModel = attribute.Key("mcp.sampling.model")

	// MCP operation result
	keyMCPOperationStatus = attribute.Key("mcp.operation.status")
	keyMCPErrorType       = attribute.Key("mcp.error.type")
	keyMCPErrorMessage    = attribute.Key("mcp.error.message")
)

// gen_ai.system value for MCP.
const genAISystem = "mcp"

// MCP method strings as received in the receiving middleware.
const (
	opToolsCall          = "tools/call"
	opToolsList          = "tools/list"
	opResourcesRead  = "resources/read"
	opResourcesList  = "resources/list"
	opPromptsGet     = "prompts/get"
	opPromptsList        = "prompts/list"
	opSamplingCreate     = "sampling/createMessage"
	opCompletionComplete = "completion/complete"
	opInitialize         = "initialize"
	opPing               = "ping"
)

// Error type values for mcp.error.type dimension.
const (
	errTypeUser   = "user_error"
	errTypeSystem = "system_error"
)

// Status values for mcp.operation.status dimension.
const (
	statusSuccess = "success"
	statusError   = "error"
)

// spanName returns the canonical OTel span name "mcp {operation}".
func spanName(operation string) string { return "mcp " + operation }

// toolSpanName returns the canonical span name "mcp tools/call {tool_name}".
func toolSpanName(name string) string { return "mcp tools/call " + name }

// promptGetSpanName returns the canonical span name "mcp prompts/get {prompt_name}".
func promptGetSpanName(name string) string { return "mcp prompts/get " + name }
