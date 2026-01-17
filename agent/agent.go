// Copyright (c) 2025 AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	"tailscale.com/syncs"
	"tailscale.com/types/logger"
	"tailscale.com/util/backoff"
	"tailscale.com/util/ctxkey"
)

//go:generate go run tailscale.com/cmd/cloner  -clonefunc=false -type=Message,MessageContent,ToolUse,ToolResult,CacheControl,Usage,MessagesRequest,MessagesResponse,ToolChoice,ToolDefinition,Tool

// Standard error types for agent operations
var (
	// ErrTooLarge indicates the request exceeds size limits
	ErrTooLarge = errors.New("request too large")

	// ErrOverloaded indicates the service is temporarily overloaded
	ErrOverloaded = errors.New("service overloaded")

	// ErrRemoteServerError indicates a remote server failure
	ErrRemoteServerError = errors.New("server error")

	// ErrRateLimit indicates rate limiting by the service
	ErrRateLimit = errors.New("rate limit exceeded")

	// ErrMaxToolIterations indicates the maximum number of tool iterations was reached
	ErrMaxToolIterations = errors.New("max tool iterations reached")

	// ErrTerminateLoop is a sentinel error that indicates that the agent should terminate the loop.
	ErrTerminateLoop = errors.New("terminate loop")
)

// RateLimitError represents a rate limiting error from an LLM service.
// It includes information about when to retry the request.
type RateLimitError struct {
	// RetryAfter indicates how long to wait before retrying the request
	RetryAfter time.Duration
	// Err is the underlying error, typically wrapping ErrRateLimit
	Err error
}

// Error implements the error interface and provides a formatted error message
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limit exceeded, retry after %v: %v", e.RetryAfter, e.Err)
}

// Unwrap implements the errors.Unwrap interface to allow errors.Is/As checking
func (e *RateLimitError) Unwrap() error {
	return e.Err
}

// ContentType defines the type of content in a message
type ContentType string

// Content types for message content
const (
	// ContentTypeText represents plain text content
	ContentTypeText ContentType = "text"

	// ContentTypeToolUse represents a tool being used
	ContentTypeToolUse ContentType = "tool_use"

	// ContentTypeToolResult represents the results of a tool execution
	ContentTypeToolResult ContentType = "tool_result"

	// ContentTypeThinking represents thinking/reasoning content (for Claude Sonnet)
	ContentTypeThinking ContentType = "thinking"

	// ContentTypeRedactedThinking represents redacted thinking content
	ContentTypeRedactedThinking ContentType = "redacted_thinking"

	// ContentTypeImage represents an image
	ContentTypeImage ContentType = "image"
)

// Cache control type constants
const (
	// CacheControlTypeEphemeral indicates content should be cached but not stored permanently
	CacheControlTypeEphemeral = "ephemeral"
)

type Role string

// Message role constants
const (
	// RoleSystem represents a system message that guides the AI's behavior
	RoleSystem Role = "system"

	// RoleUser represents a message from the user
	RoleUser Role = "user"

	// RoleAssistant represents a message from the AI assistant
	RoleAssistant Role = "assistant"

	// RoleTool represents a message from a tool execution
	RoleTool Role = "tool"
)

// Message represents a chat message in a conversation with an LLM.
// It contains the role of the sender (system, user, assistant, or tool)
// and one or more content blocks that can have different types (text, tool use, etc.).
type Message struct {
	Role    Role    `json:"role"`    // Role of the message sender (e.g. "user", "assistant")
	Content Content `json:"content"` // Content blocks for the message
}

type Content []MessageContent

// LossyText returns just the text content of the message content.
// It is lossy because it may lose things like images, thinking, tool use, etc.
func (c Content) LossyText() string {
	if len(c) == 0 {
		return ""
	}
	if len(c) == 1 {
		if c[0].Type == ContentTypeText {
			return c[0].Text
		}
		return ""
	}
	var out strings.Builder
	for _, c := range c {
		switch c.Type {
		case ContentTypeText:
			out.WriteString(c.Text)
		}
	}
	if out.Len() == 0 {
		return ""
	}
	return out.String()
}

// MessageContent represents different types of content that can appear in a message.
// The Type field determines which other fields are populated and used.
type MessageContent struct {
	// Type indicates the kind of content (text, tool_use, tool_result, thinking, etc.)
	Type ContentType `json:"type"`

	// Thinking contains the reasoning/thinking content when Type is ContentTypeThinking
	// This is primarily used with Claude Sonnet and other models supporting thinking chains
	Thinking string `json:"thinking,omitempty"`

	// Signature contains a cryptographic signature for the thinking block when used
	Signature string `json:"signature,omitempty"`

	// MediaType is used to specify what type of image is being sent.
	// Available types are "image/png", "image/jpeg", "image/webp", and "image/gif".
	MediaType string `json:"media_type,omitempty"`

	// Data contains base64 encoded data when Type is ContentTypeImage.
	Data json.RawMessage `json:"data,omitempty"`

	// RedactedThinking contains the redacted thinking content when Type is ContentTypeRedactedThinking
	RedactedThinking string `json:"redacted_thinking,omitempty"`

	// Text contains the plain text content when Type is ContentTypeText
	Text string `json:"text,omitempty"`

	// ToolUse contains tool use information when Type is ContentTypeToolUse
	ToolUse *ToolUse `json:"tool_use,omitempty"`

	// ToolResults contains tool execution results when Type is ContentTypeToolResult
	ToolResults *ToolResult `json:"tool_results,omitempty"`

	// CacheControl contains optional caching directives for this content
	CacheControl *CacheControl `json:"cache_control,omitempty"`
}

// NewTextContent creates a new text content
func NewTextContent(text string) MessageContent {
	return MessageContent{
		Type: ContentTypeText,
		Text: text,
	}
}

// NewImageContent creates a new image content with base64 encoded data
func NewImageContent(mediaType string, base64Data string) MessageContent {
	return MessageContent{
		Type:      ContentTypeImage,
		MediaType: mediaType,
		Data:      json.RawMessage(`"` + base64Data + `"`),
	}
}

// NewToolUseContent creates a new tool use content
func NewToolUseContent(id, name string, input json.RawMessage) MessageContent {
	return MessageContent{
		Type: ContentTypeToolUse,
		ToolUse: &ToolUse{
			ID:    id,
			Name:  name,
			Input: input,
		},
	}
}

// NewToolResultContent creates a new tool result content
func NewToolResultContent(name, toolCallID, output string, isError bool) MessageContent {
	return MessageContent{
		Type: ContentTypeToolResult,
		ToolResults: &ToolResult{
			Name:       name,
			ToolCallID: toolCallID,
			Output:     output,
			Error:      isError,
		},
	}
}

// GetText returns the text content of the message
func (c *MessageContent) GetText() string {
	switch c.Type {
	case ContentTypeText:
		return c.Text
	case ContentTypeToolUse:
		if c.ToolUse != nil {
			return fmt.Sprintf("Tool use: %s", c.ToolUse.Name)
		}
	case ContentTypeToolResult:
		if c.ToolResults != nil {
			return fmt.Sprintf("Tool results: %s", c.ToolResults.Output)
		}
	}
	return ""
}

// ToolUse represents a tool being invoked by the LLM during a conversation.
// It contains the necessary information to identify and execute a specific tool
// with the provided input parameters.
type ToolUse struct {
	ID    string          `json:"id"`    // Unique identifier for this tool use
	Name  string          `json:"name"`  // Name of the tool
	Input json.RawMessage `json:"input"` // Input parameters for the tool
}

// ToolResult represents the results of a tool execution.
// It contains the output from executing a tool, along with information about
// whether the execution resulted in an error.
type ToolResult struct {
	Name       string `json:"tool_name"`    // Name of the tool
	ToolCallID string `json:"tool_call_id"` // ID of the tool call these results are for
	Output     string `json:"output"`       // Output from the tool
	Error      bool   `json:"error"`        // Whether this output represents an error
}

// CacheControl represents caching directives for message content.
// It defines how a message should be cached by the LLM provider to optimize
// token usage and response times in subsequent interactions.
type CacheControl struct {
	Type string `json:"type"` // Type of cache control (e.g. "ephemeral")
}

// Usage represents token usage statistics
type Usage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
}

// LLMClient represents a client that can process messages and return responses.
// Implementations must handle:
//
//   - Rate limiting: Return ErrRateLimit wrapped in a RateLimitError containing retry duration.
//     Example: return &RateLimitError{RetryAfter: 30 * time.Second, Err: fmt.Errorf("%w: %v", ErrRateLimit, err)}
//
//   - Context cancellation: Respect context cancellation and return ctx.Err() directly.
//     Example: if ctx.Err() != nil { return MessagesResponse{}, ctx.Err() }
//
//   - Request size limits: Return ErrTooLarge wrapped with additional context.
//     Example: return MessagesResponse{}, fmt.Errorf("%w: request exceeds size limit", ErrTooLarge)
//
//   - Service overload: Return ErrOverloaded wrapped with additional context.
//     Example: return MessagesResponse{}, fmt.Errorf("%w: service temporarily unavailable", ErrOverloaded)
//
//   - Message conversion: Convert between implementation-specific and agent message types
//     while preserving all required fields and maintaining proper JSON serialization.
//
//   - Token counting: Track and report token usage accurately in Usage struct.
//
// The interface is designed to be implementation-agnostic, allowing different
// LLM providers to be used interchangeably. Implementations must properly wrap
// their native errors using the defined error types to ensure consistent error
// handling across different providers.
type LLMClient interface {
	// CreateMessages sends a request to the LLM and returns the response.
	// It must handle rate limiting, context cancellation, and other errors
	// as specified above. All provider-specific errors must be wrapped using
	// the appropriate error types defined in this package.
	//
	// If onUpdate is provided, it will be called with incremental updates as the
	// response is generated (streaming). The callback receives the full accumulated
	// response for each update. If nil, the method behaves non-streaming.
	CreateMessages(ctx context.Context, req MessagesRequest, onUpdate func(MessagesResponse)) (MessagesResponse, error)
}

// TokenCounter is an optional interface that can be implemented by an LLMClient
// to estimate the token usage and cost of a request before sending it to the LLM service.
// This allows for pre-flight checks on token limits and cost estimations.
type TokenCounter interface {
	// CountTokens analyzes the request and returns the estimated number of tokens it would use.
	// This is useful for:
	// 1. Estimating costs before making expensive API calls
	// 2. Preventing requests that would exceed token limits
	// 3. Optimizing prompts by analyzing token usage
	//
	// If the implementation cannot count tokens accurately, it should return an error.
	CountTokens(ctx context.Context, req MessagesRequest) (int, error)
}

// MessagesRequest represents a request to create messages through an LLM service.
// It contains all the necessary information to generate a response, including
// the conversation history, available tools, and configuration parameters.
//
// This struct serves as the primary input to LLMClient.CreateMessages() and encapsulates
// everything needed to generate an AI response, whether using tools or just text.
// The fields control both what content the LLM considers and how it should respond.
type MessagesRequest struct {
	// System is the system prompt that guides the LLM's behavior.
	// This provides high-level instructions to the model about its role and constraints.
	System string `json:"system"`

	// MaxTokens limits the number of tokens the LLM can generate in its response.
	// A value of 0 means the default model limit will be used.
	MaxTokens int `json:"max_tokens"`

	// Messages contains the conversation history in chronological order.
	// This includes previous user messages, assistant responses, and tool interactions.
	Messages []Message `json:"messages"`

	// Tools defines the tools available for the LLM to use in its response.
	// These are presented to the model as capabilities it can invoke.
	Tools []ToolDefinition `json:"tools"`

	// ToolChoice specifies how tools should be chosen:
	// - If nil or Type="auto": Let the LLM decide which tool to use (if any)
	// - If Type="tool" and Name is set: Force the LLM to use that specific tool
	// - If Type="any": Force the LLM to use any tool (implementation-specific)
	ToolChoice *ToolChoice `json:"tool_choice,omitempty"`

	// ThinkingMode enables the LLM to show its reasoning process.
	// This is only supported by certain models (e.g., Claude Sonnet).
	// The provider should ignore this field if it does not support it.
	ThinkingMode bool `json:"thinking_mode,omitempty"`

	// ThinkingTokens specifies how many tokens to allocate for thinking/reasoning.
	// Only applies when ThinkingMode is true. A value of 0 means the default (typically 1024).
	// The provider should ignore this field if it does not support ThinkingMode.
	ThinkingTokens int `json:"thinking_tokens,omitempty"`
}

// MessagesResponse represents a response from creating messages via an LLM service.
// It contains the generated content from the model along with usage statistics
// for token consumption and caching metrics.
type MessagesResponse struct {
	// ID is the ID of the response.
	ID string `json:"id"`

	// StopReason is the reason the LLM stopped generating content.
	StopReason string `json:"stop_reason"`

	// Content contains the actual response content from the LLM,
	// which may include text, tool calls, or other content types.
	// The format of this content matches the MessageContent struct and can
	// contain multiple types of responses in a single message.
	Content Content `json:"content"`

	// Usage provides statistics about token consumption and caching metrics
	// from the LLM service, including input, output, and cache-related tokens.
	Usage Usage `json:"usage"`

	// TimeToFirstToken is the time it took for the first token to be generated.
	TimeToFirstToken time.Duration `json:"time_to_first_token"`

	// ResponseTime is the total time it took for the response to be generated.
	ResponseTime time.Duration `json:"response_time"`
}

// ToolChoice specifies how an LLM should choose tools during a conversation.
// It controls whether the LLM automatically selects appropriate tools
// or if it should be directed to use a specific named tool.
//
// This struct is used in MessagesRequest to guide tool selection behavior,
// allowing for both autonomous tool selection by the LLM and forced usage
// of specific tools when needed for deterministic behavior.
type ToolChoice struct {
	// Type determines the tool selection strategy:
	// - "auto": Let the LLM decide which tool to use (if any)
	// - "tool": Force the LLM to use the specific tool named in the Name field
	// - "any": Force the LLM to use any tool (implementation-specific behavior)
	Type string `json:"type"`

	// Name is the specific tool name to use when Type is "tool".
	// This field is required when Type is "tool" and ignored otherwise.
	Name string `json:"name"`
}

// ToolDefinition represents the definition of a tool that can be provided to an LLM.
// It contains the metadata needed for the LLM to understand the tool's purpose
// and how to properly invoke it with correct parameters.
type ToolDefinition struct {
	Name        string          `json:"name"`         // Name of the tool
	Description string          `json:"description"`  // Human-readable description of what the tool does
	InputSchema json.RawMessage `json:"input_schema"` // JSON schema describing the input parameters
}

// ToolSpec defines a content tool with a user-visible summary for better UX
type ToolSpec[T any] struct {
	Name        string              // Name of the tool
	Description string              // Full description for the LLM
	Summary     func(args T) string // Function to generate a summary of the tool invocation
	Handler     ToolHandler[T]      // The handler function for the tool
}

type Tool struct {
	// Name is the name of the tool.
	Name string
	// Desc is the description of the tool.
	Desc string
	// summary is a function that generates a short user-visible summary of a specific tool invocation.
	// It takes the raw JSON input and returns a human-readable summary of what the tool will do.
	summary func(inputJSON json.RawMessage) string
	// Schema is the JSON schema for the tool's input.
	Schema string

	// Handler is the function that will be called when the tool is used. It
	// must be set.
	Handler toolUseHandler
}

func (t *Tool) Summary(inputJSON json.RawMessage) string {
	if t.summary == nil {
		return t.Name
	}
	return t.summary(inputJSON)
}

var jsonSchemaCache syncs.Map[reflect.Type, string]

func NewTool[T any](name, desc string, handler ToolHandler[T]) *Tool {
	schema, _ := jsonSchemaCache.LoadOrInit(reflect.TypeFor[T](), func() string {
		return JSONSchema[T]()
	})
	return &Tool{
		Name:    name,
		Desc:    desc,
		Schema:  schema,
		Handler: handler.Handle,
	}
}

// NewToolFromSpec creates a new content tool from a ContentToolSpec with a user-visible summary
func NewToolFromSpec[T any](spec ToolSpec[T]) *Tool {
	schema, _ := jsonSchemaCache.LoadOrInit(reflect.TypeFor[T](), func() string {
		return JSONSchema[T]()
	})
	// Create a summary function that unmarshals JSON and calls the spec summary
	var summaryFunc func(json.RawMessage) string
	if spec.Summary != nil {
		summaryFunc = func(inputJSON json.RawMessage) string {
			var args T
			if err := json.Unmarshal(inputJSON, &args); err != nil {
				return fmt.Sprintf("%s: invalid input", spec.Name)
			}
			return spec.Summary(args)
		}
	}
	return &Tool{
		Name:    spec.Name,
		Desc:    spec.Description,
		summary: summaryFunc,
		Schema:  schema,
		Handler: spec.Handler.Handle,
	}
}

var toolIDContextKey = ctxkey.New("toolID", "")

// ToolCallID returns the ID of the tool call that is currently being executed.
func ToolCallID(ctx context.Context) (string, bool) {
	return toolIDContextKey.ValueOk(ctx)
}

// toolUseHandler is a function type that processes tool execution requests.
// It accepts a context and raw JSON input, and returns a string response or an error.
//
// The inputJSON parameter contains the tool's input parameters as provided by the LLM.
// The returned string should be the formatted result that will be sent back to the LLM.
// If an error is returned, it will be formatted and sent to the LLM as an error message.
type toolUseHandler func(ctx context.Context, toolUse *ToolUse) (string, []MessageContent, error)

// ToolHandler is a type-safe version of ToolHandler that works with a specific request type.
// It handles type conversion and validation automatically when used with JSONHandler.
// The Req type parameter defines the structure expected for the tool's input parameters.
//
// This allows for type-safe tool implementations with automatic schema validation
// based on the Go type system. It's the preferred way to implement new tools.
type ToolHandler[Req any] func(ctx context.Context, req Req) (string, []MessageContent, error)

func (h ToolHandler[Req]) Handle(ctx context.Context, toolUse *ToolUse) (string, []MessageContent, error) {
	var req Req
	if err := json.Unmarshal(toolUse.Input, &req); err != nil {
		return "", nil, err
	}
	ctx = toolIDContextKey.WithValue(ctx, toolUse.ID)
	return h(ctx, req)
}

type Agent struct {
	opts  Opts
	usage Usage
}

func asJSONPretty(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func JSONSchema[T any]() string {
	rt := jsonschema.Reflector{
		DoNotReference: true,
		BaseSchemaID:   "agents",
	}
	return asJSON(rt.ReflectFromType(reflect.TypeFor[T]()))
}

// Opts defines the configuration options for creating a new Agent.
// It controls the agent's behavior, capabilities, and integration with LLM services.
type Opts struct {
	// Name is the unique identifier for this agent instance.
	// It is only used for logging and metrics.
	Name string

	// SystemPrompt is the system instruction that guides the LLM's behavior.
	// Required - must be non-empty.
	SystemPrompt string

	// Client is the LLM service implementation to use for generating responses.
	// Required - must be a valid implementation of the LLMClient interface.
	Client LLMClient

	// Hooks provides optional callback functions for customizing agent behavior
	// at various points in the conversation lifecycle.
	Hooks Hooks

	// ToolProvider is an optional function that provides tools dynamically on each request.
	// If set, it will be called before each LLM request to get the current list of tools.
	// The tools returned by this function will be merged with the Tools list.
	ToolProvider func() []*Tool

	// Logf is the logging function to use. If nil, defaults to log.Printf.
	// Can be used to integrate with custom logging systems.
	Logf logger.Logf

	// ThinkingTokens specifies how many tokens to allocate for thinking/reasoning.
	// Only applies when ThinkingMode is true. A value of 0 means to use the default value.
	ThinkingTokens int

	// ForceTools restricts the agent to only using tools.
	// When true, the agent will not use the LLM to generate responses.
	ForceTools bool

	// MaxTokens limits the number of tokens in the LLM's response.
	// A value of 0 means to use the default value.
	MaxTokens int

	// MaxContextSize limits how large the agent's context can get before a loop is terminated.
	// If 0, no limit is applied.
	MaxContextSize int

	// MaxToolIterations is the maximum number of iterations for a call to
	// [Agent.Loop]. If 0, no limit is applied.
	MaxToolIterations int
}

func New(opts Opts) (*Agent, error) {
	if opts.Logf == nil {
		opts.Logf = logger.Discard
	}
	if opts.Client == nil {
		return nil, errors.New("client is required")
	}
	if opts.SystemPrompt == "" {
		return nil, errors.New("systemPrompt is required")
	}
	return &Agent{
		opts: opts,
	}, nil
}

// getTools returns the current set of tools, merging static with dynamic
func (a *Agent) getTools() map[string]*Tool {
	if a.opts.ToolProvider == nil {
		return nil
	}
	dynamicTools := a.opts.ToolProvider()
	out := make(map[string]*Tool, len(dynamicTools))
	for _, tool := range dynamicTools {
		out[tool.Name] = tool
	}
	return out
}

func (a *Agent) execTool(ctx context.Context, tools map[string]*Tool, toolUse *ToolUse) (string, []MessageContent, error) {
	tool, ok := tools[toolUse.Name]
	if !ok {
		return "", nil, fmt.Errorf("unknown tool %q", toolUse.Name)
	}
	return tool.Handler(ctx, toolUse)
}

func agentTools(t map[string]*Tool) []ToolDefinition {
	out := make([]ToolDefinition, len(t))
	i := 0
	for _, tool := range t {
		out[i] = ToolDefinition{
			Name:        tool.Name,
			Description: tool.Desc,
			InputSchema: json.RawMessage(tool.Schema),
		}
		i++
	}
	slices.SortFunc(out, func(a, b ToolDefinition) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

func (a *Agent) recordUsage(usage Usage) {
	a.usage.CacheCreationInputTokens += usage.CacheCreationInputTokens
	a.usage.CacheReadInputTokens += usage.CacheReadInputTokens
	a.usage.InputTokens += usage.InputTokens
	a.usage.OutputTokens += usage.OutputTokens
	a.opts.Logf("Usage: %s", asJSONPretty(a.usage))
	cost := float64(a.usage.InputTokens)*3 +
		float64(a.usage.OutputTokens)*15 +
		float64(a.usage.CacheCreationInputTokens)*3.75 +
		float64(a.usage.CacheReadInputTokens)*0.3
	a.opts.Logf("Cost (Sonnet 3.7 values): %.2fc", cost/1e4)

	if a.opts.Name == "" {
		return
	}
}

// Hooks defines callback functions that can be registered to intercept and modify
// agent behavior at various points in the conversation lifecycle.
// All hook functions are optional and can be nil if not needed.
//
// These hooks allow for customization of the agent's behavior without modifying
// the core agent implementation. This is useful for adding logging, metrics,
// custom validation, or integration with other systems.
type Hooks struct {
	// BeforeRequest is called just before sending a request to the LLM.
	// It can be used to modify or log the request, or to cancel the request by returning an error.
	BeforeRequest func(ctx context.Context, mr MessagesRequest) error

	// OnResponse is called immediately after receiving a response from the LLM,
	// before any tool calls are processed.
	// It can be used to log responses or modify them before further processing.
	OnResponse func(ctx context.Context, resp MessagesResponse) error

	// OnStreamingResponse is called during streaming responses with incremental updates.
	// It receives the full accumulated response for each update during streaming.
	OnStreamingResponse func(ctx context.Context, resp MessagesResponse)

	// BeforeToolRun is called just before executing a tool.
	// It can be used to validate or log tool calls, or to prevent execution by returning an error.
	// If an error is returned, the tool will not be executed and the error will be returned to the agent.
	BeforeToolRun func(ctx context.Context, toolID, toolName string, inputJSON json.RawMessage) error

	// AfterToolRun is called after a tool has been executed, with the result or error.
	// It can be used to log or modify tool results before they're sent back to the LLM.
	AfterToolRun func(ctx context.Context, toolID, toolName string, inputJSON json.RawMessage, output string, other []MessageContent, outErr error) error

	// OnToolResponse is called after a tool has been executed, with the result or error.
	// It can be used to log or modify tool results before they're sent back to the LLM.
	OnToolResponse func(ctx context.Context, toolResponse *Message, err error) error
}

// execTools executes all tool_use content in msg. The context is propagated to
// the tool execution functions, so it can be used to cancel async tool
// executions even if this function returns.
//
// It only returns an error if a hook returned an error aborting the
// conversation.
//
// The returned message has all the tool results added to it, even if the tool
// execution failed. The returned message is only nil if the message has no tool
// use content.
func (a *Agent) execTools(ctx context.Context, tools map[string]*Tool, msg *MessagesResponse) (*Message, error) {
	var toolResponse *Message
	var additionalContent []MessageContent
	for _, c := range msg.Content {
		switch c.Type {
		case ContentTypeThinking:
			a.opts.Logf("Thinking: %s", c.Thinking)
		case ContentTypeRedactedThinking:
			a.opts.Logf("Redacted thinking: %s", c.RedactedThinking)
		case ContentTypeText:
			a.opts.Logf("Text: %s", c.Text)
		case ContentTypeToolUse:
			a.opts.Logf("%s\nExecuting tool %q:\n%s", c.GetText(), c.ToolUse.Name, asJSONPretty(c.ToolUse))
			var toolErr error
			if a.opts.Hooks.BeforeToolRun != nil {
				toolErr = a.opts.Hooks.BeforeToolRun(ctx, c.ToolUse.ID, c.ToolUse.Name, c.ToolUse.Input)
			}
			var result string
			var out []MessageContent
			if toolErr == nil {
				result, out, toolErr = a.execTool(ctx, tools, c.ToolUse)
				additionalContent = append(additionalContent, out...)
			}
			if toolResponse == nil {
				toolResponse = &Message{
					Role: RoleTool,
				}
			}
			if a.opts.Hooks.AfterToolRun != nil {
				if err := a.opts.Hooks.AfterToolRun(ctx, c.ToolUse.ID, c.ToolUse.Name, c.ToolUse.Input, result, out, toolErr); err != nil {
					return toolResponse, err
				}
			}
			if toolErr == nil {
				toolResponse.Content = append(toolResponse.Content, NewToolResultContent(c.ToolUse.Name, c.ToolUse.ID, result, false))
				continue
			}
			if errors.Is(toolErr, ErrTerminateLoop) {
				toolResponse.Content = append(toolResponse.Content, NewToolResultContent(c.ToolUse.Name, c.ToolUse.ID, "ok", false))
				return toolResponse, toolErr
			}
			a.opts.Logf("Tool execution error for %s: %v", c.ToolUse.Name, toolErr)
			toolResponse.Content = append(toolResponse.Content, NewToolResultContent(c.ToolUse.Name, c.ToolUse.ID, fmt.Sprintf("error: %v", toolErr), true))
		}
	}
	if toolResponse != nil {
		toolResponse.Content = append(toolResponse.Content, additionalContent...)
	}
	return toolResponse, nil
}

// Loop runs the agent in a loop, generating messages and executing tools. It
// returns the final response from the LLM. It returns an error if the agent
// fails to generate a message or execute a tool.
//
// The interjections function is called after each message is generated, and can
// be used to add additional messages to the conversation.
//
// It only returns when the LLM returns a response with no tool uses, or
// MaxToolIterations is reached, or if a tool returns ErrTerminateLoop.
//
// On error, the function returns both the last response (if any) and the error,
// allowing callers to access any partial results generated before the failure.
//
// The context is propagated to the tool execution functions, so it can be used
// to cancel async tool executions even if this function returns.
func (a *Agent) Loop(ctx context.Context, messages []Message, interjections func() []Message) (*MessagesResponse, error) {
	openToolUses := make(map[string]bool)
	for _, m := range messages {
		for _, c := range m.Content {
			if c.Type == ContentTypeToolUse {
				openToolUses[c.ToolUse.ID] = true
			}
			if c.Type == ContentTypeToolResult {
				delete(openToolUses, c.ToolResults.ToolCallID)
			}
		}
	}

	msgs := make([]Message, 0, len(messages)+100)
	for _, m := range messages {
		msgs = append(msgs, m)
		var replyContent []MessageContent
		for _, c := range m.Content {
			if c.Type == ContentTypeToolUse {
				if _, ok := openToolUses[c.ToolUse.ID]; ok {
					delete(openToolUses, c.ToolUse.ID)
					replyContent = append(replyContent, MessageContent{
						Type: ContentTypeToolResult,
						ToolResults: &ToolResult{
							ToolCallID: c.ToolUse.ID,
							Output:     "tool call was aborted",
							Error:      true,
						},
					})
				}
			}
		}
		if len(replyContent) > 0 {
			msgs = append(msgs, Message{
				Role:    RoleUser,
				Content: replyContent,
			})
		}
	}
	curIter := 0
	var lastResponse *MessagesResponse
	for shouldLoop := true; shouldLoop; {
		if ctx.Err() != nil {
			return lastResponse, ctx.Err()
		}
		curIter++
		if a.opts.MaxToolIterations > 0 && curIter > a.opts.MaxToolIterations {
			return lastResponse, ErrMaxToolIterations
		}
		if interjections != nil {
			msgs = append(msgs, interjections()...)
		}
		if len(msgs) == 0 {
			return lastResponse, fmt.Errorf("no messages to generate")
		}
		var setCacheControlOnMessage *Message
		x := &msgs[len(msgs)-1]
		if lc := len(x.Content); lc > 0 {
			x.Content[lc-1].CacheControl = &CacheControl{
				Type: CacheControlTypeEphemeral,
			}
			setCacheControlOnMessage = x
		}
		tools := a.getTools()
		mr, genErr := a.generate(ctx, msgs, tools)
		if mr != nil {
			lastResponse = mr
			msgs = append(msgs, Message{
				Role:    RoleAssistant,
				Content: mr.Content,
			})
		}
		if setCacheControlOnMessage != nil {
			setCacheControlOnMessage.Content[len(setCacheControlOnMessage.Content)-1].CacheControl = nil
		}
		if genErr != nil {
			return lastResponse, genErr
		}
		toolResponse, stopExecErr := a.execTools(ctx, tools, mr)
		if a.opts.Hooks.OnToolResponse != nil {
			if hookErr := a.opts.Hooks.OnToolResponse(ctx, toolResponse, stopExecErr); hookErr != nil {
				return lastResponse, hookErr
			}
		}
		if toolResponse != nil {
			msgs = append(msgs, *toolResponse)
		}
		if stopExecErr != nil {
			a.opts.Logf("Tool execution error: %v", stopExecErr)
			if errors.Is(stopExecErr, ErrTerminateLoop) {
				return lastResponse, nil
			}
			return lastResponse, stopExecErr
		}
		shouldLoop = toolResponse != nil
	}
	return lastResponse, nil
}

// maxGenerateTries is the maximum number of times to attempt to generate a
// message response from the LLM.
const maxGenerateTries = 3

// generate generates a message response from the LLM.
//
// It is a thin wrapper around the LLM client to handle rate limiting, context
// cancellation, and other common errors.
//
// It attempts to generate a response up to [maxGenerateTries] times, with a backoff
// between attempts.
func (a *Agent) generate(ctx context.Context, history []Message, tools map[string]*Tool) (*MessagesResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	mr := MessagesRequest{
		System:         a.opts.SystemPrompt,
		MaxTokens:      cmp.Or(a.opts.MaxTokens, 8192),
		Tools:          agentTools(tools),
		ThinkingMode:   true,
		ThinkingTokens: a.opts.ThinkingTokens,
		Messages:       history,
	}
	// Anthropic will throw an error if ToolChoice is set to "auto" and there are no tools.
	if len(tools) > 0 {
		mr.ToolChoice = &ToolChoice{
			Type: "auto",
		}
		if a.opts.ForceTools {
			mr.ToolChoice.Type = "any"

			// Thinking may not be enabled when tool_choice forces tool use
			mr.ThinkingMode = false
		}
	}
	bo := backoff.NewBackoff("anthropic", a.opts.Logf, 30*time.Second)

	var lastErr error
	for range maxGenerateTries {
		if a.opts.Hooks.BeforeRequest != nil {
			if err := a.opts.Hooks.BeforeRequest(ctx, mr); err != nil {
				return nil, err
			}
		}
		a.opts.Logf("Generating with %d messages", len(mr.Messages))
		msgCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		if ct, ok := a.opts.Client.(TokenCounter); ok {
			tokens, err := ct.CountTokens(msgCtx, mr)
			if err != nil {
				a.opts.Logf("CountTokens error: %v", err)
			} else {
				a.opts.Logf("Tokens: %d", tokens)
			}
			if a.opts.MaxContextSize > 0 && tokens > a.opts.MaxContextSize {
				return nil, ErrTooLarge
			}
		}
		resp, err := a.opts.Client.CreateMessages(msgCtx, mr, func(streamResp MessagesResponse) {
			if a.opts.Hooks.OnStreamingResponse != nil {
				a.opts.Hooks.OnStreamingResponse(msgCtx, streamResp)
			}
		})
		cancel()
		if err != nil {
			lastErr = err
			if errors.Is(err, ctx.Err()) {
				return nil, ctx.Err()
			}
			a.opts.Logf("CreateMessages error: %v", err)
			var rle *RateLimitError
			if errors.Is(err, msgCtx.Err()) {
				a.opts.Logf("CreateMessages context error: %v", msgCtx.Err())
				bo.BackOff(ctx, msgCtx.Err())
				continue
			} else if errors.As(err, &rle) {
				a.opts.Logf("Rate limit error: %v", rle)
				if rle.RetryAfter > 0 {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(rle.RetryAfter):
					}
				} else {
					// We don't know how long to wait, so use the backoff.
					bo.BackOff(ctx, err)
				}
				continue
			} else if errors.Is(err, ErrOverloaded) || errors.Is(err, ErrRemoteServerError) {
				a.opts.Logf("Remote server error: %v", err)
				bo.BackOff(ctx, err)
				continue
			}
			return nil, err
		}
		bo.BackOff(ctx, nil) // Reset backoff
		if a.opts.Hooks.OnResponse != nil {
			if err := a.opts.Hooks.OnResponse(ctx, resp); err != nil {
				return nil, err
			}
		}
		a.recordUsage(resp.Usage)
		return &resp, nil
	}
	return nil, fmt.Errorf("max iterations reached: %w", lastErr)
}
