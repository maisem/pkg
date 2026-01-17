// Copyright (c) 2025 AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// Test clients available in this package:
//
// mockLLMClient: Simple test client for basic sequential response testing.
//   - Use when you need deterministic responses in a fixed sequence
//   - Good for simple test scenarios with predictable behavior
//
// FakeLLMClient: Advanced test client with more features (defined in fake_client.go).
//   - Use when you need dynamic behavior based on request content
//   - Supports delays, request history, custom handlers, and builder pattern
//   - Better for complex test scenarios or integration tests

// mockResponse groups a response with its associated error for cleaner test configuration
type mockResponse struct {
	Response MessagesResponse
	Error    error
}

// mockLLMClient implements LLMClient for testing.
// It provides a simple way to simulate LLM responses in tests by returning
// pre-configured responses and errors in sequence.
//
// Usage:
//
//	client := &mockLLMClient{
//	    calls: []mockResponse{
//	        {
//	            Response: MessagesResponse{Content: Content{{Type: ContentTypeText, Text: "First"}}},
//	            Error:    nil,  // First call succeeds
//	        },
//	        {
//	            Response: MessagesResponse{Content: Content{{Type: ContentTypeText, Text: "Second"}}},
//	            Error:    errors.New("second fails"),  // Second call returns error with response
//	        },
//	    },
//	}
//
// The client will return the response and error for each call in sequence.
// If all configured responses are exhausted, it returns an error.
type mockLLMClient struct {
	calls     []mockResponse
	callCount int
}

func (m *mockLLMClient) CreateMessages(ctx context.Context, req MessagesRequest, onUpdate func(MessagesResponse)) (MessagesResponse, error) {
	if m.callCount >= len(m.calls) {
		return MessagesResponse{}, errors.New("no more responses configured")
	}
	call := m.calls[m.callCount]
	m.callCount++
	return call.Response, call.Error
}

// TestLoopTerminatesOnErrTerminateLoop verifies that Loop properly handles ErrTerminateLoop
func TestLoopTerminatesOnErrTerminateLoop(t *testing.T) {
	tests := []struct {
		name           string
		toolErr        error
		wantErr        error
		wantLastResp   bool
		wantToolResult string
	}{
		{
			name:           "ErrTerminateLoop returns nil error and last response",
			toolErr:        ErrTerminateLoop,
			wantErr:        nil,
			wantLastResp:   true,
			wantToolResult: "ok",
		},
		{
			name:           "Tool errors continue loop with error in tool response",
			toolErr:        errors.New("tool failed"),
			wantErr:        nil, // Loop continues, doesn't return error
			wantLastResp:   true,
			wantToolResult: "error: tool failed",
		},
	}
	lr := func(c ...MessageContent) mockResponse {
		return mockResponse{
			Response: MessagesResponse{
				Content: c,
			},
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create a tool that returns the test error
			testTool := NewTool("test_tool", "Test tool for ErrTerminateLoop",
				func(ctx context.Context, params struct{}) (string, []MessageContent, error) {
					if tt.toolErr != nil {
						return "", nil, tt.toolErr
					}
					return "success", nil, nil
				})

			// Create mock LLM client that simulates tool usage
			mockClient := &mockLLMClient{
				calls: []mockResponse{
					// First response with tool use
					lr(NewTextContent("Using test tool"), NewToolUseContent("test_1", "test_tool", json.RawMessage("{}"))),
					// Second response after tool error (no tool use to end loop)
					lr(NewTextContent("Done")),
				},
			}

			// Create agent
			agent, err := New(Opts{
				SystemPrompt: "Test system prompt",
				Client:       mockClient,
				ToolProvider: func() []*Tool {
					return []*Tool{testTool}
				},
				Logf: func(format string, args ...any) {
					// no-op for testing
				},
			})
			if err != nil {
				t.Fatalf("failed to create agent: %v", err)
			}

			// Run the Loop
			resp, err := agent.Loop(ctx, []Message{
				{
					Role: RoleUser,
					Content: Content{
						NewTextContent("Test message"),
					},
				},
			}, nil)

			// Check error
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if !errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error() {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			// Check last response
			if tt.wantLastResp {
				if resp == nil {
					t.Error("expected last response, got nil")
				}
			} else if resp != nil {
				t.Error("expected no last response, got one")
			}
		})
	}
}

// TestLoopReturnsLastResponseOnError verifies that Loop returns the last response even when an error occurs
func TestLoopReturnsLastResponseOnError(t *testing.T) {
	ctx := context.Background()

	// Create mock LLM client that succeeds first, then fails
	callCount := 0
	mockClient := NewFakeLLMClient().
		WithOnRequest(func(ctx context.Context, req MessagesRequest) (*MessagesResponse, error) {
			callCount++
			if callCount == 1 {
				// First call succeeds
				return &MessagesResponse{
					Content: Content{
						NewTextContent("Partial result"),
					},
					StopReason: "end_turn",
				}, nil
			}
			// Second call fails
			return nil, errors.New("generation failed")
		}).Build()

	agent, err := New(Opts{
		SystemPrompt: "Test system prompt",
		Client:       mockClient,
		Logf: func(format string, args ...any) {
			// no-op for testing
		},
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	// Create a tool that triggers another LLM call
	testTool := NewTool("test_tool", "Test tool",
		func(ctx context.Context, params struct{}) (string, []MessageContent, error) {
			return "tool result", nil, nil
		})

	agent.opts.ToolProvider = func() []*Tool {
		return []*Tool{testTool}
	}

	// Create a new client with specific behavior
	var genCallCount int
	testClient := &FakeLLMClient{
		OnRequest: func(ctx context.Context, req MessagesRequest) (*MessagesResponse, error) {
			genCallCount++
			if genCallCount == 1 {
				// First call returns tool use
				return &MessagesResponse{
					Content: Content{
						NewTextContent("Using tool"),
						NewToolUseContent("test_1", "test_tool", json.RawMessage("{}")),
					},
					StopReason: "tool_use",
				}, nil
			}
			// Second call fails with error (no response)
			return nil, errors.New("generation failed")
		},
	}

	// Update agent to use the new client
	agent.opts.Client = testClient

	resp, err := agent.Loop(ctx, []Message{
		{
			Role: RoleUser,
			Content: Content{
				NewTextContent("Test"),
			},
		},
	}, nil)

	if err == nil {
		t.Error("expected error, got nil")
	}
	if resp == nil {
		t.Error("expected last response to be returned with error, got nil")
	}
	if resp != nil && len(resp.Content) > 0 {
		// The last successful response was the one with tool use
		foundToolUse := false
		for _, c := range resp.Content {
			if c.Type == ContentTypeToolUse {
				foundToolUse = true
				break
			}
		}
		if !foundToolUse {
			t.Errorf("expected last response to contain tool use, got %v", resp.Content)
		}
	}
}

// TestExecToolsTerminateLoop verifies that execTools properly handles ErrTerminateLoop
func TestExecToolsTerminateLoop(t *testing.T) {
	ctx := context.Background()

	// Create a tool that returns ErrTerminateLoop
	terminateTool := NewTool("terminate_tool", "Tool that terminates the loop",
		func(ctx context.Context, params struct{}) (string, []MessageContent, error) {
			return "", nil, ErrTerminateLoop
		})

	agent, err := New(Opts{
		SystemPrompt: "Test system prompt",
		Client:       &mockLLMClient{calls: []mockResponse{}}, // Not used in this test
		ToolProvider: func() []*Tool {
			return []*Tool{terminateTool}
		},
		Logf: func(format string, args ...any) {
			// no-op for testing
		},
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	tools := agent.getTools()
	mockResponse := &MessagesResponse{
		Content: Content{
			NewToolUseContent("test_1", "terminate_tool", json.RawMessage("{}")),
		},
	}

	toolResponse, err := agent.execTools(ctx, tools, mockResponse)

	if !errors.Is(err, ErrTerminateLoop) {
		t.Errorf("expected ErrTerminateLoop, got %v", err)
	}

	if toolResponse == nil {
		t.Fatal("expected tool response, got nil")
	}

	if len(toolResponse.Content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(toolResponse.Content))
	}

	if toolResponse.Content[0].Type != ContentTypeToolResult {
		t.Errorf("expected tool result content type, got %s", toolResponse.Content[0].Type)
	}

	if toolResponse.Content[0].ToolResults.Output != "ok" {
		t.Errorf("expected tool result output 'ok', got %s", toolResponse.Content[0].ToolResults.Output)
	}

	if toolResponse.Content[0].ToolResults.Error {
		t.Error("expected tool result error to be false")
	}
}

// TestLoopContextCancellation verifies that Loop properly handles context cancellation
func TestLoopContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context immediately
	cancel()

	lr := func(c ...MessageContent) mockResponse {
		return mockResponse{
			Response: MessagesResponse{
				Content: c,
			},
		}
	}

	mockClient := &mockLLMClient{
		calls: []mockResponse{
			lr(NewTextContent("Response")),
		},
	}

	agent, err := New(Opts{
		SystemPrompt: "Test system prompt",
		Client:       mockClient,
		Logf: func(format string, args ...any) {
			// no-op for testing
		},
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	// Call Loop with cancelled context
	// It should check context at the beginning of the loop
	resp, err := agent.Loop(ctx, []Message{
		{
			Role: RoleUser,
			Content: Content{
				NewTextContent("Test"),
			},
		},
	}, nil)

	// Should return context error
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got %v", err)
	}

	// lastResponse should be nil since no iteration completed
	if resp != nil {
		t.Error("expected nil response for immediate context cancellation")
	}
}

// TestLoopMaxToolIterationsEarlyCheck verifies that MaxToolIterations is checked early in the loop
func TestLoopMaxToolIterationsEarlyCheck(t *testing.T) {
	ctx := context.Background()

	// Track if tool was executed
	toolExecuted := false
	testTool := NewTool("test_tool", "Test tool",
		func(ctx context.Context, params struct{}) (string, []MessageContent, error) {
			toolExecuted = true
			return "success", nil, nil
		})

	tests := []struct {
		name                 string
		maxToolIterations    int
		initialMessages      []Message
		expectGenerateCalled bool
		expectToolExecuted   bool
		expectError          error
		expectLastResponse   bool
	}{
		{
			name:              "MaxToolIterations=1 allows first iteration",
			maxToolIterations: 1,
			initialMessages: []Message{
				{
					Role:    RoleUser,
					Content: Content{NewTextContent("Test")},
				},
			},
			expectGenerateCalled: true,
			expectToolExecuted:   true,
			expectError:          ErrMaxToolIterations, // Second iteration hits the limit
			expectLastResponse:   true,                 // First iteration completed successfully
		},
		{
			name:              "MaxToolIterations=0 means no limit",
			maxToolIterations: 0,
			initialMessages: []Message{
				{
					Role:    RoleUser,
					Content: Content{NewTextContent("Test")},
				},
			},
			expectGenerateCalled: true,
			expectToolExecuted:   true,
			expectError:          nil, // No error since we'll stop the loop by returning no tools after 3 iterations
			expectLastResponse:   true,
		},
		{
			name:              "MaxToolIterations=2 allows two iterations",
			maxToolIterations: 2,
			initialMessages: []Message{
				{
					Role:    RoleUser,
					Content: Content{NewTextContent("Test")},
				},
			},
			expectGenerateCalled: true,
			expectToolExecuted:   true,
			expectError:          ErrMaxToolIterations, // Third iteration hits the limit
			expectLastResponse:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset tracking variables
			generateCalled := false
			toolExecuted = false
			iterationCount := 0

			// Create a client that counts iterations
			client := NewFakeLLMClient().
				WithOnRequest(func(ctx context.Context, req MessagesRequest) (*MessagesResponse, error) {
					generateCalled = true
					iterationCount++

					// For MaxToolIterations=0 test, return tool uses for first 3 iterations, then stop
					if tt.maxToolIterations == 0 && iterationCount == 4 {
						// Return a response without tool use to end the loop after 3 complete iterations
						return &MessagesResponse{
							Content:    Content{NewTextContent("Done after 3 tool iterations")},
							StopReason: "end_turn",
						}, nil
					}

					// Keep returning tool uses to trigger the loop
					return &MessagesResponse{
						Content: Content{
							NewToolUseContent("test_"+string(rune('0'+iterationCount)), "test_tool", json.RawMessage("{}")),
						},
						StopReason: "tool_use",
					}, nil
				}).Build()

			agent, err := New(Opts{
				SystemPrompt:      "Test system prompt",
				Client:            client,
				MaxToolIterations: tt.maxToolIterations,
				ToolProvider: func() []*Tool {
					return []*Tool{testTool}
				},
				Logf: func(format string, args ...any) {
					// no-op for testing
				},
			})
			if err != nil {
				t.Fatalf("failed to create agent: %v", err)
			}

			resp, err := agent.Loop(ctx, tt.initialMessages, nil)

			// Check if generate was called as expected
			if generateCalled != tt.expectGenerateCalled {
				t.Errorf("generate called = %v, want %v", generateCalled, tt.expectGenerateCalled)
			}

			// Check if tool was executed as expected
			if toolExecuted != tt.expectToolExecuted {
				t.Errorf("tool executed = %v, want %v", toolExecuted, tt.expectToolExecuted)
			}

			// Check error
			if tt.expectError != nil {
				if !errors.Is(err, tt.expectError) {
					t.Errorf("expected error %v, got %v", tt.expectError, err)
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			// Check if we got a last response
			if tt.expectLastResponse && resp == nil {
				t.Error("expected last response, got nil")
			} else if !tt.expectLastResponse && resp != nil {
				t.Error("expected no last response, got one")
			}
		})
	}
}

// TestLoopMaxToolIterationsCheckedBeforeGeneration verifies the iteration check happens before any work
func TestLoopMaxToolIterationsCheckedBeforeGeneration(t *testing.T) {
	ctx := context.Background()

	// Track how many times generate was called
	generateCallCount := 0

	// Create a client that counts calls and returns tool uses to continue the loop
	mockClient := NewFakeLLMClient().
		WithOnRequest(func(ctx context.Context, req MessagesRequest) (*MessagesResponse, error) {
			generateCallCount++
			// Return tool use to keep the loop going
			return &MessagesResponse{
				Content: Content{
					NewToolUseContent("tool_"+string(rune('0'+generateCallCount)), "test_tool", json.RawMessage("{}")),
				},
				StopReason: "tool_use",
			}, nil
		}).Build()

	// Create a simple tool
	testTool := NewTool("test_tool", "Test tool",
		func(ctx context.Context, params struct{}) (string, []MessageContent, error) {
			return "success", nil, nil
		})

	agent, err := New(Opts{
		SystemPrompt:      "Test system prompt",
		Client:            mockClient,
		MaxToolIterations: 2, // Allow only 2 iterations
		ToolProvider: func() []*Tool {
			return []*Tool{testTool}
		},
		Logf: func(format string, args ...any) {
			// no-op for testing
		},
	})
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	// Start with a simple user message
	messages := []Message{
		{
			Role:    RoleUser,
			Content: Content{NewTextContent("Initial request")},
		},
	}

	// This should run 2 iterations successfully, then fail on the 3rd with ErrMaxToolIterations
	resp, err := agent.Loop(ctx, messages, nil)

	if !errors.Is(err, ErrMaxToolIterations) {
		t.Errorf("expected ErrMaxToolIterations, got %v", err)
	}

	// Should have called generate exactly 2 times (for iterations 1 and 2)
	if generateCallCount != 2 {
		t.Errorf("expected generate to be called 2 times, got %d", generateCallCount)
	}

	// lastResponse should be the response from the 2nd iteration
	if resp == nil {
		t.Error("expected last response from completed iterations")
	}
}
