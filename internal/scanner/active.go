package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxActiveResponse = 4 << 20

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}
type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// ActiveScan performs read-only MCP discovery. It never invokes a tool, reads a
// resource, renders a prompt, requests sampling, or accepts elicitation.
func (s *Scanner) ActiveScan(ctx context.Context, endpoint string, allowPrivate bool) (*ScanResult, error) {
	parsed, err := validateActiveURL(endpoint, allowPrivate)
	if err != nil {
		return nil, err
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("unexpected default HTTP transport type")
	}
	transport := defaultTransport.Clone()
	if !allowPrivate {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		transport.DialContext = func(dialCtx context.Context, network, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, splitErr
			}
			addresses, lookupErr := net.DefaultResolver.LookupIPAddr(dialCtx, host)
			if lookupErr != nil {
				return nil, lookupErr
			}
			for _, candidate := range addresses {
				ip := candidate.IP
				if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
					continue
				}
				return dialer.DialContext(dialCtx, network, net.JoinHostPort(ip.String(), port))
			}
			return nil, fmt.Errorf("endpoint resolved only to blocked private or local addresses")
		}
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		_, validateErr := validateActiveURL(req.URL.String(), allowPrivate)
		return validateErr
	}}
	session := ""
	call := func(id int, method string, params any) (json.RawMessage, error) {
		payload, marshalErr := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
		if marshalErr != nil {
			return nil, marshalErr
		}
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(payload))
		if requestErr != nil {
			return nil, requestErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if s.ActiveToken != "" {
			req.Header.Set("Authorization", "Bearer "+s.ActiveToken)
		}
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			return nil, requestErr
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			if closeErr := resp.Body.Close(); closeErr != nil {
				return nil, closeErr
			}
			return nil, fmt.Errorf("endpoint requires authorization (HTTP %d)", resp.StatusCode)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if closeErr := resp.Body.Close(); closeErr != nil {
				return nil, closeErr
			}
			return nil, fmt.Errorf("MCP endpoint returned HTTP %d", resp.StatusCode)
		}
		if value := resp.Header.Get("Mcp-Session-Id"); value != "" {
			session = value
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxActiveResponse+1))
		closeErr := resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(body) > maxActiveResponse {
			return nil, fmt.Errorf("MCP response exceeds %d bytes", maxActiveResponse)
		}
		body = extractSSEData(body)
		var rpc rpcResponse
		if unmarshalErr := json.Unmarshal(body, &rpc); unmarshalErr != nil {
			return nil, fmt.Errorf("invalid JSON-RPC response: %w", unmarshalErr)
		}
		if rpc.Error != nil {
			return nil, fmt.Errorf("JSON-RPC %d: %s", rpc.Error.Code, rpc.Error.Message)
		}
		return rpc.Result, nil
	}
	if _, err = call(1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "mcpsec", "version": "active-scan"}}); err != nil {
		return nil, fmt.Errorf("initializing: %w", err)
	}
	// Complete the MCP lifecycle before requesting inventory. This notification
	// has no response and grants no additional capability.
	notification, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if err != nil {
		return nil, err
	}
	notifyReq, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(notification))
	if err != nil {
		return nil, err
	}
	notifyReq.Header.Set("Content-Type", "application/json")
	notifyReq.Header.Set("Accept", "application/json, text/event-stream")
	if s.ActiveToken != "" {
		notifyReq.Header.Set("Authorization", "Bearer "+s.ActiveToken)
	}
	if session != "" {
		notifyReq.Header.Set("Mcp-Session-Id", session)
	}
	notifyResp, err := client.Do(notifyReq)
	if err != nil {
		return nil, fmt.Errorf("sending initialized notification: %w", err)
	}
	if _, copyErr := io.Copy(io.Discard, io.LimitReader(notifyResp.Body, maxActiveResponse)); copyErr != nil {
		if closeErr := notifyResp.Body.Close(); closeErr != nil {
			return nil, fmt.Errorf("reading notification response: %v; closing response: %w", copyErr, closeErr)
		}
		return nil, copyErr
	}
	if closeErr := notifyResp.Body.Close(); closeErr != nil {
		return nil, closeErr
	}
	if notifyResp.StatusCode < 200 || notifyResp.StatusCode >= 300 {
		return nil, fmt.Errorf("initialized notification returned HTTP %d", notifyResp.StatusCode)
	}
	config := &MCPServerConfig{MCPServers: map[string]MCPServer{parsed.Host: {URL: parsed.String(), Transport: "streamable-http"}}}
	server := config.MCPServers[parsed.Host]
	var toolsErr error
	cursor := ""
	for page := 0; page < 100; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		toolsResult, listErr := call(2+page, "tools/list", params)
		if listErr != nil {
			toolsErr = listErr
			break
		}
		var listed struct {
			Tools      []Tool `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if unmarshalErr := json.Unmarshal(toolsResult, &listed); unmarshalErr != nil {
			return nil, fmt.Errorf("parsing tools/list: %w", unmarshalErr)
		}
		server.Tools = append(server.Tools, listed.Tools...)
		cursor = listed.NextCursor
		if cursor == "" {
			break
		}
		if page == 99 {
			return nil, fmt.Errorf("tools/list exceeded 100 pages")
		}
	}
	config.MCPServers[parsed.Host] = server
	result, err := s.scanConfig(config, nil, parsed.String())
	if err != nil {
		return nil, err
	}
	if s.ActiveToken == "" {
		result.Findings = append(result.Findings, Finding{RuleID: "MCP07-201", Name: "Remote MCP endpoint permits unauthenticated enumeration", Severity: "high", OWASPMCP: "MCP07", Description: "The endpoint completed MCP initialization and tool inventory without credentials. This is factual exposure evidence, but public access may be intentional.", Remediation: "Confirm public enumeration is intended; otherwise require OAuth 2.1 or another strong identity mechanism and enforce per-tool authorization.", Resource: "mcpserver:" + parsed.Host})
	}
	if toolsErr != nil {
		result.Findings = append(result.Findings, Finding{RuleID: "MCP08-201", Name: "Tool inventory unavailable", Severity: "medium", OWASPMCP: "MCP08", Description: toolsErr.Error(), Remediation: "Ensure tools/list is auditable for an authorized security identity.", Resource: "mcpserver:" + parsed.Host})
	}
	return result, nil
}

func extractSSEData(body []byte) []byte {
	if json.Valid(body) {
		return body
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data:") {
			return bytes.TrimSpace([]byte(strings.TrimPrefix(scanner.Text(), "data:")))
		}
	}
	return body
}

func validateActiveURL(raw string, allowPrivate bool) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid MCP endpoint URL")
	}
	if parsed.Scheme != "https" && (!allowPrivate || parsed.Scheme != "http") {
		return nil, fmt.Errorf("active scans require HTTPS; use --allow-private to permit HTTP development endpoints")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("credentials in endpoint URLs are not allowed")
	}
	addresses, err := net.LookupIP(parsed.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolving endpoint: %w", err)
	}
	if !allowPrivate {
		for _, ip := range addresses {
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				return nil, fmt.Errorf("private or local endpoint blocked; use --allow-private to authorize it")
			}
		}
	}
	return parsed, nil
}
