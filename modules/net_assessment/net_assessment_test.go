package net_assessment

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/bettercap/bettercap/v2/modules/syn_scan"
	"github.com/bettercap/bettercap/v2/network"
	"github.com/bettercap/bettercap/v2/session"
	"github.com/evilsocket/islazy/data"
)

type mockHostProvider struct {
	hosts []*network.Endpoint
	calls int
}

func (m *mockHostProvider) List() []*network.Endpoint {
	m.calls++
	return m.hosts
}

func newMockSession(t *testing.T) *session.Session {
	t.Helper()

	env, err := session.NewEnvironment("")
	if err != nil {
		t.Fatal(err)
	}

	iface := &network.Endpoint{
		IpAddress: "192.168.1.10",
		HwAddress: "02:00:00:00:00:10",
		Hostname:  "eth0",
	}
	iface.SetIP(iface.IpAddress)
	iface.SetBits(24)

	gateway := &network.Endpoint{
		IpAddress: "192.168.1.1",
		HwAddress: "02:00:00:00:00:01",
	}
	gateway.SetIP(gateway.IpAddress)
	gateway.SetBits(24)

	aliases, err := data.NewMemUnsortedKV()
	if err != nil {
		t.Fatal(err)
	}

	return &session.Session{
		Interface: iface,
		Gateway:   gateway,
		Env:       env,
		Events:    session.NewEventPool(false, false),
		Modules:   make(session.ModuleList, 0),
		Lan:       network.NewLAN(iface, gateway, aliases, func(e *network.Endpoint) {}, func(e *network.Endpoint) {}),
	}
}

func mockEndpoint(ip, mac string, ports map[int]*syn_scan.OpenPort) *network.Endpoint {
	endpoint := network.NewEndpointNoResolve(ip, mac, "", 24)
	if ports != nil {
		endpoint.Meta.Set("ports", ports)
	}
	return endpoint
}

func findEvent(sess *session.Session, tag string) *session.Event {
	for _, event := range sess.Events.Sorted() {
		if event.Tag == tag {
			found := event
			return &found
		}
	}
	return nil
}

func waitForEvent(t *testing.T, sess *session.Session, tag string) *session.Event {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if event := findEvent(sess, tag); event != nil {
			return event
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("event %q was not emitted", tag)
	return nil
}

func TestNewAssessmentContract(t *testing.T) {
	sess := newMockSession(t)
	provider := &mockHostProvider{}
	mod := NewAssessmentWithProvider(sess, provider)

	if mod.Name() != "net.assessment" {
		t.Fatalf("unexpected module name %q", mod.Name())
	}
	if mod.Description() == "" || mod.Author() == "" {
		t.Fatal("module metadata must be compatible with the module API")
	}
	if mod.Running() {
		t.Fatal("module must not be running before Start")
	}

	expected := map[string]bool{
		"net.assessment on":    false,
		"net.assessment off":   false,
		"net.assessment run":   false,
		"net.assessment show":  false,
		"net.assessment.clear": false,
	}
	for _, handler := range mod.Handlers() {
		if _, found := expected[handler.Name]; found {
			expected[handler.Name] = true
		}
	}
	for handler, found := range expected {
		if !found {
			t.Errorf("missing handler %q", handler)
		}
	}

	if err, period := mod.IntParam("net.assessment.period"); err != nil || period != 60 {
		t.Errorf("unexpected period parameter: %d, %v", period, err)
	}
	if err, min := mod.StringParam("net.assessment.min-severity"); err != nil || min != "info" {
		t.Errorf("unexpected min-severity parameter: %q, %v", min, err)
	}
}

func TestBuildReportWithMockHosts(t *testing.T) {
	hosts := []*network.Endpoint{
		mockEndpoint("192.168.1.20", "02:00:00:00:00:20", map[int]*syn_scan.OpenPort{
			22: {
				Port:    22,
				Proto:   "tcp",
				Service: "ssh",
			},
			445: {
				Port:    445,
				Proto:   "tcp",
				Service: "microsoft-ds",
			},
			6379: {
				Port:    6379,
				Proto:   "tcp",
				Service: "redis",
			},
		}),
		mockEndpoint("192.168.1.11", "02:00:00:00:00:11", map[int]*syn_scan.OpenPort{
			80: {
				Port:    80,
				Proto:   "tcp",
				Service: "http",
			},
		}),
	}

	report := BuildReport(hosts, SeverityInfo)
	if report.HostCount != 2 {
		t.Fatalf("got %d hosts, want 2", report.HostCount)
	}
	if report.FindingCount != 3 {
		t.Fatalf("got %d findings, want 3: %#v", report.FindingCount, report.Findings)
	}
	if report.Findings[0].Port != 6379 || report.Findings[0].Severity != SeverityCritical {
		t.Fatalf("findings are not sorted by severity: %#v", report.Findings)
	}
	if report.Summary.Critical != 1 || report.Summary.High != 1 || report.Summary.Low != 1 {
		t.Fatalf("unexpected summary: %#v", report.Summary)
	}
	if report.Hosts[0].Address != "192.168.1.11" {
		t.Fatalf("hosts are not sorted by address: %#v", report.Hosts)
	}

	filtered := BuildReport(hosts, SeverityHigh)
	if filtered.FindingCount != 2 {
		t.Fatalf("got %d high-or-critical findings, want 2", filtered.FindingCount)
	}
	if filtered.Summary.Low != 0 {
		t.Fatalf("low finding was not filtered: %#v", filtered.Summary)
	}
}

func TestAssessUsesMockProviderAndEmitsEvent(t *testing.T) {
	sess := newMockSession(t)
	provider := &mockHostProvider{
		hosts: []*network.Endpoint{
			mockEndpoint("192.168.1.50", "02:00:00:00:00:50", map[int]*syn_scan.OpenPort{
				23: {Port: 23, Proto: "tcp", Service: "telnet"},
			}),
		},
	}
	mod := NewAssessmentWithProvider(sess, provider)

	report, err := mod.Assess()
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 {
		t.Fatalf("provider called %d times, want 1", provider.calls)
	}
	if report.FindingCount != 1 || report.Findings[0].Port != 23 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if mod.LastReport() != report {
		t.Fatal("last report was not stored")
	}

	event := findEvent(sess, EventTag)
	if event == nil {
		t.Fatal("assessment event was not emitted")
	}
	eventReport, ok := event.Data.(*Report)
	if !ok {
		t.Fatalf("unexpected event payload type %T", event.Data)
	}
	if eventReport.FindingCount != 1 {
		t.Fatalf("unexpected event report: %#v", eventReport)
	}

	if hostCount := stateInt(t, mod, "host_count"); hostCount != 1 {
		t.Fatalf("state host_count = %d, want 1", hostCount)
	}
	if findingCount := stateInt(t, mod, "finding_count"); findingCount != 1 {
		t.Fatalf("state finding_count = %d, want 1", findingCount)
	}
}

func TestAssessmentLifecycle(t *testing.T) {
	sess := newMockSession(t)
	provider := &mockHostProvider{}
	mod := NewAssessmentWithProvider(sess, provider)

	if err := mod.Start(); err != nil {
		t.Fatal(err)
	}
	if !mod.Running() {
		t.Fatal("module is not running after Start")
	}
	waitForEvent(t, sess, EventTag)
	waitForEvent(t, sess, "mod.started")

	if err := mod.Start(); err == nil {
		t.Fatal("starting an already running module must fail")
	}

	if err := mod.Stop(); err != nil {
		t.Fatal(err)
	}
	if mod.Running() {
		t.Fatal("module is still running after Stop")
	}
	waitForEvent(t, sess, "mod.stopped")

	if err := mod.Stop(); err == nil {
		t.Fatal("stopping an already stopped module must fail")
	}
	if provider.calls == 0 {
		t.Fatal("worker did not assess the mocked host source")
	}
}

func TestModuleJSONCompatibility(t *testing.T) {
	sess := newMockSession(t)
	provider := &mockHostProvider{
		hosts: []*network.Endpoint{
			mockEndpoint("192.168.1.60", "02:00:00:00:00:60", map[int]*syn_scan.OpenPort{
				6379: {Port: 6379, Proto: "tcp", Service: "redis"},
			}),
		},
	}
	mod := NewAssessmentWithProvider(sess, provider)
	if err := sess.Register(mod); err != nil {
		t.Fatal(err)
	}

	previous := session.I
	session.I = sess
	defer func() {
		session.I = previous
	}()

	raw, err := json.Marshal(sess.Modules)
	if err != nil {
		t.Fatal(err)
	}

	var modules []map[string]interface{}
	if err := json.Unmarshal(raw, &modules); err != nil {
		t.Fatal(err)
	}
	if len(modules) != 1 {
		t.Fatalf("got %d modules, want 1", len(modules))
	}

	module := modules[0]
	for _, field := range []string{"name", "description", "author", "parameters", "handlers", "running", "state"} {
		if _, found := module[field]; !found {
			t.Fatalf("module API field %q is missing: %#v", field, module)
		}
	}
	if module["name"] != ModuleName {
		t.Fatalf("unexpected module name in API response: %#v", module["name"])
	}

	state, ok := module["state"].(map[string]interface{})
	if !ok {
		t.Fatalf("module state is not an object: %#v", module["state"])
	}
	for _, field := range []string{"assessing", "host_count", "finding_count", "findings", "summary", "last_report"} {
		if _, found := state[field]; !found {
			t.Fatalf("module state field %q is missing: %#v", field, state)
		}
	}
}

func TestClearAndSeverityFiltering(t *testing.T) {
	sess := newMockSession(t)
	provider := &mockHostProvider{
		hosts: []*network.Endpoint{
			mockEndpoint("192.168.1.70", "02:00:00:00:00:70", map[int]*syn_scan.OpenPort{
				22: {Port: 22, Proto: "tcp", Service: "ssh"},
			}),
		},
	}
	mod := NewAssessmentWithProvider(sess, provider)
	sess.Env.Set("net.assessment.min-severity", "HIGH")

	report, err := mod.Assess()
	if err != nil {
		t.Fatal(err)
	}
	if report.FindingCount != 0 {
		t.Fatalf("expected high threshold to filter SSH finding: %#v", report.Findings)
	}

	mod.Clear()
	if mod.LastReport() != nil {
		t.Fatal("report was not cleared")
	}
	if hostCount := stateInt(t, mod, "host_count"); hostCount != 0 {
		t.Fatalf("state host_count = %d after clear, want 0", hostCount)
	}
}

func stateInt(t *testing.T, mod *Assessment, key string) int {
	t.Helper()
	value, found := mod.State.Load(key)
	if !found {
		t.Fatalf("state key %q not found", key)
	}
	number, ok := value.(int)
	if !ok {
		t.Fatalf("state key %q has type %T", key, value)
	}
	return number
}
