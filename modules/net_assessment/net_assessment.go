package net_assessment

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bettercap/bettercap/v2/modules/syn_scan"
	"github.com/bettercap/bettercap/v2/network"
	"github.com/bettercap/bettercap/v2/session"
)

const (
	ModuleName = "net.assessment"
	EventTag   = "net.assessment"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type OpenPort struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

type HostResult struct {
	Address   string     `json:"address"`
	MAC       string     `json:"mac"`
	Hostname  string     `json:"hostname,omitempty"`
	Vendor    string     `json:"vendor,omitempty"`
	OpenPorts []OpenPort `json:"open_ports"`
}

type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Address  string   `json:"address"`
	MAC      string   `json:"mac"`
	Port     int      `json:"port,omitempty"`
	Service  string   `json:"service,omitempty"`
	Message  string   `json:"message"`
}

type SeveritySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type Report struct {
	GeneratedAt  time.Time       `json:"generated_at"`
	DurationMS   int64           `json:"duration_ms"`
	HostCount    int             `json:"host_count"`
	FindingCount int             `json:"finding_count"`
	Summary      SeveritySummary `json:"summary"`
	Hosts        []HostResult    `json:"hosts"`
	Findings     []Finding       `json:"findings"`
}

type HostProvider interface {
	List() []*network.Endpoint
}

type Assessment struct {
	session.SessionModule

	provider  HostProvider
	runLock   sync.Mutex
	stateLock sync.RWMutex
	stopLock  sync.Mutex
	stop      chan struct{}
	wait      sync.WaitGroup
	period    time.Duration
	min       Severity
	last      *Report
}

func NewAssessment(s *session.Session) *Assessment {
	return NewAssessmentWithProvider(s, nil)
}

func NewAssessmentWithProvider(s *session.Session, provider HostProvider) *Assessment {
	mod := &Assessment{
		SessionModule: session.NewSessionModule(ModuleName, s),
		provider:      provider,
		period:        time.Minute,
		min:           SeverityInfo,
	}

	mod.State.Store("assessing", false)
	mod.State.Store("host_count", 0)
	mod.State.Store("finding_count", 0)
	mod.State.Store("findings", []Finding{})
	mod.State.Store("summary", SeveritySummary{})
	mod.State.Store("last_report", (*Report)(nil))

	mod.AddParam(session.NewIntParameter("net.assessment.period",
		"60",
		"Seconds between periodic internal network assessments."))

	mod.AddParam(session.NewStringParameter("net.assessment.min-severity",
		string(SeverityInfo),
		`(?i)^(info|low|medium|high|critical)$`,
		"Minimum finding severity included in the report."))

	mod.AddHandler(session.NewModuleHandler("net.assessment on", "",
		"Start periodic internal network assessment.",
		func(args []string) error {
			return mod.Start()
		}))

	mod.AddHandler(session.NewModuleHandler("net.assessment off", "",
		"Stop periodic internal network assessment.",
		func(args []string) error {
			return mod.Stop()
		}))

	mod.AddHandler(session.NewModuleHandler("net.assessment run", "",
		"Run an internal network assessment immediately.",
		func(args []string) error {
			_, err := mod.Assess()
			return err
		}))

	mod.AddHandler(session.NewModuleHandler("net.assessment show", "",
		"Show the latest internal network assessment report.",
		func(args []string) error {
			return mod.Show()
		}))

	mod.AddHandler(session.NewModuleHandler("net.assessment.clear", "",
		"Clear the latest internal network assessment report.",
		func(args []string) error {
			mod.Clear()
			return nil
		}))

	return mod
}

func (mod *Assessment) Name() string {
	return ModuleName
}

func (mod *Assessment) Description() string {
	return "Correlate discovered internal hosts and open services into a risk assessment report."
}

func (mod *Assessment) Author() string {
	return "Bettercap Contributors"
}

func (mod *Assessment) Configure() error {
	if mod.Running() {
		return session.ErrAlreadyStarted(mod.Name())
	}
	return mod.loadConfig()
}

func (mod *Assessment) loadConfig() error {
	err, seconds := mod.IntParam("net.assessment.period")
	if err != nil {
		return err
	} else if seconds < 1 {
		return fmt.Errorf("net.assessment.period must be greater than zero")
	}

	err, min := mod.StringParam("net.assessment.min-severity")
	if err != nil {
		return err
	}
	severity, err := ParseSeverity(min)
	if err != nil {
		return err
	}

	mod.stateLock.Lock()
	mod.period = time.Duration(seconds) * time.Second
	mod.min = severity
	mod.stateLock.Unlock()
	return nil
}

func (mod *Assessment) Start() error {
	if err := mod.Configure(); err != nil {
		return err
	}

	stop := make(chan struct{})
	mod.stopLock.Lock()
	mod.stop = stop
	mod.stopLock.Unlock()

	mod.wait.Add(1)
	if err := mod.SetRunning(true, func() {
		defer mod.wait.Done()
		mod.worker(stop)
	}); err != nil {
		mod.wait.Done()
		return err
	}
	return nil
}

func (mod *Assessment) Stop() error {
	if !mod.Running() {
		return mod.SetRunning(false, nil)
	}

	mod.stopLock.Lock()
	if mod.stop != nil {
		close(mod.stop)
		mod.stop = nil
	}
	mod.stopLock.Unlock()

	return mod.SetRunning(false, func() {
		mod.wait.Wait()
	})
}

func (mod *Assessment) worker(stop <-chan struct{}) {
	mod.assessAndLog()

	mod.stateLock.RLock()
	period := mod.period
	mod.stateLock.RUnlock()

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mod.assessAndLog()
		case <-stop:
			return
		}
	}
}

func (mod *Assessment) assessAndLog() {
	if _, err := mod.Assess(); err != nil {
		mod.Error("%s", err)
	}
}

func (mod *Assessment) Assess() (*Report, error) {
	if err := mod.loadConfig(); err != nil {
		return nil, err
	}

	mod.runLock.Lock()
	defer mod.runLock.Unlock()

	started := time.Now()
	mod.State.Store("assessing", true)
	defer mod.State.Store("assessing", false)

	mod.stateLock.RLock()
	min := mod.min
	mod.stateLock.RUnlock()

	report := BuildReport(mod.snapshot(), min)
	report.GeneratedAt = started
	report.DurationMS = time.Since(started).Milliseconds()

	mod.stateLock.Lock()
	mod.last = report
	mod.stateLock.Unlock()

	mod.State.Store("host_count", report.HostCount)
	mod.State.Store("finding_count", report.FindingCount)
	mod.State.Store("findings", report.Findings)
	mod.State.Store("summary", report.Summary)
	mod.State.Store("last_report", report)

	mod.Session.Events.Add(EventTag, report)
	mod.Info("assessed %d hosts, found %d findings", report.HostCount, report.FindingCount)

	return report, nil
}

func (mod *Assessment) LastReport() *Report {
	mod.stateLock.RLock()
	defer mod.stateLock.RUnlock()
	return mod.last
}

func (mod *Assessment) Clear() {
	mod.stateLock.Lock()
	mod.last = nil
	mod.stateLock.Unlock()

	mod.State.Store("assessing", false)
	mod.State.Store("host_count", 0)
	mod.State.Store("finding_count", 0)
	mod.State.Store("findings", []Finding{})
	mod.State.Store("summary", SeveritySummary{})
	mod.State.Store("last_report", (*Report)(nil))
}

func (mod *Assessment) Show() error {
	report := mod.LastReport()
	if report == nil {
		mod.Printf("No assessment report available, run 'net.assessment run' first.\n")
		return nil
	}

	mod.Printf("Assessment generated at %s in %dms\n", report.GeneratedAt.Format(time.RFC3339), report.DurationMS)
	mod.Printf("Hosts: %d, findings: %d (critical=%d high=%d medium=%d low=%d info=%d)\n",
		report.HostCount,
		report.FindingCount,
		report.Summary.Critical,
		report.Summary.High,
		report.Summary.Medium,
		report.Summary.Low,
		report.Summary.Info)

	for _, finding := range report.Findings {
		target := finding.Address
		if finding.Port > 0 {
			target = fmt.Sprintf("%s:%d", target, finding.Port)
		}
		mod.Printf("[%s] %s %s\n", finding.Severity, target, finding.Message)
	}

	return nil
}

func (mod *Assessment) snapshot() []*network.Endpoint {
	if mod.provider != nil {
		return mod.provider.List()
	}
	if mod.Session == nil || mod.Session.Lan == nil {
		return nil
	}
	return mod.Session.Lan.List()
}

func BuildReport(hosts []*network.Endpoint, min Severity) *Report {
	report := &Report{
		Hosts:    make([]HostResult, 0, len(hosts)),
		Findings: make([]Finding, 0),
	}

	minRank := severityRank(min)
	for _, host := range hosts {
		if host == nil {
			continue
		}
		report.HostCount++

		result := HostResult{
			Address:   endpointAddress(host),
			MAC:       host.HwAddress,
			Hostname:  host.Hostname,
			Vendor:    host.Vendor,
			OpenPorts: collectOpenPorts(host),
		}
		report.Hosts = append(report.Hosts, result)

		for _, port := range result.OpenPorts {
			rule, found := riskyPorts[port.Port]
			if !found || severityRank(rule.severity) < minRank {
				continue
			}
			report.Findings = append(report.Findings, Finding{
				Code:     "exposed-service",
				Severity: rule.severity,
				Address:  result.Address,
				MAC:      result.MAC,
				Port:     port.Port,
				Service:  port.Service,
				Message:  rule.message,
			})
		}
	}

	sort.Slice(report.Hosts, func(i, j int) bool {
		if report.Hosts[i].Address == report.Hosts[j].Address {
			return report.Hosts[i].MAC < report.Hosts[j].MAC
		}
		return report.Hosts[i].Address < report.Hosts[j].Address
	})

	sort.Slice(report.Findings, func(i, j int) bool {
		left, right := report.Findings[i], report.Findings[j]
		if left.Severity != right.Severity {
			return severityRank(left.Severity) > severityRank(right.Severity)
		}
		if left.Address != right.Address {
			return left.Address < right.Address
		}
		return left.Port < right.Port
	})

	report.FindingCount = len(report.Findings)
	for _, finding := range report.Findings {
		switch finding.Severity {
		case SeverityCritical:
			report.Summary.Critical++
		case SeverityHigh:
			report.Summary.High++
		case SeverityMedium:
			report.Summary.Medium++
		case SeverityLow:
			report.Summary.Low++
		default:
			report.Summary.Info++
		}
	}

	return report
}

func ParseSeverity(value string) (Severity, error) {
	switch Severity(strings.ToLower(strings.TrimSpace(value))) {
	case SeverityInfo:
		return SeverityInfo, nil
	case SeverityLow:
		return SeverityLow, nil
	case SeverityMedium:
		return SeverityMedium, nil
	case SeverityHigh:
		return SeverityHigh, nil
	case SeverityCritical:
		return SeverityCritical, nil
	default:
		return "", fmt.Errorf("unknown severity %q", value)
	}
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func endpointAddress(host *network.Endpoint) string {
	if host.IpAddress != "" {
		return host.IpAddress
	}
	if host.IP != nil {
		return host.IP.String()
	}
	return host.HwAddress
}

func collectOpenPorts(host *network.Endpoint) []OpenPort {
	if host.Meta == nil {
		return nil
	}

	ports := make([]OpenPort, 0)
	add := func(port OpenPort, fallback int) {
		if port.Port == 0 {
			port.Port = fallback
		}
		if port.Port <= 0 || port.Port > 65535 {
			return
		}
		if port.Proto == "" {
			port.Proto = "tcp"
		}
		if port.Service == "" {
			port.Service = network.GetServiceByPort(port.Port, port.Proto)
		}
		ports = append(ports, port)
	}

	switch value := host.Meta.Get("ports").(type) {
	case map[int]*syn_scan.OpenPort:
		for port, info := range value {
			if info == nil {
				add(OpenPort{}, port)
			} else {
				add(OpenPort{
					Port:    info.Port,
					Proto:   info.Proto,
					Service: info.Service,
					Banner:  info.Banner,
				}, port)
			}
		}
	case map[int]syn_scan.OpenPort:
		for port, info := range value {
			add(OpenPort{
				Port:    info.Port,
				Proto:   info.Proto,
				Service: info.Service,
				Banner:  info.Banner,
			}, port)
		}
	case map[int]interface{}:
		for port, entry := range value {
			switch info := entry.(type) {
			case *syn_scan.OpenPort:
				if info == nil {
					add(OpenPort{}, port)
				} else {
					add(OpenPort{
						Port:    info.Port,
						Proto:   info.Proto,
						Service: info.Service,
						Banner:  info.Banner,
					}, port)
				}
			case syn_scan.OpenPort:
				add(OpenPort{
					Port:    info.Port,
					Proto:   info.Proto,
					Service: info.Service,
					Banner:  info.Banner,
				}, port)
			case OpenPort:
				add(info, port)
			default:
				add(OpenPort{}, port)
			}
		}
	case []*syn_scan.OpenPort:
		for _, info := range value {
			if info != nil {
				add(OpenPort{
					Port:    info.Port,
					Proto:   info.Proto,
					Service: info.Service,
					Banner:  info.Banner,
				}, 0)
			}
		}
	case []syn_scan.OpenPort:
		for _, info := range value {
			add(OpenPort{
				Port:    info.Port,
				Proto:   info.Proto,
				Service: info.Service,
				Banner:  info.Banner,
			}, 0)
		}
	case []OpenPort:
		for _, info := range value {
			add(info, 0)
		}
	case []int:
		for _, port := range value {
			add(OpenPort{}, port)
		}
	}

	byPort := make(map[int]OpenPort)
	for _, port := range ports {
		current, found := byPort[port.Port]
		if !found || (current.Banner == "" && port.Banner != "") {
			byPort[port.Port] = port
		}
	}

	ports = ports[:0]
	for _, port := range byPort {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].Port < ports[j].Port
	})
	return ports
}

type portRisk struct {
	severity Severity
	message  string
}

var riskyPorts = map[int]portRisk{
	21:    {SeverityHigh, "FTP service exposes a cleartext administrative protocol."},
	22:    {SeverityLow, "SSH administrative service is reachable from the network."},
	23:    {SeverityHigh, "Telnet service exposes a cleartext administrative protocol."},
	111:   {SeverityMedium, "RPC portmapper is reachable and may expose internal RPC services."},
	135:   {SeverityHigh, "Microsoft RPC endpoint mapper is reachable."},
	139:   {SeverityHigh, "NetBIOS service is reachable."},
	161:   {SeverityMedium, "SNMP service is reachable and may expose device information."},
	445:   {SeverityHigh, "SMB service is reachable."},
	512:   {SeverityHigh, "Legacy rexec service is reachable."},
	513:   {SeverityHigh, "Legacy rlogin service is reachable."},
	514:   {SeverityHigh, "Legacy rsh service is reachable."},
	1433:  {SeverityHigh, "Microsoft SQL Server is reachable from the network."},
	1521:  {SeverityHigh, "Oracle database listener is reachable from the network."},
	2049:  {SeverityHigh, "NFS service is reachable from the network."},
	2375:  {SeverityCritical, "Unauthenticated Docker API is reachable."},
	3306:  {SeverityHigh, "MySQL service is reachable from the network."},
	3389:  {SeverityHigh, "Remote Desktop service is reachable from the network."},
	5432:  {SeverityHigh, "PostgreSQL service is reachable from the network."},
	5900:  {SeverityHigh, "VNC service is reachable from the network."},
	6379:  {SeverityCritical, "Redis service is reachable and may allow unauthenticated access."},
	9200:  {SeverityHigh, "Elasticsearch HTTP API is reachable."},
	11211: {SeverityHigh, "Memcached service is reachable."},
	27017: {SeverityHigh, "MongoDB service is reachable from the network."},
}

var _ session.Module = (*Assessment)(nil)
