package events_stream

import (
	"fmt"
	"io"

	"github.com/bettercap/bettercap/v2/modules/net_assessment"
	"github.com/bettercap/bettercap/v2/session"

	"github.com/evilsocket/islazy/tui"
)

func (mod *EventsStream) viewAssessmentEvent(output io.Writer, e session.Event) {
	report, ok := e.Data.(*net_assessment.Report)
	if !ok || report == nil {
		fmt.Fprintf(output, "[%s] [%s] %v\n", e.Time.Format(mod.timeFormat), tui.Green(e.Tag), e.Data)
		return
	}

	fmt.Fprintf(output, "[%s] [%s] assessed %d hosts, %d findings (critical=%d high=%d medium=%d low=%d info=%d)\n",
		e.Time.Format(mod.timeFormat),
		tui.Green(e.Tag),
		report.HostCount,
		report.FindingCount,
		report.Summary.Critical,
		report.Summary.High,
		report.Summary.Medium,
		report.Summary.Low,
		report.Summary.Info)
}
