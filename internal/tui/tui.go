package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"edgesight/internal/analytics"
	"edgesight/internal/storage"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// tickMsg triggers UI refresh.
type tickMsg time.Time

// Model is the Bubble Tea model.
type Model struct {
	store    *storage.Store
	detector *analytics.Detector
	width    int
	height   int
	events   []string
	metrics  string
}

// NewModel creates a TUI model.
func NewModel(store *storage.Store, detector *analytics.Detector) *Model {
	return &Model{store: store, detector: detector}
}

// Init starts the tick command.
func (m Model) Init() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		m.refresh()
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
	}
	return m, nil
}

func (m *Model) refresh() {
	ms := m.detector.Metrics()
	m.metrics = fmt.Sprintf("Flows/s: %.1f | Bytes/s: %.0f | Active: %d | Alerts: %d",
		ms.FlowsPerSec, ms.BytesPerSec, ms.ActiveFlows, ms.Alerts)
	if m.store != nil {
		ev, err := m.store.ListEvents(context.Background(), "", 10, 0)
		if err == nil {
			var lines []string
			for _, e := range ev {
				lines = append(lines, fmt.Sprintf("[%s] %s %s S%d %s",
					e.Timestamp.Format("15:04:05"), e.Kind, e.Source, e.Severity, e.Title))
			}
			m.events = lines
		}
	}
}

// View renders the UI.
func (m Model) View() string {
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00d4aa"))
	boxStyle := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1)
	header := headerStyle.Render("EdgeSight Passive Network Detector")
	metrics := boxStyle.Render("Metrics\n" + m.metrics)
	body := "No events yet"
	if len(m.events) > 0 {
		body = strings.Join(m.events, "\n")
	}
	events := boxStyle.Render("Recent Events\n" + body)
	help := lipgloss.NewStyle().Foreground(lipgloss.Color("#7a8398")).Render("Press q to quit")
	return lipgloss.JoinVertical(lipgloss.Left, header, metrics, events, help)
}

// Run starts the Bubble Tea program.
func Run(store *storage.Store, detector *analytics.Detector) error {
	p := tea.NewProgram(NewModel(store, detector), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
