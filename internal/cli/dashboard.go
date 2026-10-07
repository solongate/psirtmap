package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"charm.land/bubbles/v2/filepicker"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/solongate/psirtmap/internal/store"
)

const (
	dashboardDefaultWidth  = 110
	dashboardDefaultHeight = 32
	dashboardMenuWidth     = 21
	dashboardMinWideWidth  = 88
	dashboardMinWideHeight = 28
)

type dashboardScreen int

const (
	screenOverview dashboardScreen = iota
	screenProducts
	screenReleases
	screenComponents
	screenFindings
	screenScanner
	screenFeeds
	screenCount
)

var dashboardScreens = []struct {
	label string
	hint  string
}{
	{label: "Overview", hint: "Inventory health and next actions"},
	{label: "Products", hint: "Product families you ship"},
	{label: "Releases", hint: "Released product versions"},
	{label: "Components", hint: "Third-party software inventory"},
	{label: "Findings", hint: "Durable potential-impact history"},
	{label: "Scanner", hint: "Local impact and KEV prioritization"},
	{label: "Feeds", hint: "Online updates and air-gapped transfer"},
}

type dashboardInventory struct {
	products    []store.Product
	releases    []store.Release
	components  []store.Component
	findings    []store.Finding
	assessments []store.Assessment
	sync        *store.VulnerabilitySync
	kevSync     *store.KEVSync
	feedImport  *store.FeedImport
}

type dashboardInventoryMsg struct {
	inventory dashboardInventory
	err       error
}

type dashboardSavedMsg struct {
	message string
	err     error
}

type dashboardScanMsg struct {
	result scanResult
	err    error
}

type dashboardSyncMsg struct {
	result intelligenceSyncResult
	err    error
}

type dashboardFormKind int

const (
	formNone dashboardFormKind = iota
	formProduct
	formRelease
	formComponent
	formSBOMImport
	formAssessment
	formQuickImport
	formFeedExport
	formFeedImport
)

type dashboardField struct {
	label        string
	hint         string
	input        textinput.Model
	file         bool
	choices      []string
	allowedTypes []string
}

type dashboardForm struct {
	kind   dashboardFormKind
	title  string
	fields []dashboardField
	active int
	err    error
	target *store.Finding
}

type dashboardModel struct {
	ctx         context.Context
	database    *store.DB
	querier     VulnerabilityQuerier
	kevFetcher  KEVFetcher
	width       int
	height      int
	screen      dashboardScreen
	focusMenu   bool
	selected    [screenCount]int
	data        dashboardInventory
	loaded      bool
	loading     bool
	form        dashboardForm
	showHelp    bool
	status      string
	statusErr   bool
	scanning    bool
	syncing     bool
	scan        *scanResult
	spinner     spinner.Model
	filePicker  filepicker.Model
	pickingFile bool
}

var (
	colorAccent = lipgloss.Color("#7C6CFF")
	colorCyan   = lipgloss.Color("#55D6BE")
	colorMuted  = lipgloss.Color("#8A8A96")
	colorError  = lipgloss.Color("#FF6B6B")
	colorWarn   = lipgloss.Color("#FFB86C")

	styleBrand = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F4F4F5"))
	styleMuted = lipgloss.NewStyle().Foreground(colorMuted)
	styleGood  = lipgloss.NewStyle().Foreground(colorCyan)
	styleWarn  = lipgloss.NewStyle().Foreground(colorWarn)
	styleError = lipgloss.NewStyle().Foreground(colorError)
	styleKey   = lipgloss.NewStyle().Bold(true).Foreground(colorCyan)
)

func runDashboard(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
	querier VulnerabilityQuerier,
	kevFetcher KEVFetcher,
) int {
	if len(args) == 1 && isHelp(args[0]) {
		printDashboardUsage(stdout)
		return 0
	}
	if len(args) != 0 {
		return usageError(stderr, errors.New("dashboard does not accept arguments"), printDashboardUsage)
	}
	if querier == nil {
		return commandError(stderr, errors.New("vulnerability service is unavailable"))
	}

	model := newDashboardModel(ctx, database, querier, kevFetcher)
	program := tea.NewProgram(model, tea.WithContext(ctx), tea.WithOutput(stdout))
	if _, err := program.Run(); err != nil {
		return commandError(stderr, fmt.Errorf("run dashboard: %w", err))
	}
	return 0
}

func newDashboardModel(ctx context.Context, database *store.DB, querier VulnerabilityQuerier, kevFetcher KEVFetcher) *dashboardModel {
	loader := spinner.New(
		spinner.WithSpinner(spinner.MiniDot),
		spinner.WithStyle(lipgloss.NewStyle().Foreground(colorAccent)),
	)
	picker := filepicker.New()
	picker.AllowedTypes = []string{".json", ".bundle"}
	picker.ShowPermissions = false
	picker.ShowSize = true
	picker.SetHeight(12)
	if workingDirectory, err := os.Getwd(); err == nil {
		picker.CurrentDirectory = workingDirectory
	}
	return &dashboardModel{
		ctx:        ctx,
		database:   database,
		querier:    querier,
		kevFetcher: kevFetcher,
		width:      dashboardDefaultWidth,
		height:     dashboardDefaultHeight,
		screen:     screenOverview,
		focusMenu:  true,
		loading:    true,
		spinner:    loader,
		filePicker: picker,
	}
}

func (m *dashboardModel) Init() tea.Cmd {
	return tea.Batch(m.loadInventory(), m.spinner.Tick)
}

func (m *dashboardModel) loadInventory() tea.Cmd {
	return func() tea.Msg {
		products, err := m.database.ListProducts(m.ctx)
		if err != nil {
			return dashboardInventoryMsg{err: err}
		}
		releases, err := m.database.ListReleases(m.ctx, "")
		if err != nil {
			return dashboardInventoryMsg{err: err}
		}
		components, err := m.database.ListAllComponents(m.ctx)
		if err != nil {
			return dashboardInventoryMsg{err: err}
		}
		findings, err := m.database.ListFindings(m.ctx, store.FindingFilter{})
		if err != nil {
			return dashboardInventoryMsg{err: err}
		}
		assessments, err := m.database.ListAssessments(m.ctx, store.AssessmentFilter{})
		if err != nil {
			return dashboardInventoryMsg{err: err}
		}
		inventory := dashboardInventory{
			products: products, releases: releases, components: components,
			findings: findings, assessments: assessments,
		}
		latestSync, err := m.database.LatestVulnerabilitySync(m.ctx)
		if err == nil {
			inventory.sync = &latestSync
		} else if !errors.Is(err, store.ErrSnapshotNotFound) {
			return dashboardInventoryMsg{err: err}
		}
		latestKEVSync, err := m.database.LatestKEVSync(m.ctx)
		if err == nil {
			inventory.kevSync = &latestKEVSync
		} else if !errors.Is(err, store.ErrSnapshotNotFound) {
			return dashboardInventoryMsg{err: err}
		}
		latestFeedImport, err := m.database.LatestFeedImport(m.ctx)
		if err == nil {
			inventory.feedImport = &latestFeedImport
		} else if !errors.Is(err, store.ErrSnapshotNotFound) {
			return dashboardInventoryMsg{err: err}
		}
		return dashboardInventoryMsg{inventory: inventory}
	}
}

func (m *dashboardModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if m.form.kind != formNone {
		return m.updateForm(message)
	}

	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = max(message.Width, 1)
		m.height = max(message.Height, 1)
		return m, nil
	case dashboardInventoryMsg:
		m.loading = false
		if message.err != nil {
			m.loaded = false
			m.setStatus(message.err.Error(), true)
			return m, nil
		}
		m.data = message.inventory
		m.loaded = true
		m.clampSelections()
		if m.status == "Refreshing inventory..." {
			m.setStatus("Inventory refreshed", false)
		}
		return m, nil
	case dashboardSavedMsg:
		if message.err != nil {
			m.form.err = message.err
			m.loading = false
			return m, nil
		}
		m.form = dashboardForm{}
		m.loading = true
		m.setStatus(message.message, false)
		return m, m.loadInventory()
	case dashboardScanMsg:
		m.scanning = false
		if message.err != nil {
			m.setStatus(message.err.Error(), true)
			return m, nil
		}
		m.scan = &message.result
		m.setStatus(fmt.Sprintf(
			"Scan saved: %d potential findings (%d new, %d no longer matched)",
			len(message.result.Findings), message.result.New, message.result.NoLongerMatched,
		), false)
		return m, m.loadInventory()
	case dashboardSyncMsg:
		m.syncing = false
		if message.err != nil {
			m.setStatus(message.err.Error(), true)
			return m, nil
		}
		status := fmt.Sprintf(
			"OSV updated: %d packages, %d vulnerabilities",
			message.result.OSV.Packages, message.result.OSV.Vulnerabilities,
		)
		if message.result.CISAKEV != nil {
			status += fmt.Sprintf("; CISA KEV: %d entries", message.result.CISAKEV.Entries)
		}
		m.setStatus(status, false)
		return m, m.loadInventory()
	case spinner.TickMsg:
		var command tea.Cmd
		m.spinner, command = m.spinner.Update(message)
		if m.loading || m.scanning || m.syncing {
			return m, command
		}
		return m, nil
	case tea.KeyPressMsg:
		key := message.String()
		if m.showHelp {
			switch key {
			case "?", "esc", "enter":
				m.showHelp = false
			case "q", "ctrl+c":
				return m, tea.Quit
			}
			return m, nil
		}

		switch key {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?":
			m.showHelp = true
			return m, nil
		case "tab":
			m.focusMenu = !m.focusMenu
			return m, nil
		case "left", "h", "esc":
			m.focusMenu = true
			return m, nil
		case "right", "l":
			m.focusMenu = false
			return m, nil
		case "r":
			m.loading = true
			m.setStatus("Refreshing inventory...", false)
			return m, tea.Batch(m.loadInventory(), m.spinner.Tick)
		case "n":
			if m.screen == screenOverview && len(m.data.products) == 0 {
				return m, m.openQuickImportForm()
			}
			return m, m.openCreateForm()
		case "i":
			if m.screen == screenOverview && len(m.data.products) == 0 {
				return m, m.openQuickImportForm()
			}
			return m, m.openImportForm()
		case "e":
			if m.screen == screenFeeds {
				return m, m.openFeedExportForm()
			}
		case "a":
			return m, m.openAssessmentForm()
		case "s":
			if m.screen == screenScanner {
				return m.startScan()
			}
		case "u":
			return m.startSync()
		}

		if numericScreen, ok := screenFromKey(key); ok {
			m.screen = numericScreen
			m.focusMenu = false
			return m, nil
		}

		switch key {
		case "up", "k":
			m.moveSelection(-1)
		case "down", "j":
			m.moveSelection(1)
		case "home", "g":
			m.moveToBoundary(false)
		case "end", "G":
			m.moveToBoundary(true)
		case "enter":
			if m.screen == screenOverview {
				return m.primaryAction()
			} else if m.focusMenu {
				m.focusMenu = false
			} else if m.screen == screenScanner {
				return m.startScan()
			} else if m.screen == screenFindings {
				return m, m.openAssessmentForm()
			} else if m.screen == screenFeeds {
				return m.feedAction()
			}
		}
	}
	return m, nil
}

func (m *dashboardModel) primaryAction() (tea.Model, tea.Cmd) {
	if len(m.data.products) == 0 {
		return m, m.openQuickImportForm()
	}
	if len(m.data.components) == 0 {
		m.screen = screenReleases
		m.focusMenu = false
		return m, m.openImportForm()
	}
	if m.data.sync == nil {
		return m.startSync()
	}
	if len(m.data.findings) > 0 {
		m.screen = screenFindings
		m.focusMenu = false
		return m, nil
	}
	m.screen = screenScanner
	m.focusMenu = false
	return m, nil
}

func (m *dashboardModel) openQuickImportForm() tea.Cmd {
	m.form = dashboardForm{
		kind:  formQuickImport,
		title: "Import your first shipped release",
		fields: []dashboardField{
			newDashboardField("Product name", "The product family customers receive", "AG-200"),
			newDashboardField("Description (optional)", "A short description of the product", "Industrial gateway"),
			newDashboardField("Release version", "The shipped firmware or software version", "2.2"),
			newDashboardFileField("CycloneDX JSON", "Press Ctrl+O to browse, or type / drag the file path", "./firmware.cdx.json", []string{".json"}),
		},
	}
	m.form.fields[0].input.Focus()
	return nil
}

func (m *dashboardModel) feedAction() (tea.Model, tea.Cmd) {
	switch m.selected[screenFeeds] {
	case 0:
		return m.startSync()
	case 1:
		return m, m.openFeedImportForm()
	case 2:
		return m, m.openFeedExportForm()
	default:
		return m, nil
	}
}

func (m *dashboardModel) openFeedImportForm() tea.Cmd {
	m.form = dashboardForm{
		kind:  formFeedImport,
		title: "Import offline vulnerability feed",
		fields: []dashboardField{
			newDashboardFileField("Bundle path", "Press Ctrl+O to browse for a trusted .bundle file", "./psirtmap-feed.bundle", []string{".bundle"}),
		},
	}
	m.form.fields[0].input.Focus()
	return nil
}

func (m *dashboardModel) openFeedExportForm() tea.Cmd {
	createdAt := time.Now().UTC().Truncate(time.Second)
	m.form = dashboardForm{
		kind:  formFeedExport,
		title: "Export offline vulnerability feed",
		fields: []dashboardField{
			newDashboardFieldWithValue(
				"Output path",
				"A new .bundle file; existing files are never overwritten",
				fmt.Sprintf("./psirtmap-feed-%s.bundle", createdAt.Format("20060102T150405Z")),
			),
		},
	}
	m.form.fields[0].input.Focus()
	return nil
}

func (m *dashboardModel) openImportForm() tea.Cmd {
	if m.screen == screenFeeds {
		return m.openFeedImportForm()
	}
	if m.screen != screenReleases {
		m.setStatus("Open Releases and press i to import a CycloneDX SBOM", false)
		return nil
	}
	if len(m.data.products) == 0 {
		m.setStatus("Create a product before importing a release SBOM", true)
		return nil
	}
	reference := m.data.products[min(m.selected[screenProducts], len(m.data.products)-1)].Name + "@2.2"
	if len(m.data.releases) > 0 {
		release := m.data.releases[min(m.selected[screenReleases], len(m.data.releases)-1)]
		reference = release.Product + "@" + release.Version
	}
	m.form = dashboardForm{
		kind:  formSBOMImport,
		title: "Import CycloneDX release SBOM",
		fields: []dashboardField{
			newDashboardFieldWithValue("Product@release", "Existing product; the release may be new", reference),
			newDashboardFileField("CycloneDX JSON path", "Press Ctrl+O to browse, or type / drag the file path", "./firmware.cdx.json", []string{".json"}),
		},
	}
	m.form.fields[0].input.Focus()
	return nil
}

func (m *dashboardModel) openAssessmentForm() tea.Cmd {
	if m.screen != screenFindings {
		m.setStatus("Open Findings and press a or Enter to record an assessment", false)
		return nil
	}
	if len(m.data.findings) == 0 {
		m.setStatus("Run a local release scan before recording an assessment", true)
		return nil
	}
	selected := min(m.selected[screenFindings], len(m.data.findings)-1)
	finding := m.data.findings[selected]
	m.form = dashboardForm{
		kind:   formAssessment,
		title:  "Assess " + finding.VulnerabilityID + " in " + finding.Product + "@" + finding.Release,
		target: &finding,
		fields: []dashboardField{
			newDashboardChoiceField(
				"Status", "Use ←/→ to choose; no typing required",
				[]string{store.AssessmentInvestigating, store.AssessmentAffected, store.AssessmentNotAffected, store.AssessmentFixed},
				store.AssessmentInvestigating,
			),
			newDashboardField("Reason", "Required for affected, not-affected, and fixed", "Feature disabled in this firmware build"),
			newDashboardField("Reviewer", "Person responsible for this decision", "reviewer name"),
			newDashboardField("Evidence (optional)", "Ticket, test report, advisory, or other reference", "SEC-123 or document reference"),
		},
	}
	m.form.fields[0].input.Focus()
	return nil
}

func (m *dashboardModel) updateForm(message tea.Msg) (tea.Model, tea.Cmd) {
	if m.pickingFile {
		return m.updateFilePicker(message)
	}
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = max(message.Width, 1)
		m.height = max(message.Height, 1)
		return m, nil
	case dashboardSavedMsg:
		if message.err != nil {
			m.form.err = message.err
			m.loading = false
			return m, nil
		}
		m.form = dashboardForm{}
		m.loading = true
		m.setStatus(message.message, false)
		return m, m.loadInventory()
	case spinner.TickMsg:
		var command tea.Cmd
		m.spinner, command = m.spinner.Update(message)
		if m.loading {
			return m, command
		}
		return m, nil
	case tea.KeyPressMsg:
		if m.loading {
			if message.String() == "ctrl+c" {
				return m, tea.Quit
			}
			return m, nil
		}
		switch message.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			m.form = dashboardForm{}
			m.setStatus("Action canceled", false)
			return m, nil
		case "ctrl+o":
			if len(m.form.fields) > 0 && m.form.fields[m.form.active].file {
				return m, m.openFilePicker()
			}
		case "left":
			if m.changeChoice(-1) {
				return m, nil
			}
		case "right":
			if m.changeChoice(1) {
				return m, nil
			}
		case "tab", "down":
			return m, m.focusFormField(1)
		case "shift+tab", "up":
			return m, m.focusFormField(-1)
		case "enter":
			if m.form.active < len(m.form.fields)-1 {
				return m, m.focusFormField(1)
			}
			m.loading = true
			m.form.err = nil
			return m, tea.Batch(m.saveForm(), m.spinner.Tick)
		}
	}

	if m.loading || len(m.form.fields) == 0 {
		return m, nil
	}
	active := m.form.active
	if len(m.form.fields[active].choices) > 0 {
		return m, nil
	}
	updated, command := m.form.fields[active].input.Update(message)
	m.form.fields[active].input = updated
	m.form.err = nil
	return m, command
}

func (m *dashboardModel) changeChoice(delta int) bool {
	if len(m.form.fields) == 0 {
		return false
	}
	field := &m.form.fields[m.form.active]
	if len(field.choices) == 0 {
		return false
	}
	current := 0
	for index, choice := range field.choices {
		if choice == field.input.Value() {
			current = index
			break
		}
	}
	current = (current + delta + len(field.choices)) % len(field.choices)
	field.input.SetValue(field.choices[current])
	m.form.err = nil
	return true
}

func (m *dashboardModel) openFilePicker() tea.Cmd {
	field := m.form.fields[m.form.active]
	picker := filepicker.New()
	picker.AllowedTypes = append([]string(nil), field.allowedTypes...)
	picker.ShowPermissions = false
	picker.ShowSize = true
	picker.SetHeight(max(5, min(14, m.height-10)))
	currentValue := strings.TrimSpace(field.input.Value())
	if currentValue != "" {
		directory := currentValue
		if info, err := os.Stat(currentValue); err == nil && !info.IsDir() {
			directory = filepath.Dir(currentValue)
		} else if filepath.Ext(currentValue) != "" {
			directory = filepath.Dir(currentValue)
		}
		if absolute, err := filepath.Abs(directory); err == nil {
			if info, statErr := os.Stat(absolute); statErr == nil && info.IsDir() {
				picker.CurrentDirectory = absolute
			}
		}
	}
	m.filePicker = picker
	m.pickingFile = true
	return m.filePicker.Init()
}

func (m *dashboardModel) updateFilePicker(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			m.pickingFile = false
			return m, nil
		}
	}
	updated, command := m.filePicker.Update(message)
	m.filePicker = updated
	if selected, path := m.filePicker.DidSelectFile(message); selected {
		m.form.fields[m.form.active].input.SetValue(path)
		m.pickingFile = false
		m.form.err = nil
		return m, nil
	}
	if disabled, path := m.filePicker.DidSelectDisabledFile(message); disabled {
		m.form.err = fmt.Errorf("unsupported file type: %s", filepath.Base(path))
	}
	return m, command
}

func (m *dashboardModel) openCreateForm() tea.Cmd {
	var form dashboardForm
	switch m.screen {
	case screenOverview, screenProducts:
		form = dashboardForm{
			kind:  formProduct,
			title: "Create product",
			fields: []dashboardField{
				newDashboardField("Product name", "Example: AG-200", "AG-200"),
				newDashboardField("Description (optional)", "What does this product do?", "Industrial gateway"),
			},
		}
	case screenReleases:
		if len(m.data.products) == 0 {
			m.setStatus("Create a product before adding a release", true)
			return nil
		}
		product := m.data.products[min(m.selected[screenProducts], len(m.data.products)-1)].Name
		form = dashboardForm{
			kind:  formRelease,
			title: "Create product release",
			fields: []dashboardField{
				newDashboardFieldWithValue("Product", "Existing product name", product),
				newDashboardField("Release version", "Version customers receive", "2.2"),
			},
		}
	case screenComponents:
		if len(m.data.releases) == 0 {
			m.setStatus("Create a release before adding a component", true)
			return nil
		}
		release := m.data.releases[min(m.selected[screenReleases], len(m.data.releases)-1)]
		form = dashboardForm{
			kind:  formComponent,
			title: "Add release component",
			fields: []dashboardField{
				newDashboardFieldWithValue("Product@release", "Existing shipped release", release.Product+"@"+release.Version),
				newDashboardFieldWithValue("OSV ecosystem", "Examples: Alpine, Debian, Go, npm, PyPI", "Alpine"),
				newDashboardField("Package name", "Package identity in that ecosystem", "openssl"),
				newDashboardField("Package version", "Exact version in the release", "3.0.8"),
			},
		}
	case screenFindings:
		return m.openAssessmentForm()
	case screenScanner:
		m.setStatus("Select a release and press s or Enter to scan", false)
		return nil
	case screenFeeds:
		return m.openFeedImportForm()
	}

	m.form = form
	m.form.fields[0].input.Focus()
	return nil
}

func newDashboardField(label, hint, placeholder string) dashboardField {
	input := textinput.New()
	input.Prompt = ""
	input.Placeholder = placeholder
	input.CharLimit = 1024
	input.SetWidth(48)
	return dashboardField{label: label, hint: hint, input: input}
}

func newDashboardFieldWithValue(label, hint, value string) dashboardField {
	field := newDashboardField(label, hint, "")
	field.input.SetValue(value)
	return field
}

func newDashboardFileField(label, hint, placeholder string, allowedTypes []string) dashboardField {
	field := newDashboardField(label, hint, placeholder)
	field.file = true
	field.allowedTypes = append([]string(nil), allowedTypes...)
	return field
}

func newDashboardChoiceField(label, hint string, choices []string, value string) dashboardField {
	field := newDashboardFieldWithValue(label, hint, value)
	field.choices = append([]string(nil), choices...)
	return field
}

func (m *dashboardModel) focusFormField(delta int) tea.Cmd {
	if len(m.form.fields) == 0 {
		return nil
	}
	m.form.fields[m.form.active].input.Blur()
	m.form.active = (m.form.active + delta + len(m.form.fields)) % len(m.form.fields)
	return m.form.fields[m.form.active].input.Focus()
}

func (m *dashboardModel) saveForm() tea.Cmd {
	kind := m.form.kind
	values := make([]string, len(m.form.fields))
	for index, field := range m.form.fields {
		values[index] = field.input.Value()
	}
	return func() tea.Msg {
		switch kind {
		case formProduct:
			product, err := m.database.CreateProduct(m.ctx, values[0], values[1])
			return dashboardSavedMsg{message: "Created product " + product.Name, err: err}
		case formRelease:
			release, err := m.database.CreateRelease(m.ctx, values[0], values[1])
			return dashboardSavedMsg{message: "Created release " + release.Product + "@" + release.Version, err: err}
		case formComponent:
			product, release, err := splitReference(values[0], "release")
			if err != nil {
				return dashboardSavedMsg{err: err}
			}
			component, err := m.database.CreateComponent(m.ctx, product, release, values[1], values[2], values[3])
			return dashboardSavedMsg{
				message: fmt.Sprintf("Added %s@%s to %s@%s", component.Name, component.Version, component.Product, component.ReleaseVersion),
				err:     err,
			}
		case formSBOMImport:
			product, release, err := splitReference(values[0], "release")
			if err != nil {
				return dashboardSavedMsg{err: err}
			}
			result, err := importReleaseSBOM(m.ctx, m.database, product, release, values[1])
			return dashboardSavedMsg{
				message: fmt.Sprintf(
					"Imported %d components into %s@%s (%d skipped)",
					result.Imported, result.Product, result.Release, result.Skipped,
				),
				err: err,
			}
		case formQuickImport:
			result, err := importProductReleaseSBOM(
				m.ctx, m.database, values[0], values[1], values[2], values[3], true,
			)
			return dashboardSavedMsg{
				message: fmt.Sprintf(
					"Imported %s@%s with %d components; next, update vulnerability data",
					result.Product, result.Release, result.Imported,
				),
				err: err,
			}
		case formAssessment:
			if m.form.target == nil {
				return dashboardSavedMsg{err: errors.New("assessment target is unavailable")}
			}
			target := *m.form.target
			assessment, err := m.database.CreateAssessment(m.ctx, store.AssessmentTarget{
				Product: target.Product, Release: target.Release,
				VulnerabilityID: target.VulnerabilityID, Ecosystem: target.Ecosystem,
				Component: target.Component, ComponentVersion: target.ComponentVersion,
			}, store.AssessmentInput{
				Status: values[0], Reason: values[1], Reviewer: values[2], Evidence: values[3],
			})
			return dashboardSavedMsg{
				message: fmt.Sprintf("Recorded %s assessment for %s", assessment.Status, assessment.VulnerabilityID),
				err:     err,
			}
		case formFeedExport:
			info, err := exportFeedBundle(m.ctx, m.database, values[0], time.Now().UTC().Truncate(time.Second))
			return dashboardSavedMsg{
				message: fmt.Sprintf("Exported offline feed to %s (%d packages)", info.Path, info.Packages),
				err:     err,
			}
		case formFeedImport:
			_, result, err := importFeedBundle(m.ctx, m.database, values[0])
			return dashboardSavedMsg{
				message: fmt.Sprintf("Imported offline feed: %d packages, %d vulnerabilities", result.Packages, result.Vulnerabilities),
				err:     err,
			}
		default:
			return dashboardSavedMsg{err: errors.New("unknown create action")}
		}
	}
}

func (m *dashboardModel) startScan() (tea.Model, tea.Cmd) {
	if m.scanning {
		return m, nil
	}
	if m.syncing {
		m.setStatus("Wait for the vulnerability data update to finish", false)
		return m, nil
	}
	if len(m.data.releases) == 0 {
		m.setStatus("No releases to scan", true)
		return m, nil
	}
	if m.data.sync == nil {
		m.setStatus("No local OSV snapshot; press u to update it first", true)
		return m, nil
	}
	selected := min(m.selected[screenScanner], len(m.data.releases)-1)
	release := m.data.releases[selected]
	m.scanning = true
	m.scan = nil
	m.setStatus("Scanning "+release.Product+"@"+release.Version+" from the local OSV snapshot...", false)
	return m, tea.Batch(m.scanRelease(release), m.spinner.Tick)
}

func (m *dashboardModel) scanRelease(release store.Release) tea.Cmd {
	return func() tea.Msg {
		components, err := m.database.ListComponents(m.ctx, release.Product, release.Version)
		if err != nil {
			return dashboardScanMsg{err: err}
		}
		result := scanResult{
			Product: release.Product, Release: release.Version,
			Components: len(components), DataSource: "local-osv-snapshot", Findings: []finding{},
		}
		if len(components) > 0 {
			var synchronizedAt time.Time
			result.Findings, synchronizedAt, err = scanComponentsLocal(m.ctx, components, m.database)
			if !synchronizedAt.IsZero() {
				result.SynchronizedAt = synchronizedAt.Format(time.RFC3339)
			}
		}
		if err == nil {
			err = enrichScanResultWithKEV(m.ctx, m.database, &result)
		}
		if err == nil {
			err = persistScanResult(m.ctx, m.database, &result)
		}
		return dashboardScanMsg{result: result, err: err}
	}
}

func (m *dashboardModel) startSync() (tea.Model, tea.Cmd) {
	if m.syncing {
		return m, nil
	}
	if m.scanning {
		m.setStatus("Wait for the release scan to finish", false)
		return m, nil
	}
	if len(m.data.components) == 0 {
		m.setStatus("Import an SBOM or add a component before updating vulnerability data", true)
		return m, nil
	}
	if m.querier == nil {
		m.setStatus("Vulnerability service is unavailable", true)
		return m, nil
	}
	m.syncing = true
	m.setStatus("Updating local OSV and CISA KEV data. This uses the internet...", false)
	return m, tea.Batch(m.syncSnapshot(), m.spinner.Tick)
}

func (m *dashboardModel) syncSnapshot() tea.Cmd {
	return func() tea.Msg {
		packages, err := m.database.ListPackageVersions(m.ctx)
		if err != nil {
			return dashboardSyncMsg{err: err}
		}
		result, err := synchronizeIntelligence(m.ctx, m.database, packages, m.querier, m.kevFetcher)
		return dashboardSyncMsg{result: result, err: err}
	}
}

func (m *dashboardModel) moveSelection(delta int) {
	if m.focusMenu {
		next := int(m.screen) + delta
		if next < 0 {
			next = int(screenCount) - 1
		}
		if next >= int(screenCount) {
			next = 0
		}
		m.screen = dashboardScreen(next)
		return
	}

	length := m.currentListLength()
	if length == 0 {
		return
	}
	next := m.selected[m.screen] + delta
	if next < 0 {
		next = length - 1
	}
	if next >= length {
		next = 0
	}
	m.selected[m.screen] = next
}

func (m *dashboardModel) moveToBoundary(end bool) {
	if m.focusMenu {
		if end {
			m.screen = screenCount - 1
		} else {
			m.screen = screenOverview
		}
		return
	}
	if end && m.currentListLength() > 0 {
		m.selected[m.screen] = m.currentListLength() - 1
	} else {
		m.selected[m.screen] = 0
	}
}

func (m *dashboardModel) currentListLength() int {
	switch m.screen {
	case screenProducts:
		return len(m.data.products)
	case screenReleases, screenScanner:
		return len(m.data.releases)
	case screenComponents:
		return len(m.data.components)
	case screenFindings:
		return len(m.data.findings)
	case screenFeeds:
		return 3
	default:
		return 0
	}
}

func (m *dashboardModel) clampSelections() {
	currentScreen := m.screen
	defer func() { m.screen = currentScreen }()
	for screen := screenProducts; screen < screenCount; screen++ {
		m.screen = screen
		length := m.currentListLength()
		if length == 0 {
			m.selected[screen] = 0
		} else if m.selected[screen] >= length {
			m.selected[screen] = length - 1
		}
	}
}

func (m *dashboardModel) setStatus(message string, isError bool) {
	m.status = oneLine(message)
	m.statusErr = isError
}

func screenFromKey(key string) (dashboardScreen, bool) {
	switch key {
	case "1":
		return screenOverview, true
	case "2":
		return screenProducts, true
	case "3":
		return screenReleases, true
	case "4":
		return screenComponents, true
	case "5":
		return screenFindings, true
	case "6":
		return screenScanner, true
	case "7":
		return screenFeeds, true
	default:
		return screenOverview, false
	}
}

func (m *dashboardModel) View() tea.View {
	header := m.renderHeader()
	footer := m.renderFooter()
	bodyHeight := max(5, m.height-lipgloss.Height(header)-lipgloss.Height(footer)-2)
	body := m.renderBody(bodyHeight)
	content := strings.Join([]string{header, body, footer}, "\n")

	view := tea.NewView(content)
	view.AltScreen = true
	view.WindowTitle = "PSIRTMap — shipped product vulnerability impact"
	return view
}

func (m *dashboardModel) renderHeader() string {
	subtitle := styleMuted.Render("shipped-product vulnerability impact  •  local-first  •  human-reviewed")
	if m.width < dashboardMinWideWidth || m.height < dashboardMinWideHeight {
		return fitText(styleBrand.Render("PSIRTMAP")+"  "+subtitle, m.width)
	}
	banner := `██████╗ ███████╗██╗██████╗ ████████╗███╗   ███╗ █████╗ ██████╗
██╔══██╗██╔════╝██║██╔══██╗╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗
██████╔╝███████╗██║██████╔╝   ██║   ██╔████╔██║███████║██████╔╝
██╔═══╝ ╚════██║██║██╔══██╗   ██║   ██║╚██╔╝██║██╔══██║██╔═══╝
██║     ███████║██║██║  ██║   ██║   ██║ ╚═╝ ██║██║  ██║██║
╚═╝     ╚══════╝╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝`
	wideSubtitle := styleMuted.Render("PSIRTMAP  •  shipped-product vulnerability impact  •  local-first  •  human-reviewed")
	return styleBrand.Render(banner) + "\n" + fitText(wideSubtitle, m.width)
}

func (m *dashboardModel) renderBody(height int) string {
	if m.width < 58 {
		return m.renderCompactBody(height)
	}

	menuContentWidth := min(dashboardMenuWidth, max(16, m.width/4))
	mainContentWidth := max(24, m.width-menuContentWidth-1)
	panelHeight := max(3, height-2)
	menu := m.renderMenu(menuContentWidth, panelHeight)
	main := m.renderMain(mainContentWidth, panelHeight)
	return lipgloss.JoinHorizontal(lipgloss.Top, menu, " ", main)
}

func (m *dashboardModel) renderCompactBody(height int) string {
	tabs := make([]string, 0, len(dashboardScreens))
	for index, item := range dashboardScreens {
		label := fmt.Sprintf("%d:%s", index+1, item.label)
		if dashboardScreen(index) == m.screen {
			label = styleBrand.Render("[" + label + "]")
		}
		tabs = append(tabs, label)
	}
	tabLine := fitText(strings.Join(tabs, " "), m.width)
	mainHeight := max(2, height-1)
	return tabLine + "\n" + m.renderMain(max(20, m.width), mainHeight)
}

func (m *dashboardModel) renderMenu(width, height int) string {
	innerWidth := max(4, width-4)
	lines := []string{styleTitle.Render("Workspace"), ""}
	for index, item := range dashboardScreens {
		marker := "  "
		label := item.label
		if dashboardScreen(index) == m.screen {
			marker = "▸ "
			label = styleBrand.Render(label)
		}
		lines = append(lines, fitText(marker+label, innerWidth))
	}
	lines = append(lines, "", styleMuted.Render("Database"), fitText(oneLine(m.database.Path()), innerWidth))
	if m.focusMenu {
		lines = append(lines, "", styleGood.Render("● navigation active"))
	}
	return panelStyle(width, height, m.focusMenu).Render(strings.Join(lines, "\n"))
}

func (m *dashboardModel) renderMain(width, height int) string {
	innerWidth := max(4, width-4)
	innerHeight := max(1, height-2)
	var content string
	switch {
	case m.showHelp:
		content = m.renderHelp(innerWidth)
	case m.form.kind != formNone:
		content = m.renderForm(innerWidth)
	case m.loading && !m.loaded:
		content = m.spinner.View() + " Loading local inventory..."
	default:
		switch m.screen {
		case screenOverview:
			content = m.renderOverview(innerWidth, innerHeight)
		case screenProducts:
			content = m.renderProducts(innerWidth, innerHeight)
		case screenReleases:
			content = m.renderReleases(innerWidth, innerHeight)
		case screenComponents:
			content = m.renderComponents(innerWidth, innerHeight)
		case screenFindings:
			content = m.renderFindings(innerWidth, innerHeight)
		case screenScanner:
			content = m.renderScanner(innerWidth, innerHeight)
		case screenFeeds:
			content = m.renderFeeds(innerWidth, innerHeight)
		}
	}
	return panelStyle(width, height, !m.focusMenu).Render(content)
}

func panelStyle(width, height int, active bool) lipgloss.Style {
	border := colorMuted
	if active {
		border = colorAccent
	}
	return lipgloss.NewStyle().
		Width(width).
		Height(height).
		Padding(0, 1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border)
}

func (m *dashboardModel) renderOverview(width, height int) string {
	title := styleTitle.Render("Overview") + "  " + styleMuted.Render(dashboardScreens[screenOverview].hint)
	counts := fmt.Sprintf(
		"%s  %s  %s  %s",
		metric("PRODUCTS", len(m.data.products)),
		metric("RELEASES", len(m.data.releases)),
		metric("COMPONENTS", len(m.data.components)),
		metric("FINDINGS", len(m.data.findings)),
	)
	lines := []string{title, "", counts, "", styleTitle.Render("Data sources")}
	lines = append(lines,
		statusLine("●", "Local inventory", "READY", true),
		statusLine("●", "CycloneDX import", "READY", true),
		statusLine("●", "Finding history", "READY", true),
		statusLine("●", "Human assessments", "READY", true),
	)
	if m.data.sync == nil {
		lines = append(lines, statusLine("○", "Local OSV snapshot", "NOT SYNCED", false))
	} else {
		lines = append(lines, statusLine("●", "Local OSV snapshot", m.data.sync.SynchronizedAt.Format("2006-01-02 15:04Z"), true))
	}
	if m.data.kevSync == nil {
		lines = append(lines, statusLine("○", "CISA KEV catalog", "NOT SYNCED", false))
	} else {
		lines = append(lines, statusLine("●", "CISA KEV catalog", m.data.kevSync.SynchronizedAt.Format("2006-01-02 15:04Z"), true))
	}
	if m.data.feedImport == nil {
		lines = append(lines, statusLine("●", "Offline feed transfer", "READY", true))
	} else {
		lines = append(lines, statusLine(
			"●", "Offline feed imported", m.data.feedImport.ImportedAt.Format("2006-01-02 15:04Z"), true,
		))
	}
	if height >= 15 {
		lines = append(lines, "", styleTitle.Render("Recommended next action"))
		lines = append(lines,
			"  "+styleKey.Render("Enter")+"  "+m.primaryActionText(),
			styleMuted.Render("  Shortcuts remain available, but they are never required."),
		)
	}
	if len(m.data.releases) > 0 && height > 17 {
		lines = append(lines, "", styleTitle.Render("Shipped releases"))
		start := max(0, len(m.data.releases)-3)
		for _, release := range m.data.releases[start:] {
			lines = append(lines, "  "+fitText(release.Product+"@"+release.Version, max(8, width-2)))
		}
	}
	return strings.Join(lines, "\n")
}

func (m *dashboardModel) primaryActionText() string {
	switch {
	case len(m.data.products) == 0:
		return "Import your first shipped release with the guided setup"
	case len(m.data.components) == 0:
		return "Import a CycloneDX SBOM into a product release"
	case m.data.sync == nil:
		return "Update OSV and CISA KEV vulnerability intelligence"
	case len(m.data.findings) > 0:
		return "Review and assess potential-impact findings"
	default:
		return "Open the release scanner"
	}
}

func metric(label string, value int) string {
	return styleBrand.Render(fmt.Sprintf("%d", value)) + " " + styleMuted.Render(label)
}

func statusLine(marker, label, status string, ready bool) string {
	statusStyle := styleWarn
	if ready {
		statusStyle = styleGood
	}
	return fmt.Sprintf("  %s %-26s %s", statusStyle.Render(marker), label, statusStyle.Render(status))
}

func (m *dashboardModel) renderProducts(width, height int) string {
	lines := []string{
		styleTitle.Render("Products") + "  " + styleMuted.Render(fmt.Sprintf("%d total", len(m.data.products))),
		styleMuted.Render("Product family" + strings.Repeat(" ", 17) + "Description"),
	}
	if len(m.data.products) == 0 {
		return strings.Join(append(lines, "", "No products yet.", styleMuted.Render("Press n to create your first product.")), "\n")
	}
	rows := visibleRange(len(m.data.products), m.selected[screenProducts], max(1, height-4))
	nameWidth := min(28, max(12, width/3))
	for index := rows.start; index < rows.end; index++ {
		product := m.data.products[index]
		row := fmt.Sprintf("%-*s  %s", nameWidth, fitText(product.Name, nameWidth), fitText(oneLine(product.Description), max(8, width-nameWidth-4)))
		lines = append(lines, selectableRow(row, index == m.selected[screenProducts]))
	}
	return strings.Join(lines, "\n")
}

func (m *dashboardModel) renderReleases(width, height int) string {
	lines := []string{
		styleTitle.Render("Releases") + "  " + styleMuted.Render(fmt.Sprintf("%d shipped versions", len(m.data.releases))),
		styleMuted.Render("Release" + strings.Repeat(" ", 24) + "Components"),
	}
	if len(m.data.releases) == 0 {
		return strings.Join(append(lines, "", "No releases yet.", styleMuted.Render("Press n to add one manually or i to import a CycloneDX SBOM.")), "\n")
	}
	rows := visibleRange(len(m.data.releases), m.selected[screenReleases], max(1, height-4))
	for index := rows.start; index < rows.end; index++ {
		release := m.data.releases[index]
		reference := release.Product + "@" + release.Version
		row := fmt.Sprintf("%-32s  %d", fitText(reference, 32), m.componentCount(release))
		lines = append(lines, selectableRow(fitText(row, width), index == m.selected[screenReleases]))
	}
	return strings.Join(lines, "\n")
}

func (m *dashboardModel) renderComponents(width, height int) string {
	lines := []string{
		styleTitle.Render("Components") + "  " + styleMuted.Render(fmt.Sprintf("%d packages", len(m.data.components))),
		styleMuted.Render("Package" + strings.Repeat(" ", 20) + "Ecosystem     Shipped in"),
	}
	if len(m.data.components) == 0 {
		return strings.Join(append(lines, "", "No components yet.", styleMuted.Render("Press n to record a component in a release.")), "\n")
	}
	rows := visibleRange(len(m.data.components), m.selected[screenComponents], max(1, height-4))
	packageWidth := min(28, max(14, width/3))
	for index := rows.start; index < rows.end; index++ {
		component := m.data.components[index]
		packageRef := component.Name + "@" + component.Version
		releaseRef := component.Product + "@" + component.ReleaseVersion
		row := fmt.Sprintf("%-*s  %-12s  %s",
			packageWidth, fitText(packageRef, packageWidth), fitText(component.Ecosystem, 12), releaseRef)
		lines = append(lines, selectableRow(fitText(row, width), index == m.selected[screenComponents]))
	}
	return strings.Join(lines, "\n")
}

func (m *dashboardModel) renderFindings(width, height int) string {
	lines := []string{
		styleTitle.Render("Findings") + "  " + styleMuted.Render(fmt.Sprintf("%d active", len(m.data.findings))),
		styleMuted.Render("Vulnerability        Severity  Component               KEV  Assessment       Match"),
	}
	if len(m.data.findings) == 0 {
		return strings.Join(append(
			lines, "", "No active findings yet.",
			styleMuted.Render("Run a local release scan to create durable findings."),
		), "\n")
	}
	rows := visibleRange(len(m.data.findings), m.selected[screenFindings], max(1, height-15))
	for index := rows.start; index < rows.end; index++ {
		item := m.data.findings[index]
		kevStatus := "-"
		if item.KnownExploited {
			kevStatus = "YES"
		}
		row := fmt.Sprintf("%-20s %-9s %-23s %-4s %-16s %s",
			fitText(item.VulnerabilityID, 20),
			strings.ToUpper(item.Severity),
			fitText(item.Component+"@"+item.ComponentVersion, 23),
			kevStatus, fitText(item.Status, 16), item.MatchStatus,
		)
		lines = append(lines, selectableRow(fitText(row, width), index == m.selected[screenFindings]))
	}
	selected := m.data.findings[min(m.selected[screenFindings], len(m.data.findings)-1)]
	lines = append(lines, "", styleTitle.Render("Selected finding"),
		fmt.Sprintf("  %s  •  %s@%s  •  %s:%s@%s",
			selected.VulnerabilityID, selected.Product, selected.Release,
			selected.Ecosystem, selected.Component, selected.ComponentVersion),
	)
	severity := strings.ToUpper(selected.Severity)
	if selected.CVSSScore != nil {
		severity += fmt.Sprintf(" %.1f (CVSS %s)", *selected.CVSSScore, selected.CVSSVersion)
	}
	lines = append(lines, "  Severity: "+severity)
	if len(selected.FixedVersions) > 0 {
		lines = append(lines, fitText("  Fixed boundary: "+strings.Join(selected.FixedVersions, ", "), width))
	}
	if selected.Published != "" || selected.Modified != "" {
		lines = append(lines, fitText("  Published: "+selected.Published+"  •  Modified: "+selected.Modified, width))
	}
	if selected.KnownExploited && selected.KEV != nil {
		lines = append(lines,
			styleWarn.Render("  🔥 CISA KEV: known exploitation"),
			fitText("  Added: "+selected.KEV.DateAdded+"  •  Due: "+selected.KEV.DueDate+"  •  Ransomware: "+selected.KEV.KnownRansomwareCampaignUse, width),
			fitText("  Required action: "+oneLine(selected.KEV.RequiredAction), width),
		)
	}
	history := m.assessmentHistory(selected.FindingID)
	if len(history) == 0 {
		lines = append(lines,
			styleWarn.Render("  Needs human review."),
			styleMuted.Render("  Press a or Enter to record an assessment."),
		)
		return strings.Join(lines, "\n")
	}
	lines = append(lines, styleMuted.Render(fmt.Sprintf("  Assessment history: %d decision(s)", len(history))))
	available := max(1, height-len(lines)-2)
	for index, assessment := range history[:min(len(history), available)] {
		label := "Earlier"
		if index == 0 {
			label = "Latest"
		}
		lines = append(lines, fmt.Sprintf("  %s: %s by %s at %s", label,
			styleGood.Render(assessment.Status), oneLine(assessment.Reviewer),
			assessment.AssessedAt.Format("2006-01-02 15:04Z")))
	}
	latest := history[0]
	if latest.Reason != "" {
		lines = append(lines, fitText("  Reason: "+oneLine(latest.Reason), width))
	}
	if latest.Evidence != "" && len(lines) < height {
		lines = append(lines, fitText("  Evidence: "+oneLine(latest.Evidence), width))
	}
	return strings.Join(lines, "\n")
}

func (m *dashboardModel) assessmentHistory(findingID int64) []store.Assessment {
	history := make([]store.Assessment, 0)
	for _, assessment := range m.data.assessments {
		if assessment.FindingID == findingID {
			history = append(history, assessment)
		}
	}
	return history
}

func (m *dashboardModel) renderScanner(width, height int) string {
	lines := []string{
		styleTitle.Render("Release scanner") + "  " + styleMuted.Render("local OSV package-version matching"),
		styleWarn.Render("Matches are potentially affected and always require human review."),
		"",
	}
	if len(m.data.releases) == 0 {
		return strings.Join(append(lines, "No releases available.", styleMuted.Render("Create a product release and add components first.")), "\n")
	}

	listHeight := min(5, max(2, height/3))
	rows := visibleRange(len(m.data.releases), m.selected[screenScanner], listHeight)
	for index := rows.start; index < rows.end; index++ {
		release := m.data.releases[index]
		row := fmt.Sprintf("%-34s %d components", fitText(release.Product+"@"+release.Version, 34), m.componentCount(release))
		lines = append(lines, selectableRow(fitText(row, width), index == m.selected[screenScanner]))
	}
	lines = append(lines, "")
	if m.scanning {
		lines = append(lines, m.spinner.View()+" Matching against the local OSV snapshot...")
		return strings.Join(lines, "\n")
	}
	if m.scan == nil {
		if m.data.sync == nil {
			lines = append(lines, styleWarn.Render("No local OSV snapshot. Press u to update it first."))
		} else {
			lines = append(lines, styleMuted.Render("Press s or Enter to scan the selected release."))
		}
		return strings.Join(lines, "\n")
	}
	lines = append(lines,
		styleTitle.Render(fmt.Sprintf("Last result — %s@%s", m.scan.Product, m.scan.Release)),
		fmt.Sprintf("%d components checked  •  %s potential findings", m.scan.Components, styleWarn.Render(fmt.Sprintf("%d", len(m.scan.Findings)))),
		fmt.Sprintf("%s known exploited in CISA KEV", styleWarn.Render(fmt.Sprintf("%d", m.scan.KnownExploited))),
		fmt.Sprintf("Saved changes: %d new  •  %d existing  •  %d reopened  •  %d no longer matched",
			m.scan.New, m.scan.Existing, m.scan.Reopened, m.scan.NoLongerMatched),
	)
	if len(m.scan.Findings) == 0 {
		lines = append(lines, styleGood.Render("No known OSV matches found."))
		return strings.Join(lines, "\n")
	}
	available := max(1, height-len(lines)-2)
	for _, item := range m.scan.Findings[:min(available, len(m.scan.Findings))] {
		status := strings.ToUpper(strings.ReplaceAll(item.Status, "-", " "))
		kevStatus := "-"
		if item.KnownExploited {
			kevStatus = "KEV"
		}
		row := fmt.Sprintf("%-18s %-28s %-4s %s", fitText(item.ID, 18), fitText(item.Component+"@"+item.ComponentVersion, 28), kevStatus, status)
		lines = append(lines, fitText(row, width))
	}
	if len(m.scan.Findings) > available {
		lines = append(lines, styleMuted.Render(fmt.Sprintf("...and %d more", len(m.scan.Findings)-available)))
	}
	return strings.Join(lines, "\n")
}

func (m *dashboardModel) renderFeeds(width, height int) string {
	lines := []string{
		styleTitle.Render("Vulnerability feeds") + "  " + styleMuted.Render(dashboardScreens[screenFeeds].hint),
		styleMuted.Render("Select an action and press Enter."),
		"",
	}
	actions := []struct {
		title       string
		description string
	}{
		{"Update from internet", "Download inventory-scoped OSV matches and the CISA KEV catalog"},
		{"Import trusted bundle", "Validate and activate a .bundle in a disconnected environment"},
		{"Export current bundle", "Create a checksummed .bundle for controlled transfer"},
	}
	for index, action := range actions {
		row := fmt.Sprintf("%-24s  %s", action.title, action.description)
		lines = append(lines, selectableRow(fitText(row, width), index == m.selected[screenFeeds]))
	}
	lines = append(lines, "", styleTitle.Render("Current local data"))
	if m.data.sync == nil {
		lines = append(lines, styleWarn.Render("  OSV snapshot: not available"))
	} else {
		lines = append(lines, fmt.Sprintf("  OSV snapshot: %s  •  %d packages  •  %d vulnerabilities",
			m.data.sync.SynchronizedAt.Format("2006-01-02 15:04Z"), m.data.sync.Packages, m.data.sync.Vulnerabilities))
	}
	if m.data.kevSync == nil {
		lines = append(lines, styleWarn.Render("  CISA KEV: not available"))
	} else {
		lines = append(lines, fmt.Sprintf("  CISA KEV: %s  •  %d entries",
			m.data.kevSync.SynchronizedAt.Format("2006-01-02 15:04Z"), m.data.kevSync.Entries))
	}
	if m.data.feedImport != nil && len(lines) < height-3 {
		lines = append(lines, "", styleTitle.Render("Last bundle import"),
			fitText("  "+m.data.feedImport.SourceName+"  •  imported "+m.data.feedImport.ImportedAt.Format("2006-01-02 15:04Z"), width),
			fitText("  SHA-256: "+m.data.feedImport.ManifestSHA256, width),
		)
	}
	if len(lines) < height-2 {
		lines = append(lines, "", styleWarn.Render("Checksums detect corruption, not who created a bundle. Use a trusted transfer path."))
	}
	return strings.Join(lines, "\n")
}

func (m *dashboardModel) renderForm(width int) string {
	if m.pickingFile {
		return strings.Join([]string{
			styleTitle.Render("Choose a file"),
			styleMuted.Render("Enter selects  •  ←/Backspace goes up  •  Esc cancels browser"),
			styleMuted.Render(fitText(m.filePicker.CurrentDirectory, width)),
			"",
			m.filePicker.View(),
		}, "\n")
	}
	lines := []string{
		styleTitle.Render(m.form.title),
		styleMuted.Render(fmt.Sprintf("Step %d of %d  •  Enter advances  •  Esc cancels", m.form.active+1, len(m.form.fields))),
		"",
	}
	for index, field := range m.form.fields {
		if index != m.form.active {
			value := field.input.Value()
			if value == "" {
				value = "—"
			}
			lines = append(lines, fitText(styleMuted.Render("○ "+field.label+": ")+value, width))
			continue
		}

		lines = append(lines, styleBrand.Render("▸ "+field.label))
		if len(field.choices) > 0 {
			lines = append(lines,
				"  "+styleKey.Render("←")+"  "+styleBrand.Render(field.input.Value())+"  "+styleKey.Render("→"),
				styleMuted.Render("  "+field.hint),
			)
			continue
		}
		inputWidth := max(10, min(58, width))
		field.input.SetWidth(max(6, inputWidth-4))
		inputStyle := lipgloss.NewStyle().
			Width(inputWidth).
			Padding(0, 1).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorAccent)
		lines = append(lines, inputStyle.Render(field.input.View()), styleMuted.Render("  "+field.hint))
	}
	lines = append(lines, "")
	if m.loading {
		message := " Saving locally..."
		if m.form.kind == formSBOMImport || m.form.kind == formQuickImport {
			message = " Validating and importing SBOM..."
		} else if m.form.kind == formFeedImport {
			message = " Validating and importing offline feed..."
		} else if m.form.kind == formFeedExport {
			message = " Creating offline feed bundle..."
		}
		lines = append(lines, m.spinner.View()+message)
	} else if m.form.err != nil {
		lines = append(lines, styleError.Render("Error: "+oneLine(m.form.err.Error())))
	} else {
		lines = append(lines, styleKey.Render("Enter")+" save after final field")
	}
	return strings.Join(lines, "\n")
}

func (m *dashboardModel) renderHelp(width int) string {
	rows := []string{
		styleTitle.Render("Keyboard help"),
		styleMuted.Render("Everything in the dashboard is keyboard accessible."),
		"",
		helpRow("↑/↓ or j/k", "Move through sections or rows"),
		helpRow("←/→ or h/l", "Focus navigation or content"),
		helpRow("Tab", "Switch between navigation and content"),
		helpRow("1–7", "Open a section directly"),
		helpRow("Enter", "Run the highlighted or recommended action"),
		helpRow("n", "Create an item for the current section"),
		helpRow("i", "Import CycloneDX JSON from Releases"),
		helpRow("Ctrl+O", "Browse for a file while a file-path field is active"),
		helpRow("a / Enter", "Assess the selected finding"),
		helpRow("s / Enter", "Scan the selected release"),
		helpRow("u", "Update local OSV and CISA KEV data (uses internet)"),
		helpRow("r", "Refresh local inventory"),
		helpRow("? / Esc", "Close this help"),
		helpRow("q", "Quit safely"),
		"",
		styleWarn.Render("A scanner match is not a final impact decision."),
		fitText("PSIRTMap reports potential impact; a security engineer must review it.", width),
	}
	return strings.Join(rows, "\n")
}

func helpRow(key, description string) string {
	return fmt.Sprintf("  %-15s %s", styleKey.Render(key), description)
}

func (m *dashboardModel) renderFooter() string {
	hints := []string{
		styleKey.Render("↑↓") + " move",
		styleKey.Render("Enter") + " select",
	}
	switch m.screen {
	case screenOverview:
		hints[1] = styleKey.Render("Enter") + " next action"
	case screenProducts, screenComponents:
		hints = append(hints, styleKey.Render("n")+" new")
	case screenReleases:
		hints = append(hints, styleKey.Render("n")+" new", styleKey.Render("i")+" import SBOM")
	case screenFindings:
		hints[1] = styleKey.Render("Enter") + " assess"
	case screenScanner:
		hints[1] = styleKey.Render("Enter") + " scan"
	case screenFeeds:
		hints[1] = styleKey.Render("Enter") + " run action"
	}
	hints = append(hints, styleKey.Render("?")+" help", styleKey.Render("q")+" quit")
	line := fitText(strings.Join(hints, "   "), m.width)
	if m.status == "" {
		return line
	}
	statusStyle := styleGood
	if m.statusErr {
		statusStyle = styleError
	}
	prefix := "✓ "
	if m.statusErr {
		prefix = "! "
	}
	return line + "\n" + fitText(statusStyle.Render(prefix+m.status), m.width)
}

func (m *dashboardModel) componentCount(release store.Release) int {
	count := 0
	for _, component := range m.data.components {
		if component.Product == release.Product && component.ReleaseVersion == release.Version {
			count++
		}
	}
	return count
}

type dashboardRange struct {
	start int
	end   int
}

func visibleRange(length, selected, capacity int) dashboardRange {
	capacity = max(1, capacity)
	start := max(0, selected-capacity/2)
	end := min(length, start+capacity)
	start = max(0, end-capacity)
	return dashboardRange{start: start, end: end}
}

func selectableRow(value string, selected bool) string {
	if selected {
		return lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render("▸ " + value)
	}
	return "  " + value
}

func fitText(value string, width int) string {
	if width <= 0 {
		return ""
	}
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\t", " ")
	if ansi.StringWidth(value) <= width {
		return value
	}
	return ansi.Truncate(value, width, "…")
}
