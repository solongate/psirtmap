package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/solongate/psirtmap/internal/osv"
	"github.com/solongate/psirtmap/internal/store"
)

type dashboardQuerier struct {
	result []osv.Vulnerability
	err    error
	calls  int
}

func (q *dashboardQuerier) Query(_ context.Context, _ osv.Package, _ string) ([]osv.Vulnerability, error) {
	q.calls++
	return q.result, q.err
}

func newDashboardTestDatabase(t *testing.T) *store.DB {
	t.Helper()
	database, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func loadDashboard(t *testing.T, model *dashboardModel) {
	t.Helper()
	message, ok := model.loadInventory()().(dashboardInventoryMsg)
	if !ok {
		t.Fatal("loadInventory() did not return dashboardInventoryMsg")
	}
	model.Update(message)
	if !model.loaded {
		t.Fatalf("dashboard failed to load: %s", model.status)
	}
}

func dashboardKey(text string) tea.KeyPressMsg {
	code, _ := utf8.DecodeRuneInString(text)
	return tea.KeyPressMsg(tea.Key{Text: text, Code: code})
}

func dashboardSpecialKey(code rune) tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Code: code})
}

func TestDashboardLoadsAndRendersRealInventory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database := newDashboardTestDatabase(t)
	if _, err := database.CreateProduct(ctx, "AG-200", "Industrial gateway"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRelease(ctx, "AG-200", "2.2"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateComponent(ctx, "AG-200", "2.2", "Alpine", "openssl", "3.0.8"); err != nil {
		t.Fatal(err)
	}

	model := newDashboardModel(ctx, database, &dashboardQuerier{})
	loadDashboard(t, model)
	if len(model.data.products) != 1 || len(model.data.releases) != 1 || len(model.data.components) != 1 {
		t.Fatalf("inventory = %+v", model.data)
	}

	view := model.View()
	for _, expected := range []string{"PSIRTMAP", "Overview", "1", "Local inventory", "CycloneDX import", "Local OSV snapshot", "NOT SYNCED"} {
		if !strings.Contains(view.Content, expected) {
			t.Errorf("dashboard view does not contain %q", expected)
		}
	}
	if !view.AltScreen {
		t.Fatal("dashboard does not request the alternate screen")
	}
	assertDashboardFits(t, view.Content, dashboardDefaultWidth, dashboardDefaultHeight)
}

func TestDashboardNavigationAndResponsiveLayout(t *testing.T) {
	t.Parallel()

	model := newDashboardModel(context.Background(), newDashboardTestDatabase(t), &dashboardQuerier{})
	loadDashboard(t, model)
	model.Update(dashboardKey("3"))
	if model.screen != screenReleases || model.focusMenu {
		t.Fatalf("screen = %v, focusMenu = %v", model.screen, model.focusMenu)
	}
	model.Update(dashboardSpecialKey(tea.KeyLeft))
	model.Update(dashboardSpecialKey(tea.KeyDown))
	if model.screen != screenComponents || !model.focusMenu {
		t.Fatalf("screen = %v, focusMenu = %v", model.screen, model.focusMenu)
	}

	model.Update(tea.WindowSizeMsg{Width: 52, Height: 18})
	view := model.View().Content
	if !strings.Contains(view, "1:Overview") || !strings.Contains(view, "4:Components") {
		t.Fatalf("compact view = %q", view)
	}
	assertDashboardFits(t, view, 52, 18)
}

func TestDashboardCreatesProductFromForm(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database := newDashboardTestDatabase(t)
	model := newDashboardModel(ctx, database, &dashboardQuerier{})
	loadDashboard(t, model)
	model.screen = screenProducts
	model.openCreateForm()
	if model.form.kind != formProduct || len(model.form.fields) != 2 {
		t.Fatalf("form = %+v", model.form)
	}
	model.form.fields[0].input.SetValue("Gateway-X")
	model.form.fields[1].input.SetValue("Edge security gateway")

	saved, ok := model.saveForm()().(dashboardSavedMsg)
	if !ok || saved.err != nil {
		t.Fatalf("saveForm() = %#v", saved)
	}
	_, command := model.Update(saved)
	if command == nil {
		t.Fatal("successful save did not request an inventory refresh")
	}
	loaded, ok := command().(dashboardInventoryMsg)
	if !ok {
		t.Fatal("refresh command did not return dashboardInventoryMsg")
	}
	model.Update(loaded)
	if model.form.kind != formNone || len(model.data.products) != 1 || model.data.products[0].Name != "Gateway-X" {
		t.Fatalf("model after save = form %v, products %+v", model.form.kind, model.data.products)
	}
}

func TestDashboardCreatesReleaseAndComponentFromGuidedDefaults(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database := newDashboardTestDatabase(t)
	if _, err := database.CreateProduct(ctx, "AG-200", ""); err != nil {
		t.Fatal(err)
	}
	model := newDashboardModel(ctx, database, &dashboardQuerier{})
	loadDashboard(t, model)

	model.screen = screenReleases
	model.openCreateForm()
	if got := model.form.fields[0].input.Value(); got != "AG-200" {
		t.Fatalf("product default = %q", got)
	}
	model.form.fields[1].input.SetValue("2.2")
	releaseSaved := model.saveForm()().(dashboardSavedMsg)
	if releaseSaved.err != nil {
		t.Fatalf("save release: %v", releaseSaved.err)
	}
	_, refresh := model.Update(releaseSaved)
	if refresh == nil {
		t.Fatal("release save did not request refresh")
	}
	model.Update(refresh())

	model.screen = screenComponents
	model.openCreateForm()
	model.form.fields[2].input.SetValue("openssl")
	model.form.fields[3].input.SetValue("3.0.8")
	componentSaved := model.saveForm()().(dashboardSavedMsg)
	if componentSaved.err != nil {
		t.Fatalf("save component: %v", componentSaved.err)
	}
	components, err := database.ListComponents(ctx, "AG-200", "2.2")
	if err != nil || len(components) != 1 {
		t.Fatalf("ListComponents() = %+v, %v", components, err)
	}
	if components[0].Ecosystem != "Alpine" || components[0].Name != "openssl" || components[0].Version != "3.0.8" {
		t.Fatalf("component = %+v", components[0])
	}
}

func TestDashboardImportsCycloneDXFromReleaseScreen(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database := newDashboardTestDatabase(t)
	if _, err := database.CreateProduct(ctx, "AG-200", ""); err != nil {
		t.Fatal(err)
	}
	model := newDashboardModel(ctx, database, &dashboardQuerier{})
	loadDashboard(t, model)
	model.screen = screenReleases
	model.openImportForm()
	if model.form.kind != formSBOMImport || len(model.form.fields) != 2 {
		t.Fatalf("import form = %+v", model.form)
	}
	if got := model.form.fields[0].input.Value(); got != "AG-200@2.2" {
		t.Fatalf("release import default = %q", got)
	}
	model.form.fields[1].input.SetValue(filepath.Join("..", "..", "examples", "ag-200", "firmware-2.2.cdx.json"))
	saved, ok := model.saveForm()().(dashboardSavedMsg)
	if !ok || saved.err != nil {
		t.Fatalf("saveForm() = %#v", saved)
	}
	if !strings.Contains(saved.message, "Imported 3 components into AG-200@2.2") {
		t.Fatalf("saved message = %q", saved.message)
	}
	components, err := database.ListComponents(ctx, "AG-200", "2.2")
	if err != nil || len(components) != 3 {
		t.Fatalf("ListComponents() = %+v, %v", components, err)
	}
}

func TestDashboardFormKeepsValidationError(t *testing.T) {
	t.Parallel()

	model := newDashboardModel(context.Background(), newDashboardTestDatabase(t), &dashboardQuerier{})
	loadDashboard(t, model)
	model.screen = screenProducts
	model.openCreateForm()
	message := model.saveForm()().(dashboardSavedMsg)
	model.Update(message)
	if model.form.kind != formProduct || model.form.err == nil || !strings.Contains(model.form.err.Error(), "required") {
		t.Fatalf("form error = %v, form kind = %v", model.form.err, model.form.kind)
	}
}

func TestDashboardComponentFormUsesSelectedReleaseDefaultsAndFits(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database := newDashboardTestDatabase(t)
	if _, err := database.CreateProduct(ctx, "AG-200", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRelease(ctx, "AG-200", "2.2"); err != nil {
		t.Fatal(err)
	}
	model := newDashboardModel(ctx, database, &dashboardQuerier{})
	loadDashboard(t, model)
	model.screen = screenComponents
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	model.openCreateForm()
	if got := model.form.fields[0].input.Value(); got != "AG-200@2.2" {
		t.Fatalf("release default = %q", got)
	}
	if got := model.form.fields[1].input.Value(); got != "Alpine" {
		t.Fatalf("ecosystem default = %q", got)
	}
	assertDashboardFits(t, model.View().Content, 80, 24)
}

func TestDashboardRendersEverySectionWithInventory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database := newDashboardTestDatabase(t)
	if _, err := database.CreateProduct(ctx, "AG-200", "Industrial gateway"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRelease(ctx, "AG-200", "2.2"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateComponent(ctx, "AG-200", "2.2", "Alpine", "openssl", "3.0.8"); err != nil {
		t.Fatal(err)
	}
	model := newDashboardModel(ctx, database, &dashboardQuerier{})
	loadDashboard(t, model)
	model.focusMenu = false

	checks := []struct {
		screen dashboardScreen
		want   []string
	}{
		{screenProducts, []string{"Products", "AG-200", "Industrial gateway"}},
		{screenReleases, []string{"Releases", "AG-200@2.2", "1"}},
		{screenComponents, []string{"Components", "openssl@3.0.8", "Alpine"}},
		{screenFindings, []string{"Findings", "No active findings yet"}},
		{screenScanner, []string{"Release scanner", "AG-200@2.2", "Press u to update"}},
	}
	for _, check := range checks {
		model.screen = check.screen
		content := model.View().Content
		for _, expected := range check.want {
			if !strings.Contains(content, expected) {
				t.Errorf("screen %v does not contain %q", check.screen, expected)
			}
		}
	}
}

func TestDashboardHelpCancelRefreshAndEmptyScanKeys(t *testing.T) {
	t.Parallel()

	model := newDashboardModel(context.Background(), newDashboardTestDatabase(t), &dashboardQuerier{})
	loadDashboard(t, model)
	model.Update(dashboardKey("?"))
	if !model.showHelp || !strings.Contains(model.View().Content, "Keyboard help") {
		t.Fatal("help did not open")
	}
	model.Update(dashboardSpecialKey(tea.KeyEscape))
	if model.showHelp {
		t.Fatal("help did not close")
	}

	model.Update(dashboardKey("n"))
	if model.form.kind != formProduct {
		t.Fatalf("form kind = %v", model.form.kind)
	}
	model.Update(dashboardSpecialKey(tea.KeyEscape))
	if model.form.kind != formNone || !strings.Contains(model.status, "canceled") {
		t.Fatalf("form = %v, status = %q", model.form.kind, model.status)
	}

	model.screen = screenScanner
	model.focusMenu = false
	model.Update(dashboardKey("s"))
	if !model.statusErr || !strings.Contains(model.status, "No releases") {
		t.Fatalf("scan status = %q, error = %v", model.status, model.statusErr)
	}

	_, refresh := model.Update(dashboardKey("r"))
	if refresh == nil || !model.loading || model.status != "Refreshing inventory..." {
		t.Fatalf("refresh command = %v, loading = %v, status = %q", refresh, model.loading, model.status)
	}
}

func TestDashboardScansSelectedRelease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database := newDashboardTestDatabase(t)
	if _, err := database.CreateProduct(ctx, "AG-200", ""); err != nil {
		t.Fatal(err)
	}
	release, err := database.CreateRelease(ctx, "AG-200", "2.2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateComponent(ctx, "AG-200", "2.2", "Alpine", "openssl", "3.0.8"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SaveOSVSnapshot(ctx, []store.PackageSnapshot{{
		Package:         store.PackageVersion{Ecosystem: "Alpine", Name: "openssl", Version: "3.0.8"},
		Vulnerabilities: []osv.Vulnerability{{ID: "CVE-2026-12345", Summary: "test"}},
	}}); err != nil {
		t.Fatal(err)
	}
	querier := &dashboardQuerier{result: []osv.Vulnerability{{ID: "CVE-2026-12345", Summary: "test"}}}
	model := newDashboardModel(ctx, database, querier)
	loadDashboard(t, model)

	message := model.scanRelease(release)().(dashboardScanMsg)
	if message.err != nil || len(message.result.Findings) != 1 || !message.result.Persisted || message.result.New != 1 {
		t.Fatalf("scan message = %+v", message)
	}
	model.scanning = true
	_, refresh := model.Update(message)
	if model.scanning || model.scan == nil || model.scan.Findings[0].ID != "CVE-2026-12345" || querier.calls != 0 {
		t.Fatalf("scan state = %+v; calls = %d", model.scan, querier.calls)
	}
	if refresh == nil {
		t.Fatal("successful scan did not request a finding refresh")
	}
	model.Update(refresh())
	if len(model.data.findings) != 1 || model.data.findings[0].VulnerabilityID != "CVE-2026-12345" {
		t.Fatalf("dashboard findings = %+v", model.data.findings)
	}
	model.screen = screenFindings
	if content := model.View().Content; !strings.Contains(content, "CVE-2026-12345") || !strings.Contains(content, "openssl@3.0.8") {
		t.Fatalf("findings view = %q", content)
	}
	model.screen = screenScanner
	if !strings.Contains(model.View().Content, "NEEDS REVIEW") {
		t.Fatal("scanner view does not show review status")
	}
}

func TestDashboardRecordsAndDisplaysAssessmentHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database := newDashboardTestDatabase(t)
	if _, err := database.CreateProduct(ctx, "AG-200", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRelease(ctx, "AG-200", "2.2"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReconcileFindings(ctx, "AG-200", "2.2", []store.FindingMatch{{
		Ecosystem: "Alpine", Component: "openssl", ComponentVersion: "3.0.8",
		VulnerabilityID: "CVE-2026-12345",
	}}, "local-osv-snapshot", time.Now(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateAssessment(ctx, store.AssessmentTarget{
		Product: "AG-200", Release: "2.2", VulnerabilityID: "CVE-2026-12345",
	}, store.AssessmentInput{Status: store.AssessmentInvestigating, Reviewer: "initial-reviewer"}); err != nil {
		t.Fatal(err)
	}
	model := newDashboardModel(ctx, database, &dashboardQuerier{})
	loadDashboard(t, model)
	model.screen = screenFindings
	model.focusMenu = false

	model.Update(dashboardKey("a"))
	if model.form.kind != formAssessment || model.form.target == nil || model.form.target.VulnerabilityID != "CVE-2026-12345" {
		t.Fatalf("assessment form = %+v", model.form)
	}
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	assertDashboardFits(t, model.View().Content, 80, 24)
	model.form.fields[0].input.SetValue("affected")
	model.form.fields[1].input.SetValue("")
	model.form.fields[2].input.SetValue("emirhan")
	invalid := model.saveForm()().(dashboardSavedMsg)
	if invalid.err == nil || !strings.Contains(invalid.err.Error(), "reason is required") {
		t.Fatalf("invalid assessment error = %v", invalid.err)
	}
	model.Update(invalid)
	if model.form.kind != formAssessment || model.form.err == nil {
		t.Fatalf("invalid assessment closed form: %+v", model.form)
	}
	values := []string{"not-affected", "Feature disabled", "emirhan", "SEC-123"}
	for index, value := range values {
		model.form.fields[index].input.SetValue(value)
	}
	message := model.saveForm()().(dashboardSavedMsg)
	if message.err != nil {
		t.Fatalf("save assessment error = %v", message.err)
	}
	_, refresh := model.Update(message)
	if refresh == nil {
		t.Fatal("assessment save did not refresh inventory")
	}
	model.Update(refresh())
	if len(model.data.assessments) != 2 || model.data.findings[0].Status != "not-affected" {
		t.Fatalf("assessment inventory = %+v, findings = %+v", model.data.assessments, model.data.findings)
	}
	content := model.View().Content
	for _, expected := range []string{"Assessment history: 2", "not-affected", "Latest:", "Earlier:", "emirhan", "initial-reviewer", "Feature disabled", "SEC-123"} {
		if !strings.Contains(content, expected) {
			t.Errorf("findings view = %q, want %q", content, expected)
		}
	}
	assertDashboardFits(t, content, 80, 24)
}

func TestDashboardReportsScanFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database := newDashboardTestDatabase(t)
	if _, err := database.CreateProduct(ctx, "gateway", ""); err != nil {
		t.Fatal(err)
	}
	release, err := database.CreateRelease(ctx, "gateway", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateComponent(ctx, "gateway", "1.0", "npm", "pkg", "1.0"); err != nil {
		t.Fatal(err)
	}
	model := newDashboardModel(ctx, database, &dashboardQuerier{err: errors.New("offline")})
	message := model.scanRelease(release)().(dashboardScanMsg)
	model.scanning = true
	model.Update(message)
	if !model.statusErr || !strings.Contains(model.status, "no local OSV data") || model.scanning {
		t.Fatalf("status = %q, error = %v, scanning = %v", model.status, model.statusErr, model.scanning)
	}
}

func TestDashboardSynchronizesOSVSnapshot(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database := newDashboardTestDatabase(t)
	if _, err := database.CreateProduct(ctx, "gateway", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRelease(ctx, "gateway", "1.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateComponent(ctx, "gateway", "1.0", "npm", "pkg", "1.0"); err != nil {
		t.Fatal(err)
	}
	querier := &dashboardQuerier{result: []osv.Vulnerability{{ID: "CVE-2026-12345"}}}
	model := newDashboardModel(ctx, database, querier)
	loadDashboard(t, model)

	message := model.syncSnapshot()().(dashboardSyncMsg)
	if message.err != nil || message.result.Packages != 1 || message.result.Vulnerabilities != 1 {
		t.Fatalf("sync message = %+v", message)
	}
	model.syncing = true
	_, refresh := model.Update(message)
	if model.syncing || model.statusErr || refresh == nil {
		t.Fatalf("sync state = syncing %v, status %q, error %v", model.syncing, model.status, model.statusErr)
	}
	model.Update(refresh())
	if model.data.sync == nil || querier.calls != 1 {
		t.Fatalf("dashboard sync = %+v; calls = %d", model.data.sync, querier.calls)
	}
}

func TestDashboardHelpers(t *testing.T) {
	t.Parallel()

	if got := fitText("abcdef", 4); got != "abc…" {
		t.Fatalf("fitText() = %q", got)
	}
	if got := visibleRange(20, 19, 5); got.start != 15 || got.end != 20 {
		t.Fatalf("visibleRange() = %+v", got)
	}
}

func assertDashboardFits(t *testing.T, content string, width, height int) {
	t.Helper()
	lines := strings.Split(content, "\n")
	if len(lines) > height {
		t.Fatalf("dashboard height = %d, want <= %d", len(lines), height)
	}
	for index, line := range lines {
		if lineWidth := ansi.StringWidth(line); lineWidth > width {
			t.Fatalf("dashboard line %d width = %d, want <= %d: %q", index+1, lineWidth, width, line)
		}
	}
}
