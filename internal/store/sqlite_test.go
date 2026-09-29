package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestInventoryLifecyclePersists(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "nested", "inventory.db")
	database, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	product, err := database.CreateProduct(ctx, "  AG-200  ", "  Industrial gateway  ")
	if err != nil {
		t.Fatalf("CreateProduct() error = %v", err)
	}
	if product.Name != "AG-200" || product.Description != "Industrial gateway" {
		t.Fatalf("product = %+v", product)
	}
	if _, err := database.CreateProduct(ctx, "ag-200", "duplicate"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate CreateProduct() error = %v, want ErrAlreadyExists", err)
	}

	release, err := database.CreateRelease(ctx, "ag-200", "2.2")
	if err != nil {
		t.Fatalf("CreateRelease() error = %v", err)
	}
	if release.Product != "AG-200" || release.Version != "2.2" {
		t.Fatalf("release = %+v", release)
	}
	if _, err := database.CreateRelease(ctx, "missing", "1.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing product error = %v, want ErrNotFound", err)
	}
	if _, err := database.CreateRelease(ctx, "AG-200", "2.2"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate release error = %v, want ErrAlreadyExists", err)
	}

	component, err := database.CreateComponent(ctx, "AG-200", "2.2", "npm", "@scope/pkg", "1.2.3")
	if err != nil {
		t.Fatalf("CreateComponent() error = %v", err)
	}
	if component.Name != "@scope/pkg" || component.Product != "AG-200" {
		t.Fatalf("component = %+v", component)
	}
	if _, err := database.CreateComponent(ctx, "AG-200", "9.9", "npm", "pkg", "1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing release error = %v, want ErrNotFound", err)
	}
	if _, err := database.CreateComponent(ctx, "AG-200", "2.2", "npm", "@scope/pkg", "1.2.3"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate component error = %v, want ErrAlreadyExists", err)
	}

	if err := database.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("database permissions = %o, want 600", permissions)
	}

	database, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer database.Close()

	products, err := database.ListProducts(ctx)
	if err != nil || len(products) != 1 || products[0].Name != "AG-200" {
		t.Fatalf("ListProducts() = %+v, %v", products, err)
	}
	releases, err := database.ListReleases(ctx, "AG-200")
	if err != nil || len(releases) != 1 || releases[0].Version != "2.2" {
		t.Fatalf("ListReleases() = %+v, %v", releases, err)
	}
	storedRelease, err := database.GetRelease(ctx, "ag-200", "2.2")
	if err != nil || storedRelease.Product != "AG-200" {
		t.Fatalf("GetRelease() = %+v, %v", storedRelease, err)
	}
	if _, err := database.GetRelease(ctx, "AG-200", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing GetRelease() error = %v, want ErrNotFound", err)
	}
	components, err := database.ListComponents(ctx, "ag-200", "2.2")
	if err != nil || len(components) != 1 || components[0].Name != "@scope/pkg" {
		t.Fatalf("ListComponents() = %+v, %v", components, err)
	}
	allComponents, err := database.ListAllComponents(ctx)
	if err != nil || len(allComponents) != 1 || allComponents[0].Product != "AG-200" {
		t.Fatalf("ListAllComponents() = %+v, %v", allComponents, err)
	}
}

func TestListsAreSortedAndEmptyListsAreNonNil(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	products, err := database.ListProducts(ctx)
	if err != nil || products == nil || len(products) != 0 {
		t.Fatalf("empty ListProducts() = %#v, %v", products, err)
	}
	components, err := database.ListAllComponents(ctx)
	if err != nil || components == nil || len(components) != 0 {
		t.Fatalf("empty ListAllComponents() = %#v, %v", components, err)
	}
	for _, name := range []string{"Zulu", "alpha", "Bravo"} {
		if _, err := database.CreateProduct(ctx, name, ""); err != nil {
			t.Fatalf("CreateProduct(%q): %v", name, err)
		}
	}
	products, err = database.ListProducts(ctx)
	if err != nil {
		t.Fatalf("ListProducts() error = %v", err)
	}
	want := []string{"alpha", "Bravo", "Zulu"}
	for index := range want {
		if products[index].Name != want[index] {
			t.Fatalf("products = %+v, want order %v", products, want)
		}
	}
}

func TestConcurrentDuplicateProductCreation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, err := Open(ctx, filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	const attempts = 12
	results := make(chan error, attempts)
	var group sync.WaitGroup
	for range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			_, createErr := database.CreateProduct(ctx, "AG-200", "")
			results <- createErr
		}()
	}
	group.Wait()
	close(results)

	var successes, duplicates int
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, ErrAlreadyExists):
			duplicates++
		default:
			t.Fatalf("unexpected CreateProduct() error = %v", result)
		}
	}
	if successes != 1 || duplicates != attempts-1 {
		t.Fatalf("successes = %d, duplicates = %d", successes, duplicates)
	}
}

func TestValidationAndNewerSchemaProtection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "inventory.db")
	database, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := database.CreateProduct(ctx, " ", ""); err == nil {
		t.Fatal("CreateProduct() error = nil for blank name")
	}
	if _, err := database.CreateRelease(ctx, "", "1"); err == nil {
		t.Fatal("CreateRelease() error = nil for blank product")
	}
	if _, err := database.CreateComponent(ctx, "p", "r", "", "n", "v"); err == nil {
		t.Fatal("CreateComponent() error = nil for blank ecosystem")
	}
	if _, err := database.CreateProduct(ctx, "evil\x1b[31m", ""); err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("control-character product error = %v", err)
	}
	if _, err := database.CreateProduct(ctx, strings.Repeat("x", maxIdentifierLength+1), ""); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized product error = %v", err)
	}
	if _, err := database.CreateProduct(ctx, "safe", "bad\x00description"); err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("control-character description error = %v", err)
	}
	if _, err := database.db.ExecContext(ctx, "PRAGMA user_version = 999"); err != nil {
		t.Fatalf("set future schema: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	_, err = Open(ctx, path)
	if err == nil || !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("Open() future schema error = %v", err)
	}
}

func TestCanceledContextStopsWrites(t *testing.T) {
	t.Parallel()

	database, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := database.CreateProduct(ctx, "AG-200", ""); err == nil {
		t.Fatal("CreateProduct() error = nil with canceled context")
	}
}
