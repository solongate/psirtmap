package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/solongate/psirtmap/internal/feed"
	"github.com/solongate/psirtmap/internal/store"
)

type feedImportOutput struct {
	Bundle feed.Info        `json:"bundle"`
	Import store.FeedImport `json:"import"`
}

type feedKeyOutput struct {
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"key_id"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type feedExportOptions struct {
	path           string
	signingKeyPath string
	jsonOutput     bool
	help           bool
}

type feedImportOptions struct {
	path            string
	trustedKeyPaths []string
	jsonOutput      bool
	help            bool
}

func runFeed(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
	querier VulnerabilityQuerier,
	kevFetcher KEVFetcher,
) int {
	if len(args) == 0 {
		return usageError(stderr, errors.New("feed requires pull, keygen, export, or import"), printFeedUsage)
	}
	switch args[0] {
	case "pull":
		return runSync(ctx, args[1:], stdout, stderr, database, querier, kevFetcher)
	case "keygen":
		return runFeedKeygen(args[1:], stdout, stderr)
	case "export":
		return runFeedExport(ctx, args[1:], stdout, stderr, database)
	case "import":
		return runFeedImport(ctx, args[1:], stdout, stderr, database)
	case "help", "--help", "-h":
		printFeedUsage(stdout)
		return 0
	default:
		return usageError(stderr, fmt.Errorf("unknown feed action %q", args[0]), printFeedUsage)
	}
}

func runFeedExport(ctx context.Context, args []string, stdout, stderr io.Writer, database *store.DB) int {
	options, err := parseFeedExportOptions(args)
	if err != nil {
		return usageError(stderr, err, printFeedUsage)
	}
	if options.help {
		printFeedUsage(stdout)
		return 0
	}
	createdAt := time.Now().UTC().Truncate(time.Second)
	path := options.path
	if path == "" {
		path = fmt.Sprintf("psirtmap-feed-%s.bundle", createdAt.Format("20060102T150405Z"))
	}
	if err := validateCLIIdentifier("feed bundle path", path); err != nil {
		return usageError(stderr, err, printFeedUsage)
	}
	var signingKey *feed.SigningKey
	if options.signingKeyPath != "" {
		loaded, loadErr := feed.LoadSigningKey(options.signingKeyPath)
		if loadErr != nil {
			return commandError(stderr, loadErr)
		}
		signingKey = &loaded
	}
	info, err := exportFeedBundleWithSigningKey(ctx, database, path, createdAt, signingKey)
	if err != nil {
		return commandError(stderr, err)
	}
	if options.jsonOutput {
		return printJSON(stdout, stderr, info)
	}
	fmt.Fprintln(stdout, "OFFLINE FEED EXPORTED")
	fmt.Fprintf(stdout, "Bundle           %s\n", info.Path)
	fmt.Fprintf(stdout, "Format           v%d\n", info.FormatVersion)
	fmt.Fprintf(stdout, "Packages         %d\n", info.Packages)
	fmt.Fprintf(stdout, "Vulnerabilities  %d\n", info.Vulnerabilities)
	fmt.Fprintf(stdout, "KEV entries      %d\n", info.KEVEntries)
	fmt.Fprintf(stdout, "Created          %s\n", info.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(stdout, "Manifest SHA256  %s\n", info.ManifestSHA256)
	printFeedAuthenticity(stdout, info)
	return 0
}

func exportFeedBundle(
	ctx context.Context,
	database *store.DB,
	path string,
	createdAt time.Time,
) (feed.Info, error) {
	return exportFeedBundleWithSigningKey(ctx, database, path, createdAt, nil)
}

func exportFeedBundleWithSigningKey(
	ctx context.Context,
	database *store.DB,
	path string,
	createdAt time.Time,
	signingKey *feed.SigningKey,
) (feed.Info, error) {
	if err := validateCLIIdentifier("feed bundle path", path); err != nil {
		return feed.Info{}, err
	}
	if createdAt.IsZero() {
		createdAt = time.Now().UTC().Truncate(time.Second)
	}
	intelligence, err := database.ExportIntelligence(ctx)
	if err != nil {
		if errors.Is(err, store.ErrSnapshotNotFound) {
			err = errors.New("local vulnerability data is incomplete; run \"psirtmap feed pull\" first")
		}
		return feed.Info{}, err
	}
	snapshot := feed.Snapshot{
		OSV: feed.OSVSnapshot{
			Source:         intelligence.OSVSync.Source,
			SynchronizedAt: intelligence.OSVSync.SynchronizedAt,
			Packages:       intelligence.Packages,
		},
		CISAKEV: feed.KEVSnapshot{
			Source:          intelligence.KEVSync.Source,
			CatalogVersion:  intelligence.KEVSync.CatalogVersion,
			DateReleased:    intelligence.KEVSync.DateReleased,
			SynchronizedAt:  intelligence.KEVSync.SynchronizedAt,
			Vulnerabilities: intelligence.KEVEntries,
		},
	}
	feed.Sort(&snapshot)
	info, err := feed.WriteWithOptions(
		path, "PSIRTMap "+version, snapshot, createdAt,
		feed.WriteOptions{SigningKey: signingKey},
	)
	if err != nil {
		return feed.Info{}, err
	}
	return info, nil
}

func runFeedImport(ctx context.Context, args []string, stdout, stderr io.Writer, database *store.DB) int {
	options, err := parseFeedImportOptions(args)
	if err != nil {
		return usageError(stderr, err, printFeedUsage)
	}
	if options.help {
		printFeedUsage(stdout)
		return 0
	}
	path := options.path
	if err := validateCLIIdentifier("feed bundle path", path); err != nil {
		return usageError(stderr, err, printFeedUsage)
	}
	trustedKeys := make([]feed.TrustedKey, 0, len(options.trustedKeyPaths))
	seenKeyIDs := make(map[string]struct{}, len(options.trustedKeyPaths))
	for _, keyPath := range options.trustedKeyPaths {
		trusted, loadErr := feed.LoadTrustedKey(keyPath)
		if loadErr != nil {
			return commandError(stderr, loadErr)
		}
		if _, duplicate := seenKeyIDs[trusted.KeyID()]; duplicate {
			continue
		}
		seenKeyIDs[trusted.KeyID()] = struct{}{}
		trustedKeys = append(trustedKeys, trusted)
	}
	policy := feed.VerificationPolicy{
		TrustedKeys: trustedKeys, RequireSignature: len(trustedKeys) > 0,
	}
	info, result, err := importFeedBundleWithPolicy(ctx, database, path, policy)
	if err != nil {
		return commandError(stderr, err)
	}
	if options.jsonOutput {
		return printJSON(stdout, stderr, feedImportOutput{Bundle: info, Import: result})
	}
	fmt.Fprintln(stdout, "OFFLINE FEED IMPORTED")
	fmt.Fprintf(stdout, "Bundle           %s\n", oneLine(path))
	fmt.Fprintln(stdout, "Integrity        SHA-256 checksums verified")
	printFeedAuthenticity(stdout, info)
	fmt.Fprintf(stdout, "Packages         %d\n", result.Packages)
	fmt.Fprintf(stdout, "Vulnerabilities  %d\n", result.Vulnerabilities)
	fmt.Fprintf(stdout, "KEV entries      %d\n", result.KEVEntries)
	fmt.Fprintf(stdout, "Feed created     %s\n", result.BundleCreatedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(stdout, "Imported         %s\n", result.ImportedAt.Format("2006-01-02 15:04:05 UTC"))
	return 0
}

func importFeedBundle(
	ctx context.Context,
	database *store.DB,
	path string,
) (feed.Info, store.FeedImport, error) {
	return importFeedBundleWithPolicy(ctx, database, path, feed.VerificationPolicy{})
}

func importFeedBundleWithPolicy(
	ctx context.Context,
	database *store.DB,
	path string,
	policy feed.VerificationPolicy,
) (feed.Info, store.FeedImport, error) {
	if err := validateCLIIdentifier("feed bundle path", path); err != nil {
		return feed.Info{}, store.FeedImport{}, err
	}
	snapshot, info, err := feed.ReadWithPolicy(path, policy)
	if err != nil {
		return feed.Info{}, store.FeedImport{}, err
	}
	result, err := database.ImportIntelligence(ctx, store.IntelligenceSnapshot{
		OSVSync: store.VulnerabilitySync{
			Source: snapshot.OSV.Source, SynchronizedAt: snapshot.OSV.SynchronizedAt,
			Packages: info.Packages, Vulnerabilities: info.Vulnerabilities,
		},
		Packages: snapshot.OSV.Packages,
		KEVSync: store.KEVSync{
			Source: snapshot.CISAKEV.Source, CatalogVersion: snapshot.CISAKEV.CatalogVersion,
			DateReleased:   snapshot.CISAKEV.DateReleased,
			SynchronizedAt: snapshot.CISAKEV.SynchronizedAt, Entries: info.KEVEntries,
		},
		KEVEntries: snapshot.CISAKEV.Vulnerabilities,
	}, store.FeedImportMetadata{
		FormatVersion: info.FormatVersion, BundleCreatedAt: info.CreatedAt,
		SourceName: filepath.Base(path), ManifestSHA256: info.ManifestSHA256,
		Signed: info.Signed, SignatureVerified: info.SignatureVerified,
		SignerKeyID: info.SignerKeyID,
	})
	if err != nil {
		return feed.Info{}, store.FeedImport{}, err
	}
	return info, result, nil
}

func runFeedKeygen(args []string, stdout, stderr io.Writer) int {
	privatePath := "psirtmap-feed-signing-key.pem"
	publicPath := "psirtmap-feed-signing-key.pub.pem"
	jsonOutput := false
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--json":
			jsonOutput = true
		case isHelp(argument):
			printFeedUsage(stdout)
			return 0
		case argument == "--private-key":
			value, next, err := feedOptionValue(args, index, "--private-key")
			if err != nil {
				return usageError(stderr, err, printFeedUsage)
			}
			privatePath, index = value, next
		case strings.HasPrefix(argument, "--private-key="):
			privatePath = strings.TrimPrefix(argument, "--private-key=")
		case argument == "--public-key":
			value, next, err := feedOptionValue(args, index, "--public-key")
			if err != nil {
				return usageError(stderr, err, printFeedUsage)
			}
			publicPath, index = value, next
		case strings.HasPrefix(argument, "--public-key="):
			publicPath = strings.TrimPrefix(argument, "--public-key=")
		default:
			return usageError(stderr, fmt.Errorf("unknown option or argument %q", argument), printFeedUsage)
		}
	}
	for _, target := range []struct{ label, value string }{
		{"private key path", privatePath}, {"public key path", publicPath},
	} {
		if err := validateCLIIdentifier(target.label, target.value); err != nil {
			return usageError(stderr, err, printFeedUsage)
		}
	}
	keyID, err := feed.GenerateKeyPair(privatePath, publicPath)
	if err != nil {
		return commandError(stderr, err)
	}
	result := feedKeyOutput{
		Algorithm: "Ed25519", KeyID: keyID,
		PrivateKey: privatePath, PublicKey: publicPath,
	}
	if jsonOutput {
		return printJSON(stdout, stderr, result)
	}
	fmt.Fprintln(stdout, "FEED SIGNING KEY CREATED")
	fmt.Fprintf(stdout, "Algorithm        %s\n", result.Algorithm)
	fmt.Fprintf(stdout, "Key ID           %s\n", result.KeyID)
	fmt.Fprintf(stdout, "Private key      %s  (keep secret; do not transfer)\n", oneLine(result.PrivateKey))
	fmt.Fprintf(stdout, "Public key       %s  (transfer to importing systems)\n", oneLine(result.PublicKey))
	return 0
}

func parseFeedExportOptions(args []string) (feedExportOptions, error) {
	var options feedExportOptions
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--json":
			options.jsonOutput = true
		case isHelp(argument):
			options.help = true
		case argument == "--signing-key":
			value, next, err := feedOptionValue(args, index, "--signing-key")
			if err != nil {
				return options, err
			}
			options.signingKeyPath, index = value, next
		case strings.HasPrefix(argument, "--signing-key="):
			options.signingKeyPath = strings.TrimPrefix(argument, "--signing-key=")
		case strings.HasPrefix(argument, "-"):
			return options, fmt.Errorf("unknown option %q", argument)
		case options.path == "":
			options.path = argument
		default:
			return options, errors.New("feed export accepts at most one output path")
		}
	}
	return options, nil
}

func parseFeedImportOptions(args []string) (feedImportOptions, error) {
	var options feedImportOptions
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--json":
			options.jsonOutput = true
		case isHelp(argument):
			options.help = true
		case argument == "--trusted-key":
			value, next, err := feedOptionValue(args, index, "--trusted-key")
			if err != nil {
				return options, err
			}
			options.trustedKeyPaths = append(options.trustedKeyPaths, value)
			index = next
		case strings.HasPrefix(argument, "--trusted-key="):
			options.trustedKeyPaths = append(options.trustedKeyPaths, strings.TrimPrefix(argument, "--trusted-key="))
		case strings.HasPrefix(argument, "-"):
			return options, fmt.Errorf("unknown option %q", argument)
		case options.path == "":
			options.path = argument
		default:
			return options, errors.New("feed import requires exactly one bundle path")
		}
	}
	if !options.help && options.path == "" {
		return options, errors.New("feed import requires exactly one bundle path")
	}
	return options, nil
}

func feedOptionValue(args []string, index int, name string) (string, int, error) {
	if index+1 >= len(args) || strings.HasPrefix(args[index+1], "-") {
		return "", index, fmt.Errorf("%s requires a value", name)
	}
	value := strings.TrimSpace(args[index+1])
	if value == "" {
		return "", index, fmt.Errorf("%s requires a value", name)
	}
	return value, index + 1, nil
}

func printFeedAuthenticity(writer io.Writer, info feed.Info) {
	switch {
	case info.SignatureVerified:
		fmt.Fprintln(writer, "Authenticity     Ed25519 signature verified")
		fmt.Fprintf(writer, "Signer key ID    %s\n", info.SignerKeyID)
	case info.Signed:
		fmt.Fprintln(writer, "Authenticity     SIGNED — not verified (no trusted key supplied)")
		fmt.Fprintf(writer, "Signer key ID    %s\n", info.SignerKeyID)
	default:
		fmt.Fprintln(writer, "Authenticity     UNSIGNED — checksums only")
	}
}
