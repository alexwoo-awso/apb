// Command apbctl is the local administration tool. It talks to the database
// directly, so it works when nobody can sign in: a lost authenticator, a
// forgotten password, an account locked out of its own console.
//
// Run it inside the container, against the same data directory as the server:
//
//	docker compose exec apb apbctl admin create --username alex --owner
//	docker compose exec apb apbctl admin reset-2fa --username alex
//	docker compose exec apb apbctl backup /data/backups/apb-2026-09-02.db
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/alexwoo-awso/apb/internal/auth"
	"github.com/alexwoo-awso/apb/internal/config"
	"github.com/alexwoo-awso/apb/internal/model"
	"github.com/alexwoo-awso/apb/internal/netutil"
	"github.com/alexwoo-awso/apb/internal/store"
	"github.com/alexwoo-awso/apb/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "apbctl: %v\n", err)
		os.Exit(1)
	}
}

const usage = `apbctl — local administration for APB

  admin list                       show console accounts
  admin create --username U        create an account (prompts for a password)
             [--owner|--viewer] [--display D] [--email E]
  admin passwd --username U        set a new password
  admin reset-2fa --username U     clear the second factor so it can be enrolled again
  admin unlock --username U        clear a failed-login lockout
  admin delete --username U        delete an account

  device list                      show routers
  device token --name N            issue a token and print it once
  device revoke --name N --prefix P  revoke a token

  whitelist add --cidr C [--reason R]   protect a range
  whitelist list

  import-legacy --device N --file F  load an old add.csv or an upload from src/w
  backup PATH                        write a consistent copy of the database
  maintain                           run expiry and retention now
  version

Every command reads APB_DATA_DIR (default /data), the same as the server.
`

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	case "version":
		fmt.Println(version.String())
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	db, err := store.Open(cfg.DBPath(), log)
	if err != nil {
		return err
	}
	defer db.Close()
	keys, err := auth.NewKeyring(cfg.SecretKey)
	if err != nil {
		return err
	}
	ctx := context.Background()

	switch args[0] {
	case "admin":
		return adminCmd(ctx, db, args[1:])
	case "device":
		return deviceCmd(ctx, db, keys, args[1:])
	case "whitelist":
		return whitelistCmd(ctx, db, args[1:])
	case "import-legacy":
		return importLegacy(ctx, db, args[1:])
	case "backup":
		if len(args) < 2 {
			return errors.New("backup needs a destination path")
		}
		if err := db.Backup(ctx, args[1]); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", args[1])
		return nil
	case "maintain":
		if err := db.Maintain(ctx); err != nil {
			return err
		}
		fmt.Println("maintenance complete")
		return nil
	default:
		return fmt.Errorf("unknown command %q; run apbctl --help", args[0])
	}
}

// ------------------------------------------------------------------- admin

func adminCmd(ctx context.Context, db *store.DB, args []string) error {
	if len(args) == 0 {
		return errors.New("admin needs a subcommand; run apbctl --help")
	}
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	username := fs.String("username", "", "account name")
	display := fs.String("display", "", "display name")
	email := fs.String("email", "", "email address")
	owner := fs.Bool("owner", false, "create as owner")
	viewer := fs.Bool("viewer", false, "create as read-only viewer")
	password := fs.String("password", "", "password (prompts when omitted; avoid on a shared shell)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	need := func() (model.Admin, error) {
		if *username == "" {
			return model.Admin{}, errors.New("--username is required")
		}
		return db.AdminByUsername(ctx, *username)
	}

	switch args[0] {
	case "list":
		admins, err := db.ListAdmins(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("%-20s %-8s %-5s %-8s %s\n", "USERNAME", "ROLE", "2FA", "STATE", "LAST SIGN IN")
		for _, a := range admins {
			state := "active"
			if a.Disabled {
				state = "disabled"
			} else if a.LockedUntil > time.Now().Unix() {
				state = "locked"
			}
			tfa := "no"
			if a.TOTPEnrolled {
				tfa = "yes"
			}
			fmt.Printf("%-20s %-8s %-5s %-8s %s\n", a.Username, a.Role, tfa, state, model.Stamp(a.LastLoginAt))
		}
		return nil

	case "create":
		if *username == "" {
			return errors.New("--username is required")
		}
		role := model.RoleAdmin
		if *owner {
			role = model.RoleOwner
		} else if *viewer {
			role = model.RoleViewer
		}
		pw, err := resolvePassword(*password)
		if err != nil {
			return err
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		a, err := db.CreateAdmin(ctx, model.Admin{
			Username: *username, DisplayName: *display, Email: *email,
			PassHash: hash, Role: role, CreatedBy: "apbctl",
		})
		if err != nil {
			return err
		}
		db.Audit(ctx, model.AuditEntry{Actor: "apbctl", ActorType: "system",
			Action: "user.create", Target: a.Username, Detail: "role=" + role, OK: true})
		fmt.Printf("created %s (%s). They will enrol an authenticator at first sign in.\n", a.Username, role)
		return nil

	case "passwd":
		a, err := need()
		if err != nil {
			return err
		}
		pw, err := resolvePassword(*password)
		if err != nil {
			return err
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		if err := db.SetPassword(ctx, a.ID, hash, false); err != nil {
			return err
		}
		if err := db.DeleteSessionsForAdmin(ctx, a.ID); err != nil {
			return err
		}
		db.Audit(ctx, model.AuditEntry{Actor: "apbctl", ActorType: "system",
			Action: "account.password_change", Target: a.Username, OK: true})
		fmt.Printf("password changed for %s; every session was signed out\n", a.Username)
		return nil

	case "reset-2fa":
		a, err := need()
		if err != nil {
			return err
		}
		if err := db.SetTOTP(ctx, a.ID, nil, false); err != nil {
			return err
		}
		if err := db.DeleteSessionsForAdmin(ctx, a.ID); err != nil {
			return err
		}
		db.Audit(ctx, model.AuditEntry{Actor: "apbctl", ActorType: "system",
			Action: "user.reset_2fa", Target: a.Username, OK: true})
		fmt.Printf("cleared the second factor for %s; they will enrol a new one at next sign in\n", a.Username)
		return nil

	case "unlock":
		a, err := need()
		if err != nil {
			return err
		}
		if err := db.UnlockAdmin(ctx, a.ID); err != nil {
			return err
		}
		fmt.Printf("unlocked %s\n", a.Username)
		return nil

	case "delete":
		a, err := need()
		if err != nil {
			return err
		}
		if a.Role == model.RoleOwner {
			if n, err := db.CountOwners(ctx); err == nil && n <= 1 {
				return errors.New("that is the last owner; promote someone else first")
			}
		}
		if err := db.DeleteAdmin(ctx, a.ID); err != nil {
			return err
		}
		db.Audit(ctx, model.AuditEntry{Actor: "apbctl", ActorType: "system",
			Action: "user.delete", Target: a.Username, OK: true})
		fmt.Printf("deleted %s\n", a.Username)
		return nil
	}
	return fmt.Errorf("unknown admin subcommand %q", args[0])
}

// ------------------------------------------------------------------ device

func deviceCmd(ctx context.Context, db *store.DB, keys *auth.Keyring, args []string) error {
	if len(args) == 0 {
		return errors.New("device needs a subcommand")
	}
	fs := flag.NewFlagSet("device", flag.ContinueOnError)
	name := fs.String("name", "", "device name")
	label := fs.String("label", "issued by apbctl", "token label")
	prefix := fs.String("prefix", "", "token prefix to revoke")
	days := fs.Int("days", 0, "token lifetime in days, 0 for no expiry")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	switch args[0] {
	case "list":
		devices, err := db.ListDevices(ctx, "")
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		fmt.Printf("%-22s %-9s %-12s %-10s %s\n", "NAME", "STATE", "LAST SYNC", "HOLDS", "CURSOR")
		for _, d := range devices {
			fmt.Printf("%-22s %-9s %-12s %-10d %d\n",
				d.Name, d.Health(now), model.Age(d.LastSyncAt, now), d.Applied, d.Cursor)
		}
		return nil

	case "token":
		if *name == "" {
			return errors.New("--name is required")
		}
		d, err := db.DeviceByName(ctx, *name)
		if err != nil {
			return err
		}
		token, err := auth.NewDeviceToken()
		if err != nil {
			return err
		}
		var expires int64
		if *days > 0 {
			expires = time.Now().AddDate(0, 0, *days).Unix()
		}
		if _, err := db.CreateToken(ctx, d.ID, auth.TokenPrefix(token), keys.TokenHash(token),
			*label, "apbctl", expires); err != nil {
			return err
		}
		db.Audit(ctx, model.AuditEntry{Actor: "apbctl", ActorType: "system",
			Action: "device.token_issue", Target: d.Name, Detail: auth.TokenPrefix(token), OK: true})
		fmt.Printf("token for %s, shown once:\n\n  %s\n\n", d.Name, token)
		return nil

	case "revoke":
		if *name == "" || *prefix == "" {
			return errors.New("--name and --prefix are required")
		}
		d, err := db.DeviceByName(ctx, *name)
		if err != nil {
			return err
		}
		tokens, err := db.ListTokens(ctx, d.ID)
		if err != nil {
			return err
		}
		for _, t := range tokens {
			if strings.HasPrefix(t.Prefix, *prefix) {
				if err := db.RevokeToken(ctx, t.ID); err != nil {
					return err
				}
				fmt.Printf("revoked %s… on %s\n", t.Prefix, d.Name)
				return nil
			}
		}
		return fmt.Errorf("no token on %s starts with %q", d.Name, *prefix)
	}
	return fmt.Errorf("unknown device subcommand %q", args[0])
}

// --------------------------------------------------------------- whitelist

func whitelistCmd(ctx context.Context, db *store.DB, args []string) error {
	if len(args) == 0 {
		return errors.New("whitelist needs a subcommand")
	}
	fs := flag.NewFlagSet("whitelist", flag.ContinueOnError)
	cidr := fs.String("cidr", "", "address or range")
	reason := fs.String("reason", "", "why")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	switch args[0] {
	case "add":
		if *cidr == "" {
			return errors.New("--cidr is required")
		}
		e, released, err := db.AddWhitelist(ctx, *cidr, *reason, "apbctl", 0)
		if err != nil {
			return err
		}
		fmt.Printf("whitelisted %s, released %d blocked address(es)\n", e.CIDR, released)
		return nil

	case "list":
		rows, total, err := db.ListWhitelist(ctx, "", 500, 0)
		if err != nil {
			return err
		}
		fmt.Printf("%d rule(s)\n", total)
		for _, e := range rows {
			fmt.Printf("%-20s %-8d %s\n", e.CIDR, e.Hits, e.Reason)
		}
		return nil
	}
	return fmt.Errorf("unknown whitelist subcommand %q", args[0])
}

// ------------------------------------------------------------------ import

// importLegacy loads addresses from the flat CSV files the original APB kept,
// attributing them to a device row so they carry the same provenance as
// anything else on the list.
func importLegacy(ctx context.Context, db *store.DB, args []string) error {
	fs := flag.NewFlagSet("import-legacy", flag.ContinueOnError)
	device := fs.String("device", "", "device to attribute the import to")
	file := fs.String("file", "", "file or directory to read")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *device == "" || *file == "" {
		return errors.New("--device and --file are required")
	}
	d, err := db.DeviceByName(ctx, *device)
	if err != nil {
		return fmt.Errorf("device %q: %w", *device, err)
	}

	var files []string
	info, err := os.Stat(*file)
	if err != nil {
		return err
	}
	if info.IsDir() {
		entries, err := os.ReadDir(*file)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".csv") {
				files = append(files, filepath.Join(*file, e.Name()))
			}
		}
	} else {
		files = []string{*file}
	}
	if len(files) == 0 {
		return errors.New("no CSV files found")
	}

	now := time.Now().Unix()
	var total store.IngestResult
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		res, err := db.Ingest(ctx, d.ID, netutil.SplitList(string(body)), now)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		fmt.Printf("%-40s accepted %-6d new %-6d blocked %-6d rejected %d\n",
			filepath.Base(f), res.Accepted, res.NewAddresses, res.Broadcast, res.Invalid+res.Whitelisted)
		total.Accepted += res.Accepted
		total.NewAddresses += res.NewAddresses
		total.Broadcast += res.Broadcast
		total.Invalid += res.Invalid
		total.Whitelisted += res.Whitelisted
	}
	db.Audit(ctx, model.AuditEntry{Actor: "apbctl", ActorType: "system",
		Action: "address.import", Target: d.Name,
		Detail: fmt.Sprintf("%d files, %d new", len(files), total.NewAddresses), OK: true})
	fmt.Printf("\ntotal: %d accepted, %d new, %d broadcast, %d rejected\n",
		total.Accepted, total.NewAddresses, total.Broadcast, total.Invalid+total.Whitelisted)
	return nil
}

// ----------------------------------------------------------------- helpers

// resolvePassword prefers an interactive prompt so the password never reaches
// the shell history or the process list.
func resolvePassword(given string) (string, error) {
	if given != "" {
		if err := auth.CheckPasswordPolicy(given); err != nil {
			return "", err
		}
		return given, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", errors.New("no password supplied on stdin")
		}
		pw := strings.TrimRight(line, "\r\n")
		if err := auth.CheckPasswordPolicy(pw); err != nil {
			return "", err
		}
		return pw, nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Repeat:   ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("the two passwords do not match")
	}
	if err := auth.CheckPasswordPolicy(string(first)); err != nil {
		return "", err
	}
	return string(first), nil
}
