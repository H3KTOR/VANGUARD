package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"vanguard/core/internal/database"
)

// runAuditCmd implements the audit-integrity workflow (Phase 15):
//
//	vanguard audit seal       [-db F]                        seal records not yet in the ledger
//	vanguard audit verify     [-db F] [-from N] [-max N] [-checkpoint F -key-file K] [-json]
//	vanguard audit keygen     -out FILE                      create a checkpoint key (0600, never overwrites)
//	vanguard audit checkpoint [-db F] -key-file K -out FILE  write an HMAC-authenticated ledger head
//
// verify is READ-ONLY and bounded. Exit status: 0 = nothing inconsistent found in
// what was examined; 1 = a discrepancy was found; 3 = verification could not
// complete (error). "0" is not a statement that no one tampered with the
// database; see docs/PHASE15.md for the trust assumptions.
func runAuditCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: vanguard audit seal|verify|keygen|checkpoint [flags]")
		os.Exit(2)
	}
	switch args[0] {
	case "seal":
		auditSeal(args[1:])
	case "verify":
		auditVerify(args[1:])
	case "keygen":
		auditKeygen(args[1:])
	case "checkpoint":
		auditCheckpoint(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "vanguard audit: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func auditFail(code int, err error) {
	fmt.Fprintf(os.Stderr, "vanguard audit: %v\n", err)
	os.Exit(code)
}

func readKeyFile(path string) []byte {
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
			auditFail(2, fmt.Errorf("key file %s has mode %04o; it must not be accessible to group/other (chmod 600)", path, st.Mode().Perm()))
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		auditFail(2, fmt.Errorf("cannot read the key file: %w", err))
	}
	k, err := database.ParseKey(string(b))
	if err != nil {
		auditFail(2, err)
	}
	return k
}

func auditSeal(args []string) {
	fs := flag.NewFlagSet("audit seal", flag.ExitOnError)
	db, _ := openRetentionDB(fs, args)
	defer db.Close()
	for i := 0; i < 100; i++ {
		r, err := db.SealPending(time.Now().UTC())
		if err != nil {
			auditFail(3, err)
		}
		printJSON(r)
		if !r.Remaining {
			return
		}
	}
}

func auditVerify(args []string) {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	from := fs.Uint64("from", 0, "first ledger sequence to check (default: 1)")
	max := fs.Int("max", database.MaxVerifyEntries, "maximum entries to examine")
	cpPath := fs.String("checkpoint", "", "also check this checkpoint file (needs -key-file)")
	keyPath := fs.String("key-file", "", "checkpoint key file")
	db, _ := openRetentionDB(fs, args)
	defer db.Close()

	rep, err := db.VerifyLedger(database.VerifyOptions{FromSeq: *from, MaxEntries: *max})
	if err != nil {
		auditFail(3, err)
	}
	var cpFindings []database.Finding
	if *cpPath != "" {
		if *keyPath == "" {
			auditFail(2, fmt.Errorf("-checkpoint needs -key-file"))
		}
		raw, err := os.ReadFile(*cpPath)
		if err != nil {
			auditFail(2, fmt.Errorf("cannot read the checkpoint: %w", err))
		}
		var cp database.Checkpoint
		if err := json.Unmarshal(raw, &cp); err != nil {
			auditFail(2, fmt.Errorf("the checkpoint file is not valid JSON"))
		}
		cpFindings = db.CheckCheckpoint(cp, readKeyFile(*keyPath))
		rep.Findings = append(rep.Findings, cpFindings...)
		rep.OK = len(rep.Findings) == 0
	}
	printJSON(map[string]any{
		"report":             rep,
		"checkpoint_checked": *cpPath != "",
		"meaning": "ok=true means no inconsistency was found in the entries examined, under the assumptions in docs/PHASE15.md. " +
			"It is not proof that no one with write access to the database rewrote history; only an external checkpoint can show that. " +
			"Records not yet sealed (the recent tail), and tables the ledger does not cover, are not examined.",
	})
	if !rep.OK {
		os.Exit(1)
	}
}

func auditKeygen(args []string) {
	fs := flag.NewFlagSet("audit keygen", flag.ExitOnError)
	out := fs.String("out", "", "key file to create (must not exist)")
	_ = fs.Parse(args)
	if *out == "" {
		auditFail(2, fmt.Errorf("-out is required"))
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		auditFail(3, err)
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		auditFail(2, fmt.Errorf("cannot create the key file (it must not already exist): %w", err))
	}
	if _, err := f.WriteString(hex.EncodeToString(buf) + "\n"); err != nil {
		f.Close()
		auditFail(3, err)
	}
	f.Close()
	fmt.Printf("key written to %s (mode 0600). Key id: %s\nStore a copy OFF this host. If the key is lost, existing checkpoints can no longer be authenticated; the ledger itself keeps working.\n", *out, database.KeyID(buf))
}

func auditCheckpoint(args []string) {
	fs := flag.NewFlagSet("audit checkpoint", flag.ExitOnError)
	keyPath := fs.String("key-file", "", "checkpoint key file (from `audit keygen`)")
	out := fs.String("out", "", "checkpoint file to write (must not exist)")
	db, _ := openRetentionDB(fs, args)
	defer db.Close()
	if *keyPath == "" || *out == "" {
		auditFail(2, fmt.Errorf("-key-file and -out are required"))
	}
	key := readKeyFile(*keyPath)
	if _, err := db.SealPending(time.Now().UTC()); err != nil {
		auditFail(3, err)
	}
	// a checkpoint over a damaged chain would anchor the damage
	if rep, err := db.VerifyLedger(database.VerifyOptions{}); err != nil || !rep.OK {
		auditFail(1, fmt.Errorf("refusing to checkpoint: the ledger does not verify (run `vanguard audit verify`)"))
	}
	cp, err := db.MakeCheckpoint(key, time.Now().UTC())
	if err != nil {
		auditFail(3, err)
	}
	b, _ := json.MarshalIndent(cp, "", "  ")
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		auditFail(2, fmt.Errorf("cannot create the checkpoint file (it must not already exist): %w", err))
	}
	_, _ = f.Write(append(b, '\n'))
	f.Close()
	fmt.Printf("checkpoint at ledger sequence %d written to %s. Copy it off this host; verify later with `vanguard audit verify -checkpoint %s -key-file <key>`.\n", cp.Seq, *out, *out)
}
