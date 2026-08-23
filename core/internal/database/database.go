package database

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/glebarez/sqlite" // pure-Go SQLite driver (no CGO)
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// DB wraps a *gorm.DB with VANGUARD-specific convenience methods. It is safe
// for concurrent use by multiple goroutines (GORM manages its own
// connection pool over database/sql).
type DB struct {
	*gorm.DB
}

// Config controls how the database is opened.
type Config struct {
	// Path to the SQLite file, e.g. "/var/lib/vanguard/vanguard.db".
	// Use ":memory:" for ephemeral in-process testing.
	Path string
	// Verbose enables GORM's SQL statement logging (development only).
	Verbose bool
}

// Open connects to the SQLite database at cfg.Path, applies pragmas tuned
// for a single-writer/many-reader embedded workload, and runs AutoMigrate
// for every model in AllModels(). It is intentionally the single entry
// point for database setup so cmd/vanguard/main.go stays trivial.
func Open(cfg Config) (*DB, error) {
	logLevel := gormlogger.Silent
	if cfg.Verbose {
		logLevel = gormlogger.Info
	}

	dsn := cfg.Path
	if dsn == "" {
		dsn = "vanguard.db"
	}

	// Enable WAL mode + a busy timeout via DSN query params so concurrent
	// readers (dashboard API) don't block the writer (log tailer / metric
	// collector). foreign_keys=on enforces the (currently soft) relations.
	if dsn != ":memory:" {
		dsn = fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)", dsn)
	}

	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(logLevel),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("database: failed to open sqlite at %q: %w", cfg.Path, err)
	}

	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, fmt.Errorf("database: failed to get underlying sql.DB: %w", err)
	}
	// SQLite has a single writer; keep the pool small and predictable.
	sqlDB.SetMaxOpenConns(8)
	sqlDB.SetMaxIdleConns(4)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	if err := gdb.AutoMigrate(AllModels()...); err != nil {
		return nil, fmt.Errorf("database: automigrate failed: %w", err)
	}

	db := &DB{gdb}
	log.Printf("[database] opened %s (WAL) and migrated %d models", cfg.Path, len(AllModels()))
	return db, nil
}

// MustOpen is like Open but exits the process on failure. Intended for use
// only in main().
func MustOpen(cfg Config) *DB {
	db, err := Open(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return db
}

// Close releases the underlying connection pool.
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
