#!/bin/bash
# Run PostgreSQL migrations (works with local OR Supabase)

set -e

# Use DATABASE_URL from environment or .env.docker
if [ -f .env.docker ]; then
    export $(grep -v '^#' .env.docker | xargs)
fi

DB_URL="${DATABASE_URL:-postgres://haltchain:haltchain_dev@localhost:5432/haltchain}"
SEED_DATA=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --seed)
            SEED_DATA=true
            shift
            ;;
        --url)
            DB_URL="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --seed         Include test data seeding after migrations"
            echo "  --url URL      Use specific database URL"
            echo "  --help         Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Use DATABASE_URL from .env.docker"
            echo "  $0 --seed                             # Run migrations + seed data"
            echo "  $0 --url postgresql://...           # Use specific URL"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "====================================="
echo "HaltChain Database Migration Tool"
echo "====================================="
echo ""

# Mask password in output
MASKED_URL=$(echo "$DB_URL" | sed -E 's/:[^:@]+@/@/')
echo "Target: $MASKED_URL"
echo ""

# Check if psql is available
if ! command -v psql &> /dev/null; then
    echo "Error: psql is not installed. Install PostgreSQL client:"
    echo "  macOS: brew install libpq"
    echo "  Ubuntu: sudo apt-get install postgresql-client"
    exit 1
fi

# Test connection
echo "Testing database connection..."
if ! psql "$DB_URL" -c "SELECT 1;" > /dev/null 2>&1; then
    echo ""
    echo "Error: Cannot connect to database."
    echo ""
    echo "If using Supabase:"
    echo "  1. Make sure you're using the Session Pooler URL (IPv4 compatible)"
    echo "  2. Check your password is correct"
    echo "  3. Verify network access in Supabase Dashboard → Database → Network Restrictions"
    echo ""
    echo "Session pooler URL format (recommended baseline):"
    echo "  postgresql://postgres.[PROJECT]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:5432/postgres?sslmode=require"
    echo ""
    echo "Transaction pooler URL format (not recommended for baseline runs):"
    echo "  postgresql://postgres.[PROJECT]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres?sslmode=require"
    exit 1
fi

echo "Connection successful!"
echo ""

# Run schema migrations (001-005)
echo "Running schema migrations..."
for migration in migrations/00[1-5]*.sql; do
    if [ -f "$migration" ]; then
        filename=$(basename "$migration")
        echo "  → $filename"
        psql "$DB_URL" -f "$migration" > /dev/null 2>&1
    fi
done

echo ""
echo "Schema migrations completed! ✓"

# Create partitions for decisions_hot table
echo ""
echo "Creating table partitions for decisions_hot..."
if [ -f "migrations/006_create_partitions.sql" ]; then
    psql "$DB_URL" -f "migrations/006_create_partitions.sql" > /dev/null 2>&1
    echo "Partitions created! ✓"
fi

# Show current partitions
echo ""
echo "Current partitions:"
psql "$DB_URL" << 'EOF' 2>/dev/null | grep -E "decisions_hot_|already exists|created" || true
DO $$
DECLARE
    current_month DATE := date_trunc('month', CURRENT_DATE);
    i INT;
    result TEXT;
BEGIN
    FOR i IN 0..3 LOOP
        result := create_decisions_hot_partition(
            EXTRACT(YEAR FROM current_month + (i || ' months')::INTERVAL)::INT,
            EXTRACT(MONTH FROM current_month + (i || ' months')::INTERVAL)::INT
        );
        RAISE NOTICE '%', result;
    END LOOP;
END $$;
EOF

# Seed data if requested
if [ "$SEED_DATA" = true ]; then
    echo ""
    echo "Seeding test data..."
    if [ -f "migrations/999_seed_test_data.sql" ]; then
        psql "$DB_URL" -f "migrations/999_seed_test_data.sql" > /dev/null 2>&1
        echo "Test data seeded! ✓"
        echo ""
        echo "To create the first admin account, set:"
        echo "  HALTCHAIN_BOOTSTRAP_ADMIN_EMAIL and HALTCHAIN_BOOTSTRAP_ADMIN_PASSWORD"
        echo "The API will create the account on startup if admin_users is empty."
    fi
fi

echo ""
echo "====================================="
echo "Done!"
echo "====================================="
