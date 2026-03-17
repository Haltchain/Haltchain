#!/bin/bash
# Manage PostgreSQL table partitions for decisions_hot

set -e

DB_URL="${DATABASE_URL:-postgres://haltchain:haltchain_dev@localhost:5432/haltchain}"

# Parse arguments
COMMAND="${1:-create}"
MONTHS_AHEAD="${2:-3}"

show_help() {
    echo "Usage: $0 [COMMAND] [MONTHS_AHEAD]"
    echo ""
    echo "Commands:"
    echo "  create [N]     Create partitions for current month + N months ahead (default: 3)"
    echo "  list           List all existing partitions"
    echo "  cleanup [N]    Drop partitions older than N months (default: 3)"
    echo "  help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 create 6           # Create partitions for next 6 months"
    echo "  $0 list               # Show all partitions"
    echo "  $0 cleanup 6          # Remove partitions older than 6 months"
}

# Check if psql is available
if ! command -v psql &> /dev/null; then
    echo "Error: psql is not installed. Install PostgreSQL client:"
    echo "  macOS: brew install libpq"
    echo "  Ubuntu: sudo apt-get install postgresql-client"
    exit 1
fi

# Test connection
if ! psql "$DB_URL" -c "SELECT 1;" > /dev/null 2>&1; then
    echo "Error: Cannot connect to database."
    echo "Make sure PostgreSQL is running: docker-compose up -d postgres"
    exit 1
fi

case "$COMMAND" in
    create)
        echo "Creating partitions for current month + $MONTHS_AHEAD months ahead..."
        psql "$DB_URL" << EOF
-- Ensure the helper function exists
CREATE OR REPLACE FUNCTION create_decisions_hot_partition(
    year INT,
    month INT
) RETURNS TEXT AS \$\$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    partition_name := 'decisions_hot_' || year || '_' || LPAD(month::TEXT, 2, '0');
    start_date := make_date(year, month, 1);
    end_date := start_date + INTERVAL '1 month';
    
    IF EXISTS (
        SELECT 1 FROM pg_class c 
        JOIN pg_namespace n ON n.oid = c.relnamespace 
        WHERE n.nspname = 'public' AND c.relname = partition_name
    ) THEN
        RETURN partition_name || ' already exists';
    END IF;
    
    EXECUTE format(
        'CREATE TABLE %I PARTITION OF decisions_hot 
         FOR VALUES FROM (%L) TO (%L)',
        partition_name,
        start_date,
        end_date
    );
    
    RETURN partition_name || ' created';
END;
\$\$ LANGUAGE plpgsql;

-- Create partitions
DO \$\$
DECLARE
    current_month DATE := date_trunc('month', CURRENT_DATE);
    i INT;
    result TEXT;
BEGIN
    FOR i IN 0..$MONTHS_AHEAD LOOP
        result := create_decisions_hot_partition(
            EXTRACT(YEAR FROM current_month + (i || ' months')::INTERVAL)::INT,
            EXTRACT(MONTH FROM current_month + (i || ' months')::INTERVAL)::INT
        );
        RAISE NOTICE '%', result;
    END LOOP;
END \$\$;
EOF
        echo "Partitions created successfully!"
        ;;
        
    list)
        echo "Existing partitions for decisions_hot:"
        psql "$DB_URL" << 'EOF'
SELECT 
    c.relname AS partition_name,
    pg_get_expr(c.relpartbound, c.oid) AS partition_range,
    pg_size_pretty(pg_total_relation_size(c.oid)) AS size
FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
JOIN pg_class p ON p.oid = i.inhparent
WHERE p.relname = 'decisions_hot'
ORDER BY c.relname;
EOF
        ;;
        
    cleanup)
        echo "Cleaning up partitions older than $MONTHS_AHEAD months..."
        psql "$DB_URL" << EOF
DO \$\$
DECLARE
    partition_rec RECORD;
    cutoff_date DATE := CURRENT_DATE - INTERVAL '$MONTHS_AHEAD months';
BEGIN
    FOR partition_rec IN 
        SELECT c.relname AS partition_name
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'decisions_hot'
        AND c.relname != 'decisions_hot_default'
        AND c.relname ~ '^decisions_hot_[0-9]{4}_[0-9]{2}\$'
    LOOP
        -- Extract year and month from partition name
        DECLARE
            partition_year INT;
            partition_month INT;
            partition_date DATE;
        BEGIN
            partition_year := (regexp_match(partition_rec.partition_name, 'decisions_hot_(\d{4})_(\d{2})'))[1]::INT;
            partition_month := (regexp_match(partition_rec.partition_name, 'decisions_hot_(\d{4})_(\d{2})'))[2]::INT;
            partition_date := make_date(partition_year, partition_month, 1);
            
            IF partition_date < cutoff_date THEN
                RAISE NOTICE 'Dropping old partition: %', partition_rec.partition_name;
                EXECUTE format('DROP TABLE IF EXISTS %I', partition_rec.partition_name);
            END IF;
        END;
    END LOOP;
END \$\$;
EOF
        echo "Cleanup completed!"
        ;;
        
    help|--help|-h)
        show_help
        ;;
        
    *)
        echo "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac
