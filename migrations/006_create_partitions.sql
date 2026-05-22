-- Create monthly partitions for decisions_hot table
-- Run this after 001_decisions_and_feedback.sql or as part of setup
-- This creates partitions for current month and next 3 months

-- Helper function to create partitions
CREATE OR REPLACE FUNCTION create_decisions_hot_partition(
    year INT,
    month INT
) RETURNS TEXT AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    partition_name := 'decisions_hot_' || year || '_' || LPAD(month::TEXT, 2, '0');
    start_date := make_date(year, month, 1);
    end_date := start_date + INTERVAL '1 month';
    
    -- Check if partition already exists
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
$$ LANGUAGE plpgsql;

-- Create partitions for current month and next 3 months
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
