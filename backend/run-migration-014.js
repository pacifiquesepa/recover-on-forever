#!/usr/bin/env node
/**
 * Migration runner for migration 014 (graduates_promotions)
 * Usage: node run-migration-014.js
 */

require('dotenv').config();
const { createPool } = require('./db');
const fs = require('fs');
const path = require('path');

async function runMigration() {
    const pool = createPool();

    const connection = await pool.getConnection();
    try {
        // Read migration file
        const migrationPath = path.join(__dirname, 'migrations', '014_graduates_promotions.sql');
        const sql = fs.readFileSync(migrationPath, 'utf-8');

        // Split by semicolon and execute each statement
        const statements = sql
            .split(';')
            .map(stmt => stmt.trim())
            .filter(stmt => stmt.length > 0 && !stmt.startsWith('--'));

        console.log(`Running migration 014 with ${statements.length} statements...`);

        for (let i = 0; i < statements.length; i++) {
            try {
                await connection.query(statements[i]);
                console.log(`  ✓ Statement ${i + 1}/${statements.length} executed`);
            } catch (err) {
                // Some statements might fail if tables already exist - that's OK
                if (err.code === 'ER_TABLE_EXISTS_ERROR' || err.message.includes('already exists')) {
                    console.log(`  ⚠ Statement ${i + 1} (already exists, skipping)`);
                } else {
                    throw err;
                }
            }
        }

        console.log('\n✅ Migration 014 completed successfully!');
        console.log('Tables/views created:');
        console.log('  - student_promotions');
        console.log('  - Added columns to students table: graduation_date, graduated_cohort');
        console.log('  - v_graduates view');
    } catch (error) {
        console.error('\n❌ Migration failed:', error.message);
        process.exit(1);
    } finally {
        connection.release();
        await pool.end();
    }
}

runMigration();
