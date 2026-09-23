/**
 * Automatic migration handler for FKAMS
 * Runs pending migrations at server startup
 */

const fs = require('fs');
const path = require('path');
const { normalizeSql } = require('./db');

function splitStatements(sql) {
    return sql
        .split(/\r?\n/)
        .filter(line => !line.trim().startsWith('--'))
        .join('\n')
        .split(';')
        .map(stmt => stmt.trim())
        .filter(stmt => stmt.length > 0 && !stmt.startsWith('--'))
        .filter(stmt => !/^(SET|PREPARE|EXECUTE|DEALLOCATE)\b/i.test(stmt))
        .map(normalizeSql);
}

function isIgnorableMigrationError(error) {
    return error.code === '42P07' || error.code === '42701' || error.code === '42710'
        || error.code === 'ER_TABLE_EXISTS_ERROR' || error.code === 'ER_DUP_FIELDNAME'
        || error.code === 'ER_DUP_KEYNAME' || error.code === 'ER_FK_DUP_NAME'
        || /already exists|duplicate/i.test(error.message);
}

async function runPendingMigrations(pool) {
    console.log('🔄 Checking for pending migrations...');

    const migrationsDir = path.join(__dirname, 'migrations');
    const migrationFiles = fs.readdirSync(migrationsDir)
        .filter(f => /^\d+_.*\.sql$/.test(f))
        .sort();

    await pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto');
    const baseSchema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf-8');
    const baseStatements = splitStatements(baseSchema).map(statement => statement.replace(/CREATE TABLE(?! IF NOT EXISTS)/gi, 'CREATE TABLE IF NOT EXISTS'));
    const baseConnection = await pool.getConnection();
    try {
        for (const statement of baseStatements) {
            try { await baseConnection.query(statement); } catch (error) {
                if (!isIgnorableMigrationError(error)) throw error;
            }
        }
        console.log('  ✓ schema.sql');
    } finally {
        baseConnection.release();
    }

    for (const file of migrationFiles) {
        const migrationPath = path.join(migrationsDir, file);
        const sql = fs.readFileSync(migrationPath, 'utf-8');
        const statements = splitStatements(sql);

        const connection = await pool.getConnection();
        try {
            for (const statement of statements) {
                try {
                    await connection.query(statement);
                } catch (err) {
                    // Allow "already exists" errors - they're not failures
                    if (isIgnorableMigrationError(err)) {
                        // Silently skip
                        continue;
                    }
                    // Re-throw other errors
                    throw err;
                }
            }
            console.log(`  ✓ ${file}`);
        } catch (error) {
            console.error(`  ✗ ${file}: ${error.message}`);
            throw error;
        } finally {
            connection.release();
        }
    }

    console.log('✅ Migrations complete\n');
}

module.exports = { runPendingMigrations };
