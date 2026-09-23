const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const config = {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || '5432',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'postgres',
};

const backupDir = path.join(__dirname, 'backups');
fs.mkdirSync(backupDir, { recursive: true });

const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
const outputFile = path.join(backupDir, `fkams-${timestamp}.sql`);

const dumpCommand = [
    'pg_dump',
    `--host=${config.host}`,
    `--port=${config.port}`,
    `--username=${config.user}`,
    `--dbname=${config.database}`,
    '--file', outputFile,
].join(' ');

try {
    execSync(dumpCommand, { stdio: 'inherit', env: { ...process.env, PGPASSWORD: config.password } });
    console.log(`Database backup created successfully: ${outputFile}`);
} catch (error) {
    console.error('Database backup failed. Check PostgreSQL credentials or the pg_dump binary.', error.message);
    process.exitCode = 1;
}
