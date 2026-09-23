require('dotenv').config();

const bcrypt = require('bcryptjs');
const { createPool } = require('./db');

async function seedAdmin() {
  const username = process.env.ADMIN_USERNAME || 'pacifiquesepa';
  const password = process.env.ADMIN_PASSWORD || 'Admin12345$';
  const fullName = process.env.ADMIN_NAME || 'System Administrator';
  const email = process.env.ADMIN_EMAIL || 'pacifiquesepa@gmail.com';
  const phone = process.env.ADMIN_PHONE || "0793360920";
  const passwordHash = await bcrypt.hash(password, 12);
  const pool = createPool();
  const connection = await pool.getConnection();

  try {
    await connection.query(
      `INSERT INTO users (full_name, username, email, phone, password_hash, role, is_active)
       VALUES (?, ?, ?, ?, ?, 'admin', TRUE)
       ON CONFLICT (username) DO UPDATE SET
         full_name = EXCLUDED.full_name,
         email = EXCLUDED.email,
         phone = EXCLUDED.phone,
         password_hash = EXCLUDED.password_hash,
         role = 'admin',
         is_active = TRUE`,
      [fullName, username, email, phone, passwordHash],
    );
    console.log(`Default admin is ready: ${username}`);
  } finally {
    connection.release();
    await pool.end();
  }
}

seedAdmin().catch((error) => {
  console.error(`Unable to seed admin: ${error.message}`);
  process.exitCode = 1;
});
