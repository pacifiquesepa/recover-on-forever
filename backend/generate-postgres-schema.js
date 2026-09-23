require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { normalizeSql } = require('./db');

const source = path.join(__dirname, 'schema.sql');
const target = path.join(__dirname, 'schema.postgres.sql');
fs.writeFileSync(target, normalizeSql(fs.readFileSync(source, 'utf8')));
console.log(`Generated ${target}`);
