ALTER TABLE users
  ALTER COLUMN is_active DROP DEFAULT;
ALTER TABLE users
  ALTER COLUMN is_active TYPE BOOLEAN USING (is_active::text IN ('1', 'true', 't'));
ALTER TABLE users
  ALTER COLUMN is_active SET DEFAULT TRUE;

ALTER TABLE security_guard_permissions
  ALTER COLUMN enabled DROP DEFAULT;
ALTER TABLE security_guard_permissions
  ALTER COLUMN enabled TYPE BOOLEAN USING (enabled::text IN ('1', 'true', 't'));
ALTER TABLE security_guard_permissions
  ALTER COLUMN enabled SET DEFAULT TRUE;

ALTER TABLE classes
  ALTER COLUMN is_active DROP DEFAULT;
ALTER TABLE classes
  ALTER COLUMN is_active TYPE BOOLEAN USING (is_active::text IN ('1', 'true', 't'));
ALTER TABLE classes
  ALTER COLUMN is_active SET DEFAULT TRUE;

ALTER TABLE subjects
  ALTER COLUMN is_active DROP DEFAULT;
ALTER TABLE subjects
  ALTER COLUMN is_active TYPE BOOLEAN USING (is_active::text IN ('1', 'true', 't'));
ALTER TABLE subjects
  ALTER COLUMN is_active SET DEFAULT TRUE;

ALTER TABLE tests
  ALTER COLUMN is_published DROP DEFAULT,
  ALTER COLUMN is_draft DROP DEFAULT;
ALTER TABLE tests
  ALTER COLUMN is_published TYPE BOOLEAN USING (is_published::text IN ('1', 'true', 't')),
  ALTER COLUMN is_draft TYPE BOOLEAN USING (is_draft::text IN ('1', 'true', 't'));
ALTER TABLE tests
  ALTER COLUMN is_published SET DEFAULT FALSE,
  ALTER COLUMN is_draft SET DEFAULT TRUE;

ALTER TABLE test_questions
  ALTER COLUMN is_draft DROP DEFAULT;
ALTER TABLE test_questions
  ALTER COLUMN is_draft TYPE BOOLEAN USING (is_draft::text IN ('1', 'true', 't'));
ALTER TABLE test_questions
  ALTER COLUMN is_draft SET DEFAULT FALSE;

ALTER TABLE academic_years
  ALTER COLUMN is_current DROP DEFAULT;
ALTER TABLE academic_years
  ALTER COLUMN is_current TYPE BOOLEAN USING (is_current::text IN ('1', 'true', 't'));
ALTER TABLE academic_years
  ALTER COLUMN is_current SET DEFAULT FALSE;

ALTER TABLE transport_routes
  ALTER COLUMN is_active DROP DEFAULT;
ALTER TABLE transport_routes
  ALTER COLUMN is_active TYPE BOOLEAN USING (is_active::text IN ('1', 'true', 't'));
ALTER TABLE transport_routes
  ALTER COLUMN is_active SET DEFAULT TRUE;

ALTER TABLE feeding_records
  ALTER COLUMN served DROP DEFAULT;
ALTER TABLE feeding_records
  ALTER COLUMN served TYPE BOOLEAN USING (served::text IN ('1', 'true', 't'));
ALTER TABLE feeding_records
  ALTER COLUMN served SET DEFAULT TRUE;
