ALTER TABLE department_attendance_scores
  ALTER COLUMN score DROP DEFAULT;
ALTER TABLE department_attendance_scores
  ALTER COLUMN score TYPE DECIMAL(6,2) USING score::numeric;
ALTER TABLE department_attendance_scores
  ALTER COLUMN score SET DEFAULT 100.00;

ALTER TABLE department_attendance
  ALTER COLUMN score_deduction DROP DEFAULT;
ALTER TABLE department_attendance
  ALTER COLUMN score_deduction TYPE DECIMAL(5,2) USING score_deduction::numeric;
ALTER TABLE department_attendance
  ALTER COLUMN score_deduction SET DEFAULT 0.00;
