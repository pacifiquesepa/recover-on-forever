-- Migration 014: Graduates and Promotions Tracking
-- This migration adds support for tracking student promotions and graduations

CREATE TABLE IF NOT EXISTS student_promotions (
  id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  student_id INT UNSIGNED NOT NULL,
  academic_year_id INT UNSIGNED NOT NULL,
  from_level VARCHAR(80) NOT NULL,
  to_level VARCHAR(80) NULL,
  action ENUM('promoted', 'retained', 'graduated') NOT NULL,
  promoted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  promotion_notes TEXT NULL,
  created_by INT UNSIGNED NOT NULL,
  UNIQUE KEY student_year (student_id, academic_year_id),
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY (academic_year_id) REFERENCES academic_years(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE subjects
  ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;

-- Add graduation_date and graduated_cohort to students table if not exists
ALTER TABLE students 
ADD COLUMN IF NOT EXISTS graduation_date DATE NULL,
ADD COLUMN IF NOT EXISTS graduated_cohort VARCHAR(100) NULL;

DROP VIEW IF EXISTS v_graduates;
CREATE VIEW v_graduates AS
SELECT 
  s.id,
  s.user_id,
  s.full_name,
  split_part(s.full_name, ' ', 1) as first_name,
  split_part(s.full_name, ' ', array_length(string_to_array(s.full_name, ' '), 1)) as last_name,
  s.admission_number as reg_number,
  s.photo_key,
  s.class_name as from_level,
  s.academic_year,
  s.graduation_date as graduated_at,
  s.graduated_cohort as promotion_notes,
  sp.to_level as final_level,
  COALESCE(sp.to_level, sp.from_level) as trade,
  ay.name as academic_year_name,
  ay.start_date,
  ay.end_date,
  u.email as contact_email,
  u.phone as contact_phone,
  NULL as address_district,
  NULL as address_sector,
  NULL as guardian_name,
  NULL as guardian_phone,
  sp.id as promotion_id
FROM students s
LEFT JOIN student_promotions sp ON s.id = sp.student_id
LEFT JOIN academic_years ay ON sp.academic_year_id = ay.id
LEFT JOIN users u ON s.user_id = u.id
WHERE s.status = 'graduated';
