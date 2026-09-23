CREATE TABLE IF NOT EXISTS department_attendance_settings (
  id TINYINT UNSIGNED PRIMARY KEY,
  location_name VARCHAR(160) NOT NULL,
  latitude DECIMAL(10,7) NOT NULL,
  longitude DECIMAL(10,7) NOT NULL,
  radius_meters DECIMAL(8,2) NOT NULL DEFAULT 5,
  morning_cutoff TIME NOT NULL DEFAULT '08:00:00',
  afternoon_time TIME NOT NULL DEFAULT '13:00:00',
  updated_by INT UNSIGNED NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS department_attendance (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  attendance_date DATE NOT NULL,
  morning_status ENUM('present','late','inactive','outside_location') NULL,
  afternoon_status ENUM('on_time','before_time','inactive','outside_location') NULL,
  morning_at DATETIME NULL,
  afternoon_at DATETIME NULL,
  latitude DECIMAL(10,7) NULL,
  longitude DECIMAL(10,7) NULL,
  distance_meters DECIMAL(8,2) NULL,
  morning_photo_path VARCHAR(255) NULL,
  afternoon_photo_path VARCHAR(255) NULL,
  score_deduction DECIMAL(5,2) UNSIGNED NOT NULL DEFAULT 0.00,
  outside_location_attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
  attendance_settings_updated_at DATETIME NULL,
  morning_warning_sent_date DATE NULL,
  afternoon_warning_sent_date DATE NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY department_attendance_day (user_id, attendance_date),
  KEY department_attendance_date (attendance_date),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS department_attendance_scores (
  user_id INT UNSIGNED PRIMARY KEY,
  score DECIMAL(6,2) NOT NULL DEFAULT 100.00,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

ALTER TABLE department_attendance
  ADD COLUMN IF NOT EXISTS morning_warning_sent_date DATE NULL,
  ADD COLUMN IF NOT EXISTS afternoon_warning_sent_date DATE NULL,
  ADD COLUMN IF NOT EXISTS attendance_settings_updated_at DATETIME NULL;