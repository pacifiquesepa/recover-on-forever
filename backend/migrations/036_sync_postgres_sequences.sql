SELECT setval(
  pg_get_serial_sequence('department_attendance', 'id'),
  COALESCE((SELECT MAX(id) FROM department_attendance), 0) + 1,
  false
);