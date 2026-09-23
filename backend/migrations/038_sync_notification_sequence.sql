SELECT setval(
  pg_get_serial_sequence('notifications', 'id'),
  COALESCE((SELECT MAX(id) FROM notifications), 0) + 1,
  false
);
