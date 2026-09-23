# FKAMS Backend

Node.js + Express + PostgreSQL API for Forever King Academy Management System. The production database is hosted on Supabase.

## Setup

1. Install dependencies:

```powershell
npm install
```

2. Configure Supabase PostgreSQL in `.env`:

```env
DB_HOST=aws-1-eu-west-1.pooler.supabase.com
DB_PORT=5432
DB_USER=postgres.project-ref
DB_PASSWORD=your-supabase-password
DB_NAME=postgres
DB_SSL=true
```

The backend uses SSL for Supabase. Do not commit `.env`; rotate any database password that has been exposed.

3. Create the database and tables:

```powershell
node generate-postgres-schema.js
psql "$env:DATABASE_URL" -f schema.postgres.sql
```

For a newly created Supabase database, the API also applies the base schema and numbered migrations at startup. The generated schema file is useful for a first manual import or inspection.

After the base schema, apply later migrations in order when importing manually:

```powershell
node generate-postgres-schema.js
psql "$env:DATABASE_URL" -f schema.postgres.sql
```

3. Copy `.env.example` to `.env` and set a long random `JWT_SECRET` plus the Supabase credentials.

For public applications, configure Gmail SMTP in `backend/.env`. Use a Google App Password, not the normal Gmail password:

```powershell
Copy-Item .env.example .env
```

Then edit these values in `.env`:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-gmail-address@gmail.com
SMTP_PASSWORD=your-16-character-google-app-password
SMTP_FROM=your-gmail-address@gmail.com
```

The Gmail account must have two-step verification enabled before an App Password can be created. Restart `npm start` after changing `.env`. If SMTP is missing or Gmail rejects the login, the application is deliberately not saved because the parent confirmation email cannot be delivered.

4. Create the default administrator account:

```powershell
npm run seed:admin
```

The default development credentials are `admin123` and `Admin12345$`. The password is stored as a bcrypt hash. The account uses `admin@fkams.local` for the default console OTP destination; change `ADMIN_EMAIL` before using a real OTP provider.

5. Start the API:

```powershell
npm start
```

The API listens on `http://localhost:4000` by default.

To deliver OTPs by email, configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, and optionally `SMTP_FROM`/`SMTP_SECURE` in `.env`. Without SMTP settings, development OTPs are printed in the backend console.

Admission decisions notify the parent using the submitted phone number or email. Configure the same SMTP settings for email delivery. For SMS delivery, configure `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_FROM`; without a provider, the notification is printed in the backend console. Approved applicants receive their generated admission number as the student login username and a generated temporary password.

## Main routes

- `GET /api/health` - API/database health
- `POST /api/auth/login` - username/email and password verification; returns an OTP challenge for configured roles
- `POST /api/auth/verify-otp` - verify the six-digit OTP and receive a JWT
- `POST /api/auth/resend-otp` - request a new OTP with throttling
- `POST /api/auth/forgot-password`, `POST /api/auth/verify-reset-otp`, `POST /api/auth/reset-password` - two-minute password recovery OTP flow
- `GET /api/dashboard` - admin/DOS/accountant metrics
- `POST /api/users` - admin/DOS user creation
- `GET|POST /api/students` - role-scoped student records
- `GET /api/students/qr/:token` - secure QR identity lookup
- `POST /api/applications` - public admission application
- `GET /api/applications` - admin/DOS application review
- `PATCH /api/applications/:id/status` - approve/reject with comment
- Approving an application atomically creates the student user, temporary password, admission number and QR token.
- `POST /api/students` - DOS/admin registration for students who did not apply
- `POST /api/teachers/register` - DOS/admin teacher registration with automatic QR token
- `GET /api/student/profile` - student read-only profile and QR data
- `PATCH /api/student/profile/photo` - student-only photo update
- `PATCH /api/dos/students/:id/profile` - DOS/admin full student profile update
- `GET|POST /api/attendance` - role-scoped attendance
- `GET|POST /api/classes` - class management
- `GET|POST /api/subjects` - subject management
- `POST /api/teacher-assignments` - assign teacher, class and subject
- `GET|POST /api/tests` - tests visible by role/assignment
- `POST /api/tests/:id/questions` - choice, fill and match questions
- `POST /api/tests/:id/attempts` - student starts one attempt
- `POST /api/test-attempts/:id/submit` - server-side timed submission/grading
- `GET|POST /api/grades` - role-scoped academic grades
- `GET|POST /api/notices` - school notices
- `GET|POST /api/timetable` - class timetable
- `GET /api/teachers` and `POST /api/teachers/:id/profile` - teacher contracts and profiles
- `POST /api/staff-attendance` - staff attendance
- `GET|POST /api/finance/invoices` - fee invoices, scoped to parents/students
- `GET|POST /api/finance/payments` - fee payments and history
- `GET|POST /api/finance/expenses` - expenses
- `GET|POST /api/finance/budgets` - budgets
- `GET|POST /api/transport/routes` and `POST /api/transport/assign` - transport
- `GET|POST /api/inventory` - store inventory
- `GET|POST /api/assets` - asset register
- `GET|POST /api/library/books` - library catalogue
- `GET|POST /api/library/loans` and `PATCH /api/library/loans/:id/return` - borrowing and returns
- `GET /api/feeding/stock` and `POST /api/feeding/records` - feeding
- `GET|POST /api/documents` - document metadata and secure visibility
- `GET /api/publications` - public announcements and documents for the website
- `GET /api/news` and `POST /api/news` - public news and event posts
- `GET /api/curriculum` and `POST /api/curriculum` - public curriculum managed by Admin/DOS
- `GET|POST /api/homework` - teacher homework and role-scoped viewing
- `GET /api/notifications` and `PATCH /api/notifications/:id/read` - parent/user notifications
- `GET|POST /api/behavior` - behavior records
- `GET /api/students/:id/report` - consolidated student report

## OTP login

By default OTP is required for `admin`, `dos`, `parent`, `teacher`, `accountant` and `librarian`. The `student` role is excluded by default. Change `OTP_ROLES` in `.env` if the policy changes. Users in OTP roles need an email (default `OTP_CHANNEL=email`) or phone (with `OTP_CHANNEL=sms`).

For local development, `OTP_PROVIDER=console` prints the code in the backend terminal and never returns it in the HTTP response. A real email/SMS adapter must replace this provider before production; do not expose OTP codes through the frontend or API response.

## Security behavior

- Passwords are stored as bcrypt hashes; plain passwords are never persisted.
- JWTs expire after eight hours and protected routes require `Authorization: Bearer <token>`.
- OTP codes are hashed, expire after five minutes by default, are single-use, and allow only five verification attempts.
- Role middleware blocks unauthorized modules.
- Teacher access is limited to assigned class/subject students.
- Parents can access only linked children; students can access only their own records.
- Test expiry is checked on the API, so changing the browser clock cannot extend a test.
- SQL values use parameterized queries.
- Helmet, restricted CORS, JSON size limits and login attempt throttling are enabled.

Automatic backups should be configured at the infrastructure level, for example with a scheduled `pg_dump` job and encrypted off-site storage. Do not commit `.env` or database backups.

The document endpoint stores metadata and a `storageKey`; connect that key to private object storage (or a protected file service) before production. The schema intentionally keeps file bytes outside PostgreSQL.
