# FKAMS Graduates Management API

## Overview
This document describes the new graduates tracking and promotions management endpoints added to the FKAMS backend in migration 014.

## Database Schema Changes

### New Table: `student_promotions`
Tracks student promotions, retentions, and graduations for each academic year.

**Columns:**
- `id` INT UNSIGNED PRIMARY KEY AUTO_INCREMENT
- `student_id` INT UNSIGNED - Foreign key to `students`
- `academic_year_id` INT UNSIGNED - Foreign key to `academic_years`
- `from_level` VARCHAR(40) - Starting class/level
- `to_level` VARCHAR(40) NULL - Destination level (NULL for graduates)
- `action` ENUM('promoted', 'retained', 'graduated') - Promotion action
- `promoted_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
- `promotion_notes` TEXT NULL - Notes about the promotion
- `created_by` INT UNSIGNED - User who recorded the promotion
- **Unique Constraint:** (student_id, academic_year_id)

### Altered Table: `students`
Added two new columns:
- `graduation_date` DATE NULL - Date student graduated
- `graduated_cohort` VARCHAR(100) NULL - Academic year name when graduated

### New View: `v_graduates`
Provides convenient access to graduate data with related academic year and user information.

## API Endpoints

### GET /api/academic-years/graduates
List graduates with filtering and grouping by academic year and trade.

**Authorization:** admin, dos, accountant

**Query Parameters:**
- `year_id` (optional) - Filter by academic year ID
- `trade` (optional) - Filter by trade/level name
- `search` (optional) - Full-text search on student name or admission number
- `limit` (optional, default: 1000, max: 5000) - Maximum results

**Response:**
```json
{
  "total": 156,
  "groups": [
    {
      "year_id": 5,
      "year_name": "2023-2024",
      "start_date": "2023-09-01",
      "end_date": "2024-08-31",
      "total": 78,
      "trades": [
        {
          "trade": "Software Development",
          "count": 42,
          "students": [
            {
              "promotion_id": 123,
              "id": 45,
              "user_id": 890,
              "full_name": "John Doe",
              "first_name": "John",
              "last_name": "Doe",
              "reg_number": "ADM-2023-001",
              "photo_key": "photo-url-or-key",
              "from_level": "S6B",
              "final_level": "Software Development",
              "trade": "Software Development",
              "academic_year": "2023-2024",
              "academic_year_name": "2023-2024",
              "start_date": "2023-09-01",
              "end_date": "2024-08-31",
              "graduated_at": "2024-06-15",
              "promotion_notes": "2023-2024",
              "contact_email": "john@example.com",
              "contact_phone": "+250788123456"
            }
            // ... more students
          ]
        }
      ]
    }
  ],
  "filters": {
    "years": [
      { "id": 5, "name": "2023-2024" },
      { "id": 4, "name": "2022-2023" }
    ],
    "trades": [
      "Software Development",
      "Building and Construction",
      "Automobile Technology"
    ]
  }
}
```

**Example Requests:**
```bash
# Get all graduates
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:4000/api/academic-years/graduates

# Get graduates from 2023-2024 in Software Development
curl -H "Authorization: Bearer TOKEN" \
  "http://localhost:4000/api/academic-years/graduates?year_id=5&trade=Software%20Development"

# Search for specific graduate
curl -H "Authorization: Bearer TOKEN" \
  "http://localhost:4000/api/academic-years/graduates?search=John%20Doe"
```

---

### POST /api/academic-years/:id/close
Close an academic year, recording promotion decisions and optionally creating the next year.

**Authorization:** admin, dos

**Request Body:**
```json
{
  "overrides": [
    {
      "student_id": 45,
      "action": "graduated",
      "to_level": null
    },
    {
      "student_id": 46,
      "action": "promoted",
      "to_level": "S5B"
    },
    {
      "student_id": 47,
      "action": "retained",
      "to_level": "S6A"
    }
  ],
  "next_year": {
    "name": "2024-2025",
    "start_date": "2024-09-01",
    "end_date": "2025-08-31",
    "set_current": true,
    "terms": [
      {
        "name": "Term 1",
        "startDate": "2024-09-01",
        "endDate": "2024-11-30"
      },
      {
        "name": "Term 2",
        "startDate": "2024-12-01",
        "endDate": "2025-03-31"
      },
      {
        "name": "Term 3",
        "startDate": "2025-04-01",
        "endDate": "2025-08-31"
      }
    ]
  }
}
```

**Response:**
```json
{
  "promoted": 45,
  "graduated": 28,
  "retained": 5,
  "message": "Academic year closed successfully."
}
```

**Details:**
- Creates `student_promotions` records for each student
- Updates student status to 'graduated' with graduation_date and graduated_cohort
- Updates student class for promoted students
- Closes the academic year (sets status to 'closed', is_current to FALSE)
- Optionally creates the next academic year with terms

**Notes:**
- If `overrides` is empty, all students are retained by default
- For graduated students, `to_level` should be NULL
- For promoted students, provide the destination class name in `to_level`
- For retained students, provide the same class name in `to_level`

---

## Implementation Details

### Migration 014: graduates_promotions.sql
Automatically applied on server startup via `/migrations.js`.

**What it creates:**
1. `student_promotions` table with proper indexes and foreign keys
2. New columns on `students` table
3. `v_graduates` view for querying graduates
4. Proper cascading deletes and transaction support

### Frontend Integration

The `GraduatesPage.jsx` component uses the new endpoints:

```jsx
// Load graduates with filtering
const params = new URLSearchParams();
if (yearId) params.set('year_id', yearId);
if (trade) params.set('trade', trade);
if (search) params.set('search', search);
const response = await api.get(`/academic-years/graduates?${params}`);

// Display graduates grouped by year and trade
response.data.groups.forEach(group => {
  console.log(`${group.year_name}: ${group.total} graduates`);
  group.trades.forEach(t => {
    console.log(`  ${t.trade}: ${t.count} graduates`);
  });
});
```

---

## Workflow Example

### Closing an Academic Year (End-of-Year Process)

1. **Admin/DOS views year preview** → GET `/api/academic-years/:id/preview-close`
2. **System calculates promotion rules** (e.g., auto-promote pass, retain fail)
3. **Admin reviews and adjusts** (override specific student decisions in UI)
4. **Admin submits close request** → POST `/api/academic-years/:id/close`
   - Backend creates all `student_promotions` records
   - Updates student statuses and classes
   - Closes the year
   - Creates next year if provided
5. **Graduates become visible** → GET `/api/academic-years/graduates`

### Viewing Graduates

1. **Filter by year** → GET `/api/academic-years/graduates?year_id=5`
2. **Filter by trade** → GET `/api/academic-years/graduates?year_id=5&trade=Software%20Development`
3. **Search by name** → GET `/api/academic-years/graduates?search=John`
4. **Print/Export** → Frontend builds HTML and triggers browser print

---

## Error Handling

### 400 Bad Request
- Invalid `year_id` or `trade` parameter
- Missing required fields in close request

### 403 Forbidden
- User role is not admin, dos, or accountant

### 404 Not Found
- Academic year not found
- Student in overrides not found

### 503 Service Unavailable
- Database transaction failed during close

---

## Performance Notes

- Results are limited to 5000 students max
- Index on `(student_id, academic_year_id)` ensures quick promotion lookups
- Views are materialized by PostgreSQL for fast queries
- Use pagination in frontend if showing more than 1000 records at once

---

## See Also

- [Migration 014](./migrations/014_graduates_promotions.sql) - Database schema
- [GraduatesPage.jsx](../frontend/src/pages/GraduatesPage.jsx) - Frontend implementation
- [AcademicYearPage.jsx](../frontend/src/pages/AcademicYearPage.jsx) - Year management UI
