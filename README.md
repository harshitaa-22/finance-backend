# Finance Backend

A simple backend for tracking income and expenses, built with Node.js, Express v5, and SQLite.

## How to run

```bash
npm install
```

Create a `.env` file in the root folder:

```
JWT_SECRET=any-secret-string-you-want
```

Then start the server:

```bash
npm start
```

It runs on `http://localhost:3000`. For development with auto-reload, use `npm run dev`.

The first user to sign up automatically becomes the admin. Everyone after that is a viewer. So just sign up once, log in, and you have full access to all endpoints.

## What it does

- Signup and login with JWT authentication
- Three roles: admin, analyst, viewer — each with different access levels
- CRUD for financial records (income/expense with category, date, notes)
- Dashboard that shows total income, total expenses, and balance
- Analytics endpoint with category-wise breakdown and monthly trends
- Admin can manage users (delete users, change roles)

## API overview

Public routes: `POST /signup`, `POST /login`

All other routes need a `Authorization: Bearer <token>` header.

- `GET /profile` — your profile info
- `GET /dashboard` — income/expense/balance summary
- `GET /analytics` — category breakdown, monthly trends, recent activity (analyst and admin only)
- `POST /records` — add a record (analyst and admin only)
- `GET /records` — list your records
- `PUT /records/:id` — update your record
- `DELETE /records/:id` — delete your record
- `PATCH /admin/update-role/:id` — change a user's role (admin only)
- `DELETE /admin/delete-user/:id` — delete a user (admin only)

## Postman

There's a Postman collection included (`finance-backend.postman_collection.json`). Import it, run Login first — it auto-saves the token so the other requests just work.

## Tech used

- Express v5
- SQLite3 (auto-creates `finance.db` on first run)
- bcryptjs for password hashing
- jsonwebtoken for auth
- dotenv for environment config

## Some design choices I made

- Kept everything in a single `index.js` since the project is small enough. Would split into routes/controllers/middleware for anything bigger.
- Used SQLite so there's no database setup needed — just run and it works.
- Tokens expire after 1 hour.
- Users can only access their own records. Even admins operate on their own records through the normal endpoints.
- Deleting a user also deletes their records so there's no orphaned data.
- Admins can't delete themselves or change their own role to avoid accidental lockout.

## Things I'd improve with more time

- Password strength validation (minimum length, complexity)
- Email format validation
- Pagination on the records endpoint
- Filtering records by date, category, or type
- Rate limiting on login/signup to prevent brute force
- Security headers using helmet
- Better error handling with a global error middleware
- Request logging with morgan
- Graceful shutdown handling
