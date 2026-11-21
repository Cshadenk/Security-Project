# Secure Web Application: Detection and Mitigation of Vulnerabilities

## Overview
A simple user management web application built with Flask and SQLite.
It was first built with deliberate vulnerabilities, then secured.
A single flag, `SECURE_MODE` in `app.py`, switches between the vulnerable
version (`False`) and the secure version (`True`).

**Team members**

| Name | Responsibility |
|------|----------------|
| Shaden | Core app (register, login, dashboard, logout), SQL Injection |
| Wajd | Password storage (MD5 to bcrypt), password policy, Comments and XSS |
| Raghad | Role-based access control (RBAC), admin page |
| Aryam | HTTPS/TLS, secure session cookies, encryption |

## Features
- User registration, login, dashboard, and logout
- Session management with Back-button protection after logout
- Comments system
- Admin page restricted by role

## Vulnerabilities Covered

| # | Vulnerability | Vulnerable version | Mitigation |
|---|---------------|--------------------|------------|
| 1 | SQL Injection | Queries built by string concatenation | Parameterized queries |
| 2 | Weak Password Storage | MD5 hashing | bcrypt with salt + password policy |
| 3 | Cross-Site Scripting (XSS) | Comments rendered without sanitization | Output escaping / sanitization |
| 4 | Broken Access Control | `/admin` open to everyone | Role-based access control (RBAC) |
| 5 | Missing Encryption | HTTP, unprotected cookies | HTTPS (TLS) + secure session cookies |

## Project Structure
```
Security-Project/
├── app.py
├── database.py
├── make_admin.py
├── requirements.txt
├── templates/
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   └── admin.html
└── README.md
```

## Installation and Running

**Requirements:** Python 3.9 or higher.

```bash
git clone https://github.com/Cshadenk/Security-Project.git
cd Security-Project
python3 -m pip install -r requirements.txt
```

Generate a self-signed certificate (needed for HTTPS):
```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365
```

Run:
```bash
python3 app.py
```

Open: https://127.0.0.1:5001 (accept the browser warning, because the
certificate is self-signed).

Notes:
- The app uses port 5001 because macOS AirPlay Receiver blocks port 5000.
- `database.db`, `key.pem`, and `cert.pem` are not committed. The database is
  created automatically on first run.
- If you see `ModuleNotFoundError`, make sure you installed the dependencies
  with `python3 -m pip install -r requirements.txt`, ideally inside a virtual
  environment (`python3 -m venv venv && source venv/bin/activate`).

### Test Accounts

| Username   | Password | Role  |
| ---------- | -------- | ----- |
| admin_test | Set locally | admin |
| testuser1  | Set locally | user  |


Run make_admin.py from the project folder after registering the account.

To test the admin page:

1. Run the app and register two accounts: `admin_test` and `testuser1`.
2. Open the terminal and run:

   ```bash
   python make_admin.py admin_test
   ```

   On Mac, use `python3` instead of `python`.

3. Log in as `admin_test` to access `/admin`.
4. Log in as `testuser1` to check that regular users cannot access `/admin` in secure mode.


## How to Test the Security Features

Set `SECURE_MODE = False` in `app.py` to see each attack work, then
`SECURE_MODE = True` to see it blocked. Restart the app after changing it.

### 1. SQL Injection (Login)
- Enter `' OR '1'='1' --` as the username and any password.
- **Vulnerable:** logged in without a password.
- **Secure:** "Invalid credentials".

### 2. SQL Injection (Register)
- Register with username `hacker', 'x', 'admin') --` and any password,
  then log in as `hacker` / `x`.
- **Vulnerable:** dashboard shows Role: admin.
- **Secure:** the payload is stored as a plain username and the role is `user`.

### 3. Weak Password Storage
- Register a user, then inspect the database:
  `sqlite3 database.db "SELECT username, password FROM users;"`
- **Vulnerable:** a 32-character MD5 hash.
- **Secure:** a bcrypt hash starting with `$2b$`.
- Password policy: at least 8 characters with an uppercase letter, a lowercase
  letter, a number, and a special character. Try registering with `abc123`;
  it must be rejected, and the requirements are shown on the register page.

### 4. Cross-Site Scripting (XSS)
- Post this comment: `<script>alert('XSS')</script>`
- **Vulnerable:** an alert popup appears.
- **Secure:** the text is displayed as plain text and no script runs.

### 5. Access Control (RBAC)
- Log in as a standard user and open `/admin`.
- **Vulnerable:** the page opens.
- **Secure:** 403 Forbidden. Logged in as `admin`, the page opens.
- Opening `/admin` without logging in redirects to the login page.

### 6. Encryption and Sessions
- Check that the URL starts with `https://`.
- In browser DevTools, Application, Cookies: verify the `Secure`, `HttpOnly`,
  and `SameSite` flags on the session cookie.

### 7. Logout and Back button
- Log in, click Logout, then press the browser Back button, or open
  `/dashboard` directly.
- Expected: redirected to the login page, not the dashboard.

## Documentation
- Security report (vulnerabilities, fixes, challenges, testing table,
  access-control matrix): [https://docs.google.com/document/d/1KCoWNq6hMxWZcCtdKWle3GxE2KWICDucokF0XvRQVKs/edit?usp=sharing]

## Credits
Flask, SQLite (Python `sqlite3`), bcrypt, bleach, cryptography, OpenSSL.