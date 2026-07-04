# Break The Login
## Overview
This is a Flask based web application meant to demonstrate common authentication and session management vulnerabilities, alongside their corresponding fixes. The project is built around a simple ticketing system, where users can register, log in, and manage tickets based on their role. It exists in two versions: an intentionally vulnerable MVP, and a secured version where each vulnerability is patched and re-tested.

## Features
Demonstrates core authentication concepts such as registration, login, role based access (Analyst vs Manager), and password reset through a token flow. The project uses SQLite as the database, with all schema defined in schema.sql and accessed through database.py, while app.py handles routing and server logic. A key feature is the audit log, which records actions such as registration, login, logout, password resets, and ticket edits, including user id, action, resource, timestamp and IP address. The secured version adds password hashing with bcrypt, password complexity checks, rate limiting with account lockout, generic error messages, secure session cookies, and short lived, randomly generated password reset tokens.

## Structure
### Authentication
+ Register (email, password, role)
+ Login
+ Logout
+ Forgot password (email → token → reset)

### Tickets
+ Create a new ticket (any logged in user)
+ View own tickets (Analyst role)
+ View all tickets (Manager role)
+ Update ticket status (Manager role)
+ Search tickets by title, description, severity or status

### Audit
+ View audit logs (Manager role)

## Vulnerabilities Demonstrated (MVP → Fixed)
+ Weak password policy → Enforced complexity rules
+ Plaintext password storage → Bcrypt hashing
+ No rate limiting / brute force protection → Lockout after 5 failed attempts per hour
+ User enumeration on login → Single generic error message
+ Insecure session cookies (no HttpOnly/SameSite/Secure) → Flask sessions with secure flags and 15 minute lifetime
+ Static, reusable password reset token → Unique, time limited token via secrets.token_urlsafe
