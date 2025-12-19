# Simple Express Authentication App

A very simple web application built with Node.js, Express, EJS, and SQLite that allows users to:

- Sign up with a username and password
- Log in and log out
- View a profile page
- Delete their account

Passwords are hashed using `bcrypt`, and session management is handled with `express-session`.

---

## Features

- **User authentication** (signup, login, logout)
- **Account deletion**
- **Flash messages** for success/error notifications
- **SQLite database** for storing users
- **Security Features** Implementation of `CSRF` and `JWT`

---
## Prerequisites
- Node.js (v18+ recommended)
- npm
---

## Installation

1. Clone the repository

```bash
git clone https://github.com/JO-00/Mini-Local-CTF
cd Mini-Local-CTF
```
2. Install dependencies

First make sure you have npm installed, then run the following commands
```bash
npm install
```
3. Start the server
```bash
npm start
```
4. Open your browser at **http://localhost:3000**

> Expect that the SQLite database file `users.db` will be created automatically when the server first runs.

