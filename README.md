# Odyssey Travel Co – Welcome & Login

A mobile-first welcome/login screen with a small Node.js backend.

## Run it in VS Code

1. Install Node.js 18 or newer from https://nodejs.org (check with `node -v`).
2. In VS Code: **File > Open Folder...** and choose this folder.
3. Open the terminal: **Terminal > New Terminal**.
4. Install and start:

   ```bash
   npm install
   npm start
   ```
5. Open http://localhost:3000 in your browser.
   To see it as a phone, press F12, then the device toolbar icon (Ctrl+Shift+M).

For auto-restart while you edit the server, use `npm run dev`.
You can also press **F5** in VS Code to run and debug the server.

## What's inside

- `server.js` – Express API: sign up, sign in, sign out, current user, forgot password.
  Passwords are hashed with bcrypt, sessions use an httpOnly cookie, and auth routes are rate limited.
- `public/` – the screen itself (`index.html`, `styles.css`, `app.js`).
- `data/users.json` – created automatically on first sign up (a simple file store for local use).

## Good next steps

- Forgot password currently only logs the request in the terminal. Add an email service and a reset page to finish it.
- Swap the JSON file for a real database (SQLite, PostgreSQL, MongoDB) before going live.
- Set `JWT_SECRET` and `NODE_ENV=production` in your environment when you deploy, and serve over HTTPS.
