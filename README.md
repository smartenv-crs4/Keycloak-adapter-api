# 🔐 Keycloak Adapter API for Node.js (Express)

An adapter API to seamlessly integrate **Node.js Express** applications with **Keycloak** for authentication and authorization using **OpenID Connect (OIDC)**.

This middleware provides route protection, token validation, user role management, and easy access to Keycloak-secured APIs. Ideal for securing RESTful services, microservices, and Express-based backends.

---

## 📦 Features

- 🔑 OIDC-based authentication with Keycloak
- 🧾 Access token validation (JWT)
- 🔐 Route protection via role-based access control
- 🔁 Automatic token refresh (optional)
- ⚙️ Configurable Keycloak client and realm settings
- 👤 User info extraction from token
- 🌍 CORS support and integration with frontend apps (SPA or mobile)

---

## 🚀 Installation

```bash
npm install keycloak-adapter-api
```

Or, if using Yarn:

```bash
yarn add keycloak-adapter-api
```

---

## 🛠️ Configuration

Create a file named `keycloak.json` in the root of your project with the following structure:

```json
{
  "realm": "your-realm",
  "auth-server-url": "https://your-keycloak-domain/auth",
  "ssl-required": "external",
  "resource": "your-client-id",
  "credentials": {
    "secret": "your-client-secret"
  },
  "confidential-port": 0
}
```

> You can also pass the config programmatically (see example below).

---

## 📄 Usage Example

```js
const express = require('express');
const session = require('express-session');
const Keycloak = require('keycloak-connect');

const app = express();

// Session setup (required by Keycloak middleware)
const memoryStore = new session.MemoryStore();
app.use(session({
  secret: 'some-secret',
  resave: false,
  saveUninitialized: true,
  store: memoryStore
}));

// Initialize Keycloak adapter
const keycloak = new Keycloak({ store: memoryStore });

// Apply Keycloak middleware
app.use(keycloak.middleware());

// Public route
app.get('/', (req, res) => {
  res.send('Public route: no authentication required');
});

// Protected route (any authenticated user)
app.get('/secure', keycloak.protect(), (req, res) => {
  res.send('Secure route: user is authenticated');
});

// Role-based protected route
app.get('/admin', keycloak.protect('realm:admin'), (req, res) => {
  res.send('Admin route: user has realm role "admin"');
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
```

---

## ✅ Protecting Routes

You can use the following methods to protect routes:

- `keycloak.protect()` — any authenticated user
- `keycloak.protect('role')` — users with a specific role
- `keycloak.protect('realm:role')` — users with realm-level role

---

## 📤 Get User Info

Once authenticated, user info can be accessed via the `req.kauth.grant` object:

```js
app.get('/profile', keycloak.protect(), (req, res) => {
  const token = req.kauth.grant.access_token;
  const userInfo = token.content;
  res.json(userInfo);
});
```

---

## ⚠️ Notes

- This adapter relies on `keycloak-connect` under the hood.
- Make sure Keycloak client type is set to **confidential**.
- The `keycloak.json` must match the configuration from your Keycloak admin panel.

---

## 🧪 Testing

You can use tools like **Postman** or **curl** to test the secured endpoints. Obtain a token from Keycloak and include it as a Bearer token in the Authorization header.

```bash
curl -H "Authorization: Bearer <access_token>" http://localhost:3000/secure
```

---

## 📚 Resources

- [Keycloak Documentation](https://www.keycloak.org/documentation.html)
- [keycloak-connect (npm)](https://www.npmjs.com/package/keycloak-connect)
- [OIDC Protocol Overview](https://openid.net/connect/)

---

## 📝 License

This project is licensed under the MIT License.

Copyright (c) 2025 CRS4, aromanino, gporruvecchio

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 🙋‍♂️ Contributions

Contributions, issues and feature requests are welcome!

1. Fork the project
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a pull request

---

## 👨‍💻 Maintainer

Developed and maintained by [CRS4 Microservice Core Team ([cmc.smartenv@crs4.it](mailto:cmc.smartenv@crs4.it))] – feel free to reach out for questions or suggestions.

Design and development
------
Alessandro Romanino ([a.romanino@gmail.com](mailto:a.romanino@gmail.com))<br>
Guido Porruvecchio ([guido.porruvecchio@gmail.com](mailto:guido.porruvecchio@gmail.com))


