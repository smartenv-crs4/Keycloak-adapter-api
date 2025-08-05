# 🔐 Keycloak Adapter API for Node.js (Express)

An adapter API to seamlessly integrate **Node.js Express** applications with **Keycloak** for authentication and authorization using **OpenID Connect (OIDC)**.

This middleware provides route protection, token validation, user role management, and easy access to Keycloak-secured APIs. Ideal for securing RESTful services, microservices, and Express-based backends.
it is based on 'keycloak-connect', 'express-session' and '@keycloak/keycloak-admin-client'
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

## 🛠️ Get Keycloak Configuration

Copy or Download from keycloak admin page your client configuration `keycloak.json` by visiting 
the Keycloak Admin Console → clients (left sidebar) → choose your client → Installation → Format Option → Keycloak OIDC JSON → Download

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

---

## 📄 Usage Example

```js
const express = require('express');
const keycloackAdapter = require('keycloak-adapter-api');

const app = express();


// Configure and Initialize Keycloak adapter
await keycloackAdapter.configure(app,{
        "realm": "Realm-Project",
        "auth-server-url": "https://YourKeycloakUrl:30040/",
        "ssl-required": "external",
        "resource": "keycloackclientName",
        "credentials": {
            "secret": "aaaaaaaaaa"
        },
        "confidential-port": 0
    },
    {
        session:{
            secret: 'mySecretForSession',
        }
    });


// Public route
app.get('/', (req, res) => {
  res.send('Public route: no authentication required');
});

/* Protected routes (any authenticated user)
@deprecated Use the `configure` function with `await keycloakAdapter.configure(...)`,
then define your resources as you normally would in Express:

    await keycloakAdapter.configure(...);
    app.get('/my-route', handler);

Alternatively, if you prefer to define your resources inside a container after configuration,
you can use the `then` syntax:

    keycloakAdapter.configure(...).then(() => {
        // Define your routes here
        app.get('/my-route', handler);
    });
    
*/
keycloackAdapter.underKeycloakProtection(function(){
    // This function is deprecated and will be removed in future versions. 
    // It is retained only for backward compatibility with older versions
});

// Example of login with keycloackAdapter.login function
// After login redirect to "/home" 
app.get('/signIn', (req, res) => {
    console.log("Your Custom Code");
    keycloackAdapter.login(req,res,"/home")

});

// Example of login with keycloackAdapter.loginMiddleware middleware
// After login redirect to "/home" 
app.get('/loginMiddleware', keycloackAdapter.loginMiddleware("/home") ,(req, res) => {
    // Response handled by middleware, this section will never be reached.
});

// Example of logout with keycloackAdapter.logout function
// After login redirect to "http://localhost:3001/home" 
app.get('/logout', (req, res) => {
    console.log("Your Custom Code");
    keycloackAdapter.logout(req,res,"http://localhost:3001/home");
});

// Example of logout with keycloackAdapter.logoutMiddleware middleware
// After login redirect to "http://localhost:3001/home"
app.get('/logoutMiddle', keycloackAdapter.logoutMiddleware("http://redirctUrl"), (req, res) => {
    // Response handled by middleware, this section will never be reached.
});


// Example of protection with keycloackAdapter.protectMiddleware middleware
// Access is allowed only for authenticated users
app.get('/private', keycloackAdapter.protectMiddleware(), (req, res) => {
    console.log("Your Custom Code");
    console.log( req.session);
    res.redirect('/auth');
});

// Example of protection with keycloackAdapter.protectMiddleware middleware
// whith a static client role validation string
// Access is allowed only for authenticated admin users
app.get('/privateStaticClientRole', keycloackAdapter.protectMiddleware("admin"), (req, res) => {
    // "Your Custom Code"
    res.send("Is its admin.");
});

// Example of protection with keycloackAdapter.protectMiddleware middleware
// whith a static realm role validation string
// Access is allowed only for authenticated realm admin users
app.get('/privateStaticRealmRole', keycloackAdapter.protectMiddleware("realm:admin"), (req, res) => {
    // "Your Custom Code"
    res.send("Is its admin realm:admin.");
});

// Example of protection with keycloackAdapter.protectMiddleware middleware
// whith a static other client role validation string
// Access is allowed only for authenticated otherClient admin users
app.get('/privateStaticRealmRole', keycloackAdapter.protectMiddleware("otherClient:admin"), (req, res) => {
    // "Your Custom Code"
    res.send("Is its admin otherClient:admin.");
});

// Example of protection with keycloackAdapter.protectMiddleware middleware
// whith a control function tmpFunction
// Access is allowed only for authenticated admin users
let tmpFunction=function (token, req) {
    return token.hasRole('admin');
}
app.get('/isAdmin', keycloackAdapter.protectMiddleware(tmpFunction), (req, res) => {
    // "Your Custom Code"
    res.send("Is its admin tmpFunction.");
});


// Example of protection with keycloackAdapter.customProtectMiddleware middleware
// whith a control function tmpFunctionString
// Access is allowed only for authenticated users with role defined by tmpFunctionString
let tmpFunctionString=function (req,res) {
    let id=req.params.id
    // Control String by url param Id 
    return (`${id}`);
}
app.get('/:id/isAdmin', keycloackAdapter.customProtectMiddleware(tmpFunctionString), (req, res) => {
    // "Your Custom Code"
    res.send("Is its admin tmpFunctionString.");
});


// Example of protection with keycloackAdapter.encodeTokenRole middleware
// Encode the token and add it to req.encodedTokenRole
// Use req.encodedTokenRole.hasRole("role") to check whether the token has that role or not
app.get('/encodeToken', keycloackAdapter.encodeTokenRole(), (req, res) => {
    if(req.encodedTokenRole.hasRole('realm:admin'))
        res.send("Is its a realm admin");
    else
        res.send("Is its'n a realm admin");

});

// This section provides examples of how to protect resources based on permissions
// rather than roles.

// Example of protection with keycloackAdapter.enforcerMiddleware middleware
// whith a static control string
// Access is allowed only for users with 'ui-admin-resource' permission defined 
// in keycloak
app.get('/adminResource', keycloackAdapter.enforcerMiddleware('ui-admin-resource'), (req, res) => {
    // If this section is reached, the user has the required privileges; 
    // otherwise, the middleware responds with a 403 Access Denied.
    res.send('You are an authorized ui-admin-resource User');
});

// Example of protection with keycloackAdapter.enforcerMiddleware middleware
// whith a control function tmpFunctionEnforceValidation
// Access is allowed only for users with 'ui-admin-resource' or
// ui-viewer-resource permission defined in keycloak
let tmpFunctionEnforceValidation=function (token,req,callback) {
    // Check permission using token.hasPermission, which performs the verification
    // and responds with a callback that returns true if the permission is valid, 
    // and false otherwise.
    if(token.hasPermission('ui-admin-resource',function(permission){
        if(permission) callback(true);
        else if(token.hasPermission('ui-viewer-resource',function(permission){
            if(permission) callback(true);
            else callback(false);
        }));
    }));
}
app.get('/adminOrViewerResorce', keycloackAdapter.enforcerMiddleware(tmpFunctionEnforceValidation), (req, res) => {
    // If this section is reached, the user has the required privileges 
    // driven by tmpFunctionEnforceValidation; otherwise, the middleware responds
    // with a 403 Access Denied.
    res.send('You are an authorized User');
});


// Example of protection with keycloackAdapter.customEnforcerMiddleware middleware
// whith a control function tmpFunctionEnforce that define the control string
// Access is allowed only for users with a url params ':permission' permission defined 
// in keycloak
let tmpFunctionEnforce=function (req,res) {
    // Permission that depends on a URL parameter.
    return(req.params.permission);
}
app.get('/urlParameterPermission/:permission', keycloackAdapter.customEnforcerMiddleware(tmpFunctionEnforce), (req, res) => {
    res.send(`You are an authorized User with ${req.params.permission} permission`);
});

// Example of protection with keycloackAdapter.encodeTokenPermission middleware
// Encode the token permission and add it to req.encodedTokenPremission
// Use req.encodedTokenPremission.hasPermission("permission") to check whether
// the token has that permission or not
app.get('/encodeTokenPermission', keycloackAdapter.encodeTokenPermission(), (req, res) => {
    // Check permission using token.hasPermission, which performs the verification
    // and responds with a callback that returns true if the permission is valid, 
    // and false otherwise.
    req.encodedTokenPremission.hasPermission('ui-admin-resource', function(permission){
        if(permission)
            res.send('You are an authorized User by ui-admin-resource permission');
        else res.status(403).send("access Denied");
    });
});



// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
```

---

## 🧩 Configuration

In your Express application:

```js
import keycloakAdapter from 'keycloak-adapter-api';

// Configure and Initialize Keycloak adapter
keycloackAdapter.configure(app,{
        "realm": "Realm-Project",
        "auth-server-url": "https://YourKeycloakUrl:30040/",
        "ssl-required": "external",
        "resource": "keycloackclientName",
        "credentials": {
            "secret": "aaaaaaaaaa"
        },
        "confidential-port": 0
    },
    {
        session:{
            secret: 'mySecretForSession',
        }
    })
```

keycloackAdapter.configure is a configuration function for the Keycloak 
adapter in an Express application.  
It must be called at app startup, before defining any protected routes.
It is an async function and returns a promise

Parameters:
- app: Express application instance (e.g., const app = express();)
-   keyCloakConfig: JSON object containing the Keycloak client configuration.
     This can be obtained from the Keycloak admin console:
     Clients → [client name] → Installation → "Keycloak OIDC JSON" → Download
      Example:
    {
    "realm": "realm-name",
    "auth-server-url": "https://keycloak.example.com/",
    "ssl-required": "external",
    "resource": "client-name",
    "credentials": { "secret": "secret-code" },
    "confidential-port": 0
    }
- keyCloakOptions: advanced configuration options for the adapter.
  Main supported options:
    - session: Express session configuration (as in express-session)
    - scope: authentication scopes (e.g., 'openid profile email offline_access')
      Note: to use offline_access, the client must have the option enabled and
      the user must have the offline_access role.
    - idpHint: to suggest an identity provider to Keycloak during login
    - cookies: to enable cookie handling
    - realmUrl: to override the realm URL
- adminClientCredentials: [Optional] Advanced configuration for setting up the realm-admin user or client,
  which will be used as the administrator to manage Keycloak via API.
  This is required in order to use the administrative functions exposed by this library.
  If this parameter is not provided, it will not be possible to use the administrative functions of Keycloak
  exposed by this adapter. In fact, exports.kcAdminClient will be null, so any attempt to call
  keycloakAdapter.kcAdminClient will result in a runtime error due to access on an undefined object
  Main supported options:
    - realmName: [Optional] A String that specifies the realm to authenticate against, if different from the "keyCloakConfig.realm" parameter.
      If you intend to use Keycloak administrator credentials, this should be set to 'master'.
    - scope: [Optional] A string that specifies The OAuth2 scope requested during authentication (optional).
      Typically, not required for administrative clients. example:openid profile
    - requestOptions: [Optional] JSON parameters to configure HTTP requests (such as custom headers, timeouts, etc.).
      It is compatible with the Fetch API standard. Fetch request options
      https://developer.mozilla.org/en-US/docs/Web/API/fetch#options
    - username: [Optional] string username. Required when using the password grant type.
    - password: [Optional] string password. Required when using the password grant type.
    - grantType: The OAuth2 grant type used for authentication.
      Possible values: 'password', 'client_credentials', 'refresh_token', etc.
    - clientId: string containing the client ID configured in Keycloak. Required for all grant types.
    - clientSecret: [Optional] string containing the client secret of the client. Required for client_credentials or confidential clients.
    - totp: string for Time-based One-Time Password (TOTP) for multifactor authentication (MFA), if enabled for the user.
    - offlineToken: [Optional] boolean value. If true, requests an offline token (used for long-lived refresh tokens). Default is false.
    - refreshToken: [Optional] string containing a valid refresh token to request a new access token when using the refresh_token grant type.
---

## 🔧 Available Middlewares

### `underKeycloakProtection(callback)`
@deprecated Use the `configure` Method with `await keycloakAdapter.configure(...)`,
then define your resources as you normally would in Express:
```js
    await keycloakAdapter.configure(config_Parameters);
    // all your routes    
    app.get('/my-route', handler);
```

Alternatively, if you prefer to define your resources inside a container after configuration,
you can use the `then` syntax:
```js
    keycloakAdapter.configure(configParameters).then(() => {
        // Define all your routes here
        app.get('/my-route', handler);
    });
```

This Method is deprecated and will be removed in future versions.

Method to define Express routes that must be protected by Keycloak.

This method must be called **after** Keycloak has been configured with `configure()`.
The routes declared inside the provided callback will be protected and will have access
to authentication/authorization features managed by Keycloak.

📌 Public (unprotected) routes should be declared **before** calling this method.

@param {Function} callback - A function that defines all routes to be protected.
It must contain exclusively routes requiring authentication.

✅ Usage example:
```js
// Public route not protected by Keycloak
app.get('/public', (req, res) => {
res.send('Public content');
});

// Section of routes protected by Keycloak
keycloakAdapter.underKeycloakProtection(() => {

    // This function is deprecated and will be removed in future versions. 
    // It is retained only for backward compatibility with older versions
    
    // Route protected by authentication
    app.get('/confidential', keycloakAdapter.protectMiddleware(), (req, res) => {
        res.send('Confidential content visible only to authenticated users');
    });

    // Route with forced login: handled directly by middleware
    app.get('/loginMiddleware', keycloakAdapter.loginMiddleware("/home"), (req, res) => {
        // This response will never be sent because the middleware handles the 
        // request directly
    });
});
```

### `protectMiddleware([conditions])`
Middleware to protect Express routes based on authentication and, optionally,
authorization via Keycloak roles.

Allows restricting access to a resource only to authenticated users or
to those possessing specific roles in the realm or in a Keycloak client.

@param {string|function} [conditions]
- If a string, specifies one or more required roles, using the syntax:
    - 'role'              → client role in the configured client (e.g., 'admin')
    - 'clientid:role'     → client role of a specific client (e.g., 'myclient:editor')
    - 'realm:role'        → realm role (e.g., 'realm:superuser')
  - If a function, receives (token, req) and must return true or false synchronously.
    This function enables custom authorization logic.
    - The `token` object passed to the authorization function exposes methods such as:
      - token.hasRole('admin')               // client role in configured client
      - token.hasRole('realm:superuser')     // realm role
      - token.hasRole('my-client:editor')    // client role of a specific client
      - token.hasResourceRole('editor', 'my-client-id') // equivalent to hasRole('my-client:editor')

    The authorization function must be synchronous and return true (allow access) or false (deny access).

@returns {Function} Express middleware to protect the route.

✅ Usage example:
```js

// Authentication only, no role check
app.get('/admin', keycloakAdapter.protectMiddleware(), (req, res) => {
    res.send('Only authenticated users can see this resource.');
});

// Check on client role of configured client (e.g., 'admin')
app.get('/admin', keycloakAdapter.protectMiddleware('admin'), (req, res) => {
    res.send('Only users with the admin client role can access.');
});

// Check on role of a specific client (e.g., client 'clientid', role 'admin')
app.get('/admin', keycloakAdapter.protectMiddleware('clientid:admin'), (req, res) => {
    res.send('Only users with admin role in client "clientid" can access.');
});

// Check on realm role (e.g., 'superuser' role at realm level)
app.get('/admin', keycloakAdapter.protectMiddleware('realm:superuser'), (req, res) => {
    res.send('Only users with realm superuser role can access.');
});

// Custom synchronous authorization function
app.get('/custom', keycloakAdapter.protectMiddleware((token, req) => {
    // Allow only if user has realm role 'editor'
    // and the request has a specific custom header
    return token.hasRealmRole('editor') && req.headers['x-custom-header'] === 'OK';
}), (req, res) => {
    res.send('Access granted by custom authorization function.');
});

```


### `customProtectMiddleware(fn)`
Middleware similar to `protectMiddleware` but with dynamic role checking via a function.

Unlike `protectMiddleware`, which accepts a string expressing the role or a control function
that works on the token, this middleware accepts a function that receives the Express
request and response objects `req` and `res` and must return a string representing the role control string.

This is useful for parametric resources where the role control string must be dynamically generated based on the request,
for example, based on URL parameters or query strings.

Note: this function **does not** access or parse the token, nor performs any checks other than the role,
so it cannot be used for complex logic depending on request properties other than the role
(e.g., client IP, custom headers, etc.).
The function's sole task is to generate the role control string.

--- Parameters ---

@param {function} customFunction - function that receives (req, res) and returns a string
with the role control string to pass to Keycloak.

✅ Usage example:
```js

app.get('/custom/:id', keycloakAdapter.customProtectMiddleware((req) => {
    // Dynamically builds the client role based on URL parameter 'id'
    return `clientRole${req.params.id}`;
}), (req, res) => {
    res.send(`Access granted to users with role 'clientRole${req.params.id}'`);
});
```


### `enforcerMiddleware(conditions, options)`
`enforcerMiddleware` is a middleware to enable permission checks
based on resources and policies defined in Keycloak Authorization Services (UMA 2.0-based).

Unlike `protectMiddleware` and similar, which only verify authentication or roles,
`enforcerMiddleware` allows checking if the user has permission to access
a specific protected resource through flexible and dynamic policies.

Useful in contexts where resources are registered in Keycloak (such as documents, instances, dynamic entities) and
protected by flexible policies.

--- Parameters ---

@param {string|function} conditions
- string containing the name of the resource or permission to check
- custom check function with signature:
  function(token, req, callback)
    - token: decoded Keycloak token
    - req: Express request
    - callback(boolean): invoke with true if authorized, false otherwise

@param {object} [options] (optional)
- response_mode: 'permissions' (default) or 'token'
- claims: object with claim info for dynamic policies (e.g. owner id matching)
- resource_server_id: resource client id (default: current client)

--- How it works ---
- If conditions is a function, it is used for custom checks with callback.
- If conditions is a string, `keycloak.enforcer(conditions, options)` is used for the check.

--- response_mode modes ---
1) 'permissions' (default)
    - Keycloak returns the list of granted permissions (no new token)
    - Permissions available in `req.permissions`

2) 'token'
    - Keycloak issues a new access token containing the granted permissions
    - Permissions available in `req.kauth.grant.access_token.content.authorization.permissions`
    - Useful for apps with sessions and decision caching

--- Keycloak requirements ---

The client must have:
- Authorization Enabled = ON
- Policy Enforcement Mode = Enforcing
- Add permissions to access token = ON

You must also configure in Keycloak:
- Resources
- Policies (e.g., role, owner, JS script)
- Permissions (associate policies to resources)

✅ Usage example:
```js

// Check with static string
app.get('/onlyAdminroute', keycloakAdapter.enforcerMiddleware('ui-admin-resource'), (req, res) => {
    res.send('You are an authorized admin for this resource');
});

// Check with custom function (async with callback)
app.get('/onlyAdminrouteByfunction', keycloakAdapter.enforcerMiddleware(function(token, req, callback) {
    token.hasPermission('ui-admin-resource', function(permission) {
        if (permission) callback(true);
        else {
            token.hasPermission('ui-viewer-resource', function(permission) {
                callback(permission ? true : false);
            });
        }
    });
}), (req, res) => {
    res.send('You are an authorized admin or viewer (custom check)');
});
```

### `customEnforcerMiddleware(fn, options)`
`customEnforcerMiddleware` is a middleware for permission checks based on resources and policies
defined in Keycloak Authorization Services (UMA 2.0), using dynamic permission strings.

This middleware is similar to `enforcerMiddleware`, but takes a function
`customFunction(req, res)` as a parameter, which must dynamically return
the permission/resource string to be checked.

--- Parameters ---

@param {function} customFunction
Function that receives `req` and `res` and returns the control string for Keycloak.
Example:
```js
function customFunction(req, res) {
    // Your function logic
    return req.params.permission;
}
```

@param {object} [options] (optional)
Additional options passed to `keycloak.enforcer()`, including:
    - response_mode: 'permissions' (default) or 'token'
    - claims: object with claim info for dynamic policies (e.g., owner ID)
    - resource_server_id: string representing the resource client ID (default: current client)

--- response_mode options ---
1) 'permissions' (default)
    - The server returns only the list of granted permissions (no new token)
    - Permissions available in `req.permissions`

2) 'token'
    - The server issues a new access token with granted permissions
    - Permissions available in `req.kauth.grant.access_token.content.authorization.permissions`
    - Useful for decision caching, session handling, automatic token refresh

--- Keycloak Requirements ---

The client must be configured with:
- Authorization Enabled = ON
- Policy Enforcement Mode = Enforcing
- Add permissions to access token = ON

You must also have created:
- Resources
- Policies (e.g., role, owner, JS rules)
- Permissions (linking policies to resources)

✅ Usage example:
```js

const tmpFunctionEnforce = function(req, res) {
    return req.params.permission; // dynamic permission from URL parameter
};

app.get('/onlyAdminrouteByfunction/:permission', keycloakAdapter.customEnforcerMiddleware(tmpFunctionEnforce), (req, res) => {
    res.send('You are an authorized user with dynamic permission: ' + req.params.permission);
});

```

### `encodeTokenRole()`
`encodeTokenRole` is a middleware that decodes the Keycloak token and adds it
to the Express request as `req.encodedTokenRole`.

Unlike `protectMiddleware` or `customProtectMiddleware`, this middleware
does NOT perform any role or authentication checks, but simply extracts
and makes the decoded token available within the route handler function.

It is especially useful when you want to perform custom logic based on roles
or other information contained in the token directly in the route handler,
for example showing different content based on role.

--- Contents of `req.encodedTokenRole` ---

Represents the decoded Keycloak token and exposes several useful methods such as:
- token.hasRole('admin')             // true/false if it has client role "admin"
- token.hasRole('realm:superuser')   // true/false if it has realm role "superuser"
- token.hasRole('my-client:editor')  // true/false if it has client role "editor" for client "my-client"
- token.hasResourceRole('editor', 'my-client-id') // identical to hasRole('my-client:editor')

✅ Usage example:
```js

app.get('/encodeToken', keycloakAdapter.encodeTokenRole(), (req, res) => {
    if (req.encodedTokenRole.hasRole('realm:admin')) {
        res.send("User with admin (realm) role in encodeToken");
    } else {
        res.send("Regular user in encodeToken");
    }
});

```

### `encodeTokenPermission()`
`encodeTokenPermission` ia s Middleware whose sole purpose is to decode the access token present in the request
and add to the `req` object a property called `encodedTokenPermission` containing the token's permissions.

Unlike `enforcerMiddleware` and `customEnforcerMiddleware`, it **does not perform any access**
or authorization checks, but exposes a useful method (`hasPermission`) for checking permissions
within the route handler.

It is particularly useful when:
- you want to **customize the response** based on the user's permissions (e.g., show a different page),
- you want to **manually handle access** or perform custom checks on multiple permissions,
- you do not want to block access upfront but decide dynamically within the route handler.

--- Additions to `req` ---

After applying the middleware, `req` contains:
- @property {Object} req.encodedTokenPermission
An object exposing the method:
    - hasPermission(permission: string, callback: function(boolean))
      Checks whether the token contains the specified permission.
      The callback receives `true` if the permission is present, `false` otherwise.

✅ Usage example:
```js

app.get('/encodeTokenPermission',
    keycloakAdapter.encodeTokenPermission(),
    (req, res) => {
        req.encodedTokenPermission.hasPermission('ui-admin-resource', function(perm) {
            if (perm)
                res.send('You are an authorized admin user by function permission parameters');
            else
                res.status(403).send('Access Denied by encodeTokenPermission');
        });
    });

```

### `loginMiddleware(redirectTo)`
`loginMiddleware` is a Middleware used to **force user authentication** via Keycloak.

It is particularly useful when you want to: 
- ensure the user is authenticated,
- redirect the user to a specific page after login or when access is denied,
- integrate automatic login flows on routes that don’t require direct authorization,
    but where login should still be enforced (e.g., profile page, personal area, etc.).

--- Behavior ---
1. If the user is **not authenticated**, Keycloak redirects them to the login flow.
2. If authentication fails or is denied, the user is redirected according to Keycloak's configured settings.
3. If authentication is successful, the user is redirected to 'redirectTo' (usually `/home`, `/dashboard`, etc.).

--- Parameters ---

@param {string} redirectTo - URL to redirect the user to after login.

--- Warning ---

The route handler callback is **never executed**, because the middleware will respond earlier
with a redirect or block the request.

✅ Usage example:
```js

app.get('/loginMiddleware', keycloakAdapter.loginMiddleware("/home"), (req, res) => {
        // This section is never reached
        res.send("If you see this message, something went wrong.");
});

```


### `logoutMiddleware(redirectTo)`
`logoutMiddleware` Middleware is used to **force user logout**, removing the local session
and redirecting the user to Keycloak's logout endpoint according to its configuration.

It is useful when:
- You want to completely log out the user,
- You want to **terminate the session on Keycloak** (not just locally),
- You want to redirect the user to a public page, such as a homepage, after logout.

--- Behavior ---
1. Retrieves the `id_token` of the authenticated user.
2. Constructs the Keycloak logout URL including the token and the redirect URL.
3. **Destroys the local Express session** (e.g., cookies, user data).
4. Redirects the user to the Keycloak logout URL, which in turn redirects to the provided URL.

--- Parameters ---

@param {string} redirectTo - URL to which the user will be redirected after complete logout.

✅ Usage example:
```js

app.get('/logoutMiddleware', keycloakAdapter.logoutMiddleware("http://localhost:3001/home"),  (req, res) => {
        // This section is never reached
        // The middleware handles logout and redirection automatically
    });

```

--- Note ---
- The middleware **never executes the route callback**, as it fully handles the response.
- The `redirectTo` parameter must match a **valid redirect URI** configured in Keycloak for the client.

--- Requirements ---
- The Keycloak client must have properly configured `Valid Redirect URIs`.
- The Express session must be active (e.g., `express-session` properly initialized).


## 🔧 Available Functions

### `login(req, res, redirectTo)`
`login` Function not a middleware, but a **classic synchronous function** that forces user authentication
via Keycloak and, if the user is not authenticated, redirects them to the login page.
After successful login, the user is redirected to the URL specified in the `redirectTo` parameter.

--- Differences from `loginMiddleware` ---
- `loginMiddleware` handles everything automatically **before** the route handler function.
- `login` instead is a function **that can be manually called inside the route handler**,
  offering **greater control** over when and how login is enforced.

--- Parameters ---

- @param {Object} req - Express `Request` object
- @param {Object} res - Express `Response` object
- @param {string} redirectTo - URL to redirect the user to after successful login

--- Behavior ---
1. Attempts to protect the request using `keycloak.protect()`.
2. If the user **is authenticated**, it performs `res.redirect(redirectTo)`.
3. If **not authenticated**, Keycloak automatically handles redirection to the login page.

✅ Usage example:
```js

app.get('/login', (req, res) => {
    // Your route logic
    // ...
    // Force authentication if necessary
    keycloakAdapter.login(req, res, "/home");
});

```

--- Notes ---
- The function can be called **within an Express route**, allowing for custom conditional logic.
- Useful for scenarios where only certain conditions should trigger a login.

--- Requirements ---
- `Valid Redirect URIs` must include the URL passed to `redirectTo`.

### `logout(req, res, redirectTo)`
`logout` Function is not a middleware, but a **classic synchronous function** that forces the user to logout
via Keycloak. In addition to terminating the current session (if any), it generates the Keycloak
logout URL and redirects the user's browser to that address.

--- Differences from `logoutMiddleware` ---
- `logoutMiddleware` is designed to be used directly as middleware in the route definition.
- `logout` instead is a function **to be called inside the route**, useful for handling logout
  **conditionally** or within more complex logic.

--- Parameters ---
- @param {Object} req - Express `Request` object
- @param {Object} res - Express `Response` object
- @param {string} redirectTo - URL to redirect the user after logout

--- Behavior ---
1. Retrieves the `id_token` from the current user's Keycloak token (if present).
2. Builds the logout URL using `keycloak.logoutUrl()`.
3. Destroys the user's Express session.
4. Redirects the user to the Keycloak logout URL, which in turn redirects to `redirectTo`.

✅ Usage example:
```js

app.get('/logout', (req, res) => {
    // Any custom logic before logout
    // ...
    keycloakAdapter.logout(req, res, "http://localhost:3001/home");
});

```

--- Requirements ---
- The user must be authenticated with Keycloak and have a valid token in `req.kauth.grant`.
- The URL specified in `redirectTo` must be present in the `Valid Redirect URIs` in the Keycloak client.

---


## 🔧 Admin Functions
All administrative functions that rely on Keycloak's Admin API must be invoked using the 
keycloakAdapter.kcAdminClient.{entity}.{function} pattern. 
 - {entyty} represents the type of resource you want to manage (e.g., users, roles, groups, clients).
 - {function} is the specific operation you want to perform on that resource (e.g., find, create, update, del).
For example:
```js
// get all users of this client
// users is the entity you want to administer.
// find is the method used to retrieve the list of users.
 keycloakAdapter.kcAdminClient.users.find();
 ```
Credits to @keycloak/keycloak-admin-client. 
This admin function is built on top of it. For more details, please refer to the official repository.

### `entity realm`

### `entity users`
The roles users refers to Keycloak's users management functionality, part of the Admin REST API.
It allows you to create, update, inspect, and delete both realm-level and client-level users.

#### `entity roles functions`

##### `function create(user-dictionary)`
create is a method used to create a new user in the specified realm. 
This method accepts a user representation object containing details such as username, email, enabled status, 
credentials, and other user attributes that can be get by getProfile function. 
It is typically used when you want to programmatically add new users to your Keycloak realm via the Admin API.
```js
 // create a new user
 const userProfile = await keycloakAdapter.kcAdminClient.users.create({
     username:"username",
     email: "test@keycloak.org",
     // enabled required to be true in order to send actions email
     emailVerified: true,
     enabled: true,
     attributes: {
         key: "value",
     },
 });
 ```
##### `function find(filter)`
find method is used to retrieve a list of users in a specific realm. 
It supports optional filtering parameters such as username, email, first name, last name, and more. 
Searching by attributes is only available from Keycloak > 15
@parameters:
- filter: parameter provided as a JSON object that accepts the following filter:
  - q: A string containing a query filter by custom attributes, such as 'username:admin'. 
  - {builtin attribute}: To find users by builtin attributes such as email, surname... example {email:"admin@admin.com"}
  - max: A pagination parameter used to define the maximum number of users to return (limit).
  - first: A pagination parameter used to define the number of users to skip before starting to return results (offset/limit).
```js
 // find a user with 'key:value'
const user = await keycloakAdapter.kcAdminClient.users.find({ q: "key:value" });;
if(user) console.log('User found:', user);
else console.log('User not found');

// find a user by name = John
user = await keycloakAdapter.kcAdminClient.users.find({ name: "John" });;
if(user) console.log('User found:', user);
else console.log('User not found');

// find a user with 'name:john', skip 10 users and limt to 5
const user = await keycloakAdapter.kcAdminClient.users.find({ q: "name:john", first:11, max:5});;
if(user) console.log('User found:', user);
else console.log('User not found');
 ```

##### `function findOne(filter)`
findOne is method used to retrieve a specific user's details by their unique identifier (id) within a given realm. 
It returns the full user representation if the user exists.
```js
 // find a user with id:'user-id'
const user = await keycloakAdapter.kcAdminClient.users.findOne({ id: 'user-id' });
if(user) console.log('User found:', user);
else console.log('User not found');
 ```

##### `function count(filter)`
count method returns the total number of users in a given realm. 
It optionally accepts filtering parameters similar to those in users.find() such 
as username, email, firstName, lastName and so on to count only users that match specific criteria.
Searching by attributes is only available from Keycloak > 15
@parameters:
 - filter is a JSON object that accepts filter parameters, such as { email: 'test@keycloak.org' }
```js
 // Return the total number of registered users
const user_count = await keycloakAdapter.kcAdminClient.users.count();
console.log('User found:', user_count);

// Return the number of users with the name "John" 
user_count = await keycloakAdapter.kcAdminClient.users.count({name:'Jhon'});
console.log('User found:', user_count);
 ```


##### `function update(searchParams,userRepresentation)`
update method is used to update the details of a specific user in a Keycloak realm.
It requires at least the user’s ID(searchParams) and the updated data(userRepresentation). 
You can modify fields like firstName, lastName, email, enabled, and more.
@parameters:
 - searchParams: is a JSON object that accepts filter parameters
   - id: [Required] the user ID to update
   - realm [Optional] the realm name (defaults to current realm)
 - userRepresentation: An object containing the user fields to be updated.
```js
 // Update user with id:'user-id'
const user_count = await keycloakAdapter.kcAdminClient.users.update({ id: 'user-Id' }, {
    firstName: 'John',
    lastName: 'Updated',
    enabled: true,
});
 ```

##### `function resetPassword(newCredentialsParameters)`
resetPassword method is used to set a new password for a specific user. 
This action replaces the user's existing credentials. You can also set whether the user is required to 
change the password on next login.
@parameters:
 - newCredentialsParameters: is a JSON object that accepts filter parameters
   - id: [Required] the user ID to update
   - realm [Optional] the realm name (defaults to current realm)
   - credential: An object containing the new user credentials
     - temporary: true or false. Whether the new password is temporary (forces user to reset at next login). 
     - type: a String value set to "password"
     - value: a String containing new password to be set

```js
 // Update user with id:'user-id'
const user = await keycloakAdapter.kcAdminClient.users.resetPassword({ 
    id: userId,
    credential:{
        temporary: false,
        type: "password",
        value: "test"  
    } 
    });
 ```
##### `function getCredentials(filter)`
getCredentials() method retrieves the list of credentials (e.g., passwords, OTPs, WebAuthn, etc.) 
currently associated with a given user in a specific realm.
This is useful for auditing, checking what types of credentials a user has set up, 
or managing credentials such as password reset, WebAuthn deletion, etc.
@parameters:
 - getCredentials: is a JSON object that accepts filter parameters
   - id: [Required] the user ID to update
   - realm [Optional] the realm name (defaults to current realm)
```js
 // get credentials info for user whose id is 'user-id'
const ressult = await keycloakAdapter.kcAdminClient.users.getCredentials({id: 'user-id'});
console.log(ressult);
 ```


##### `function getCredentials(filter)`
getCredentials() method retrieves the list of credentials (e.g., passwords, OTPs, WebAuthn, etc.) 
currently associated with a given user in a specific realm.
This is useful for auditing, checking what types of credentials a user has set up, 
or managing credentials such as password reset, WebAuthn deletion, etc.
@parameters:
 - getCredentials: is a JSON object that accepts filter parameters
   - id: [Required] the user ID to update
   - realm [Optional] the realm name (defaults to current realm)
```js
 // get credentials info for user whose id is 'user-id'
const ressult = await keycloakAdapter.kcAdminClient.users.getCredentials({id: 'user-id'});
console.log(ressult);
 ```

##### `function deleteCredential(accountInfo)`
deleteCredential method allows you to delete a specific credential (e.g., password, OTP, WebAuthn, etc.) from a user. 
This is useful when you want to invalidate or remove a credential, forcing the user to reconfigure or reset it.
@parameters:
 - accountInfo: is a JSON object that accepts this parameters
   - id: [Required] the user ID to update
   - credentialId [Required] the credentils identifier
```js
 // delete credentials info for user whose id is 'user-id'
const ressult = await keycloakAdapter.kcAdminClient.users.deleteCredential({
    id: 'user-id',
    credentialId: credential.id
});
 ```

##### `function getProfile()`
It is a method  that retrieves the user profile dictionary information. 
This includes basic user details such as username, email, first name,  last name, 
and other attributes associated with the user profile in the Keycloak realm.
```js
 // create a role name called my-role
 const userProfile = await keycloakAdapter.kcAdminClient.users.getProfile();
 console.log('User profile dicionary:', userProfile);
 ```

##### `function addToGroup(parameters)`
Adds a user to a specific group within the realm.
@parameters:
- parameters: is a JSON object that accepts this parameters 
  - id [required]: The user ID of the user you want to add to the group. 
  - groupId [required]: The group ID of the group the user should be added to.
```js
 // create a role name called my-role
 const userGroup = await keycloakAdapter.kcAdminClient.users.addToGroup({
     groupId: 'group-id',
     id: 'user-id',
});
 console.log('User group info:', userGroup);
 ```
##### `function delFromGroup(parameters)`
Removes a user from a specific group in Keycloak.
@parameters:
- parameters: is a JSON object that accepts this parameters 
  - id [required]: The user ID of the user you want to remove to the group. 
  - groupId [required]: The group ID of the group the user should be removed to.
```js
 // create a role name called my-role
 const userGroup = await keycloakAdapter.kcAdminClient.users.delFromGroup({
     groupId: 'group-id',
     id: 'user-id',
});
 console.log('User group info:', userGroup);
 ```

##### `function countGroups(filter)`
Retrieves the number of groups that a given user is a member of.
@parameters:
- filter is a JSON object that accepts filter parameters, such as { id: '' }
  - id: [required] The user ID of the user whose group membership count you want to retrieve.
  - search: [optional] a String containing group name such "cool-group",
```js
 // Return the total number of user groups
const user_count = await keycloakAdapter.kcAdminClient.users.countGroups({id:'user-id'});
console.log('Groups found:', user_count);

 ```
##### `function listGroups(filter)`
Returns the list of groups that a given user is a member of.
@parameters:
- filter is a JSON object that accepts filter parameters, such as { id: '' }
  - id: [required] The user ID of the user whose group membership you want to retrieve.
  - search: [optional] a String containing group name such "cool-group",
```js
 // Return the total number of user groups
const user_count = await keycloakAdapter.kcAdminClient.users.listGroups({id:'user-id'});
console.log('Groups found:', user_count);

 ```


##### `function addRealmRoleMappings(roleMapping)`
Assigns one or more realm-level roles to a user.    
Returns a promise that resolves when the roles are successfully assigned. No return value on success.

@parameters:
- roleMapping is a JSON object that accepts this parameters:
  - id: [required] The ID of the user to whom the roles will be assigned..
  - roles: [required] An array of role representations to assign. Each role object should contain at least:
    - id: [required] The role Id
    - name: [required] The role Name
```js
 // Assigns one realm-level role to a user whose ID is 'user-id'.
const user_count = await keycloakAdapter.kcAdminClient.users.addRealmRoleMappings({
    id: 'user-id',
    // at least id and name should appear
    roles: [
        {
            id: 'role-id',
            name: 'role-name'
        },
    ],
});
console.log(`Assigned realm role role-name to user user-id`);
 ```

##### `function delRealmRoleMappings(roleMapping)`
Removes one or more realm-level roles from a specific user.
Only roles that were directly assigned to the user can be removed with this method.
This method does not affect composite roles. It only removes directly assigned realm roles.

@parameters:
- roleMapping is a JSON object that accepts this parameters:
    - id: [required] The ID of the user to whom the roles will be removed..
    - roles: [required] An array of role representations to remove. Each role object should contain at least:
        - id: [required] The role Id
        - name: [required] The role Name
```js
 // remove one realm-level role to a user whose ID is 'user-id'.
const roles_remove = await keycloakAdapter.kcAdminClient.users.delRealmRoleMappings({
    id: 'user-id',
    // at least id and name should appear
    roles: [
        {
            id: 'role-id',
            name: 'role-name'
        },
    ],
});
console.log(`realm role role-name to user user-id removed`);
 ```



##### `function listAvailableRealmRoleMappings(filter)`
Retrieves all available realm-level roles that can still be assigned to a specific user.
These are the roles that exist in the realm but have not yet been mapped to the user.

@parameters:
- filter is a JSON object that accepts this parameters:
  - id: [required] The ID of the user for whom to list assignable realm roles.
```js
 // Get assignable realm-level roles for user 'user-id'.
const available_roles = await keycloakAdapter.kcAdminClient.users.listAvailableRealmRoleMappings({
    id: 'user-id',
});
console.log('Assignable realm-level roles for user user-id',available_roles);
 ```

##### `function listRoleMappings(filter)`
Retrieves all realm-level and client-level roles that are currently assigned to a specific user.

 - @parameters:
- filter is a JSON object that accepts this parameters:
  - id: [required] The user ID for which you want to fetch the assigned role mappings.

@return a promise resolving to an object with two main properties:
- realmMappings: array of realm-level roles assigned to the user.
- clientMappings: object containing client roles grouped by client.

```js
 // Get assigned roles for user 'user-id'.
const roleMappings = await keycloakAdapter.kcAdminClient.users.listRoleMappings({
    id: 'user-id',
});
console.log(`Realm Roles assigned to user-id:`);
roleMappings.realmMappings?.forEach((role) => {
    console.log(`- ${role.name}`);
});

console.log("Client Role Mappings:");
for (const [clientId, mapping] of Object.entries(roleMappings.clientMappings || {})) {
    console.log(`Client: ${clientId}`);
    mapping.mappings.forEach((role) => {
        console.log(`  - ${role.name}`);
    });
}
 ```



##### `function listRealmRoleMappings(filter)`
Retrieves the realm-level roles that are currently assigned to a specific user.
Unlike listRoleMappings, this method focuses only on realm roles and excludes client roles.

 - @parameters:
- filter is a JSON object that accepts this parameters:
  - id: [required] The user ID for which you want to fetch the assigned role mappings.

@return a promise resolving to an array of role objects (realm roles)


```js
 // Get assigned roles for user 'user-id'.
const roleMappings = await keycloakAdapter.kcAdminClient.users.listRealmRoleMappings({
    id: 'user-id',
});
console.log(`Realm roles assigned to user user-id:`);
roleMappings.forEach((role) => {
    console.log(`- ${role.name}`);
});
 ```


##### `function listCompositeRealmRoleMappings(filter)`
Retrieves the list of composite realm-level roles that are effectively assigned to a user.
Composite roles include both directly assigned realm roles and any roles inherited through composite role structures.

 - @parameters:
- filter is a JSON object that accepts this parameters:
  - id: [required] The user ID for which you want to fetch the assigned role mappings.

@return a promise resolving to an array of role objects (realm roles)


```js
 // Get assigned roles for user 'user-id'.
const roleMappings = await keycloakAdapter.kcAdminClient.users.listCompositeRealmRoleMappings({
    id: 'user-id',
});
console.log(`Composite realm roles assigned to user user-id:`);
roleMappings.forEach((role) => {
    console.log(`- ${role.name}`);
});
 ```


##### `function addClientRoleMappings(role_mapping)`
Assigns one or more client-level roles to a user. 
This method adds role mappings from a specific client to the given user,
allowing the user to have permissions defined by those client roles.

 - @parameters:
- role_mapping is a JSON object that accepts this parameters:
  - id: [required] The ID of the user to whom roles will be assigned. 
  - clientUniqueId:[required] The internal ID of the client that owns the roles.
  - roles: [required] Array of role objects representing the client roles to assign, at least id and name should appear:
    - id:[required]: role identifier
    - name:[required]: role name
    - [optional] Other fields

```js
 // Add client roles for user 'user-id'.
const roleMappings = await keycloakAdapter.kcAdminClient.users.addClientRoleMappings({
    id: 'user-id',
    clientUniqueId: 'internal-client-id',
    
    // at least id and name should appear
    roles: [{
            id: 'role-id',
            name: 'role-name',
    }]
});
 ```

##### `function listAvailableClientRoleMappings(filter)`
Retrieves a list of client roles that are available to be assigned to a specific user,
meaning roles defined in a client that the user does not yet have assigned. 
This is useful for determining which roles can still be mapped to the user.

 - @parameters:
- filter is a JSON object that accepts this parameters:
  - id: [required] The ID of the user
  - clientUniqueId:[required] The internal ID of the client (not the clientId string)
```js

// Get all user 'user-id' available roles for client 'internal-client-id'
const availableRoles = await keycloakAdapter.kcAdminClient.users.listAvailableClientRoleMappings({
    id: 'user-id',
    clientUniqueId: 'internal-client-id'
 });
 console.log('Available roles for assignment:', availableRoles.map(r => r.name));
 ```



##### `function listCompositeClientRoleMappings(filter)`
Retrieves all composite roles assigned to a specific user for a given client. 
Composite roles are roles that include other roles. 
This method returns not only directly assigned roles, but also roles inherited through composite definitions for that client.

 - @parameters:
- filter is a JSON object that accepts this parameters:
  - id: [required] The ID of the user
  - clientUniqueId:[required] The internal ID of the client (not the clientId string)
```js

 // Get all composite roles assigned to a  user 'user-id' for client 'internal-client-id'
const availableRoles = await keycloakAdapter.kcAdminClient.users.listCompositeClientRoleMappings({
    id: 'user-id',
    clientUniqueId: 'internal-client-id'
 });
 console.log('Available composite roles:', availableRoles.map(r => r.name));
 ```



##### `function listClientRoleMappings(filter)`
Retrieves all client-level roles directly assigned to a user for a specific client.
Unlike composite role mappings, this method only returns the roles that were explicitly 
assigned to the user from the client, without including roles inherited via composite definitions.

 - @parameters:
- filter is a JSON object that accepts this parameters:
  - id: [required] The ID of the user
  - clientUniqueId:[required] The internal ID of the client (not the clientId string)
```js

 // Get all roles assigned to a  user 'user-id' for client 'internal-client-id'
const availableRoles = await keycloakAdapter.kcAdminClient.users.listClientRoleMappings({
    id: 'user-id',
    clientUniqueId: 'internal-client-id'
 });
 console.log('Available roles:', availableRoles.map(r => r.name));
 ```


##### `function delClientRoleMappings(filter)`
Removes one or more client-level roles previously assigned to a specific user. 
This operation unlinks the direct association between the user and the specified roles within the given client.

 - @parameters:
- filter is a JSON object that accepts this parameters:
  - id: [required] The ID of the user to whom roles will be removed.
  - clientUniqueId:[required] The internal ID of the client that owns the roles.
  - roles: [required] Array of role objects representing the client roles to assign, at least id and name should appear:
      - id:[required]: role identifier
      - name:[required]: role name
      - [optional] Other fields
```js

 // Get all roles assigned to a  user 'user-id' for client 'internal-client-id'
await keycloakAdapter.kcAdminClient.users.delClientRoleMappings({
    id: 'user-id',
     clientUniqueId: 'internal-client-id',
     roles: [{
         id: 'role-id',
        name: 'role-name',
     }],
 });
 console.log('Roles successfully removed from user.');
 ```



##### `function listSessions(filter)`
Retrieves a list of active user sessions for the specified user. 
Each session represents a login session associated with that user across different clients or devices.

 - @parameters:
- filter is a JSON object that accepts this parameters:
  - id: [required] The ID of the user whose sessions will be listed.
  - clientId: [optional] The internal ID of the client that owns the roles.
```js

 // Get all the user 'user-id' sessions.
const sessions=await keycloakAdapter.kcAdminClient.users.listSessions({
    id: 'user-id',
 });
 console.log("User 'user-id' sessions:",sessions);
 ```



##### `function listOfflineSessions(filter)`
Retrieves a list of offline sessions for the specified user. 
Offline sessions represent long-lived refresh tokens that allow clients to obtain new access tokens 
without requiring the user to be actively logged in.

 - @parameters:
- filter is a JSON object that accepts this parameters:
  - id: [required] The ID of the user whose sessions will be listeds
  - clientId: [optional] The client ID whose sessions are being checked
```js

 // Get all the user 'user-id' sessions.
const sessions=await keycloakAdapter.kcAdminClient.users.listOfflineSessions({ 
    id: 'user-id', 
    clientId: 'client-id' 
});
 console.log("User 'user-id' offline sessions:",sessions);
 ```



##### `function logout(filter)`
Forces logout of the specified user from all active sessions, both online and offline. 
This invalidates the user’s active sessions and tokens, effectively logging them out from all clients.

 - @parameters:
- filter is a JSON object that accepts this parameters:
  - id: [required] The ID of the user whose sessions will be closed
```js

 // Get all the user 'user-id' sessions.
const sessions=await keycloakAdapter.kcAdminClient.users.logout({ 
    id: 'user-id',
});
 console.log('All User session closed');
 ```


##### `function listConsents(filter)`
Retrieves the list of OAuth2 client consents that the specified user has granted.
Each consent represents a client application that the user has authorized to access their data with specific scopes.

 - @parameters:
- filter is a JSON object that accepts this parameters:
  - id: [required] The ID of the user whose client consents can be retrieved.
```js

 // Retrieves the list of OAuth2 client consents that the specified user has granted.
const listConsents=await keycloakAdapter.kcAdminClient.users.listConsents({ 
    id: 'user-id',
});
 console.log('All User consents:',listConsents);
 ```



##### `function revokeConsent(filter)`
Revokes a previously granted OAuth2 client consent for a specific user. 
This operation removes the authorization a user has given to a client, 
effectively disconnecting the client from the user's account and invalidating associated tokens.

- @parameters:
- filter is a JSON object that accepts this parameters:
    - id: [required] T	The ID of the user whose consent should be revoked
    - clientId: TThe client ID for which the consent should be revoked
```js

 // Retrieves the list of OAuth2 client consents that the specified user has granted.
await keycloakAdapter.kcAdminClient.users.revokeConsent({
    id: 'user-id',
    clientId: 'client-id',
 });
 ```



##### `function getUserStorageCredentialTypes()`
For more details, see the keycloak-admin-client package in the Keycloak GitHub repository.

##### `function updateCredentialLabel()`
For more details, see the keycloak-admin-client package in the Keycloak GitHub repository.



### `entity clients`
Clients entity provides a set of methods to manage clients (i.e., applications or services) within a realm. 
Clients represent entities that want to interact with Keycloak for authentication or authorization (e.g., web apps, APIs).


#### `entity clients functions`


##### `function create(client_dictionary)`
Creates a new client with the provided configuration
@parameters:
- client_dictionary:  An object(JSON) of type ClientRepresentation, containing the configuration for the new client.
    - clientId: [required] string	The unique identifier for the client (required). 
    - name:	[required] string	A human-readable name for the client. 
    - enabled: [optional]	boolean	Whether the client is enabled. Default is true. 
    - publicClient:	[optional] boolean	Whether the client is public (no secret). 
    - secret:	[optional] string	Client secret (if not a public client). 
    - redirectUris:	[optional] string[]	List of allowed redirect URIs (for browser-based clients). 
    - baseUrl:	[optional] string	Base URL of the client. 
    - protocol:	[optional] string	Protocol to use (openid-connect, saml, etc.). 
    - standardFlowEnabled:	[optional] boolean	Enables standard OAuth2 Authorization Code Flow. 
    - ....[optional] Other client fields 

```js
 // create a client called my-client
 const client= await keycloakAdapter.kcAdminClient.clients.create({name: "my-client", id:"client-id"});
console.log("New Client Created:", client);
 ```



##### `function find(filter)`
Retrieves a list of all clients in the current realm, optionally filtered by query parameters. 
This method is useful for listing all registered applications or services in Keycloak or searching 
for a specific one using filters like clientId.
@parameters:
- filter: A JSON structure used to filter results based on specific fields:
  - clientId: [optional] string filter to search clients by their clientId. 
  - viewableOnly: [optional] boolean value.	If true, returns only clients that the current user is allowed to view. 
  - first:[optional] Pagination: index of the first result to return. 
  - max:[optional]	Pagination: maximum number of results to return.
```js
 // Get client by ID: 'client-id'
const clients= await keycloakAdapter.kcAdminClient.clients.find({ id:"client-id"});
console.log("Clients:", clients);
 ```


##### `function del(filter)`
Deletes a client from the realm using its internal ID. 
This operation is irreversible and will remove the client and all its associated roles, permissions, and configurations.
@parameters:
- filter: A JSON structure used to filter results based on specific fields:
  - id: [required] The internal ID of the client to delete (not clientId)
```js
 // delete client by ID: 'internal-client-id'
const clients= await keycloakAdapter.kcAdminClient.clients.del({ id:"internal-client-id"});
console.log(`Client successfully deleted.`);
 ```




##### `function createRole(role_parameters)`
Creates a new client role under a specific client. 
Client roles are roles associated with a specific client (application), and are useful 
for fine-grained access control within that client.
@parameters:
- role_parameters: JSON structure that defines the role like:
    - id: [required] The internal ID of the client where the role will be created. 
    - name: [required] Name of the new role. 
    - description: [optional] Optional description of the role.
    - [optional] Other role fields
```js
 // Creates a new client role under a specific client.
const role= await keycloakAdapter.kcAdminClient.clients.createRole({
    id: 'client-id',
    name: 'roleName'
});
console.log("Client role:", role);
 ```




##### `function findRole(filter)`
Retrieves a specific client role by name from a given client. 
This is useful when you want to inspect or verify the properties of a role defined within a particular client.
@parameters:
- filter: JSON structure that defines the filter parameters:
    - id: [required] The internal ID of the client (not the clientId string) where the role is defined.
    - roleName: [required] The name of the client role you want to find.

```js
 // Get client role by ID: 'internal-client-id'
const role= await keycloakAdapter.kcAdminClient.clients.findRole({
    id: 'internal-client-id',
    roleName:'roleName'
});
console.log("Client role:", role);
 ```



##### `function delRole(filter)`
Deletes a client role by its name for a specific client.
This permanently removes the role from the specified client in Keycloak.
A promise that resolves to void if the deletion is successful. 
If the role does not exist or the operation fails, an error will be thrown.
@parameters:
- filter: JSON structure that defines the filter parameters:
    - id: [required] The internal ID of the client (not the clientId string) where the role is defined.
    - roleName: [required] The name of the client role you want to delete.

```js
 // delere client role by ID: 'internal-client-id'
const role= await keycloakAdapter.kcAdminClient.clients.delRole({
    id: 'internal-client-id',
    roleName:'roleName'
});
 ```


### `entity groups`
The groups entity allows you to manage groups in a Keycloak realm. 
Groups are collections of users and can have roles and attributes assigned to them. 
Groups help organize users and assign permissions in a scalable way

#### `entity groups functions`
##### `function create(role_dictionary)`
Create a new group in the current realme
```js
 // create a group called my-group
 keycloakAdapter.kcAdminClient.groups.create({name: "my-group"});
 ```

##### `function find(filter)`
find method is used to retrieve a list of groups in a specific realm.
It supports optional filtering parameters.
Searching by attributes is only available from Keycloak > 15
@parameters:
- filter: parameter provided as a JSON object that accepts the following filter:
    - {builtin attribute}: To find groips by builtin attributes such as name, id
    - max: A pagination parameter used to define the maximum number of groups to return (limit).
    - first: A pagination parameter used to define the number of groups to skip before starting to return results (offset/limit).
```js
 // find a 100 groups
const groups = await keycloakAdapter.kcAdminClient.groups.find({ max: 100 });
if(groups) console.log('Groups found:', groups);
else console.log('Groups not found');

// find a 100 groups and skip the first 50
groups = await keycloakAdapter.kcAdminClient.groups.find({ max: 100, first:50 });
if(groups) console.log('Groups found:', groups);
else console.log('Groups not found');
 ```

##### `function findOne(filter)`
findOne is method used to retrieve a specific group's details by their unique identifier (id) within a given realm.
It returns the full group representation if the group exists.
```js
 // find a group with id:'group-id'
const group = await keycloakAdapter.kcAdminClient.groups.findOne({ id: 'group-id' });
if(group) console.log('Group found:', group);
else console.log('Group not found');
 ```


##### `function del(filter)`
Deletes a group from the realm.
Return a promise that resolves when the group is successfully deleted. No content is returned on success.
@parameters:
- filter: parameter provided as a JSON object that accepts the following filter:
    - id: The ID of the group to delete.
```js
 // delete a group with id:'group-id'
const group = await keycloakAdapter.kcAdminClient.groups.del({ id: 'group-id' });
 ```




### `entity roles`
The roles entity refers to Keycloak's roles management functionality, part of the Admin REST API. 
It allows you to create, update, inspect, and delete both realm-level and client-level roles.

#### `entity roles functions`
##### `function create(role_dictionary)`
Create a new role
```js
 // create a role name called my-role
 keycloakAdapter.kcAdminClient.roles.create({name:'my-role'});
 ```
##### `function createComposite(params: { roleId: string }, payload: RoleRepresentation[]`
Create a new composite role
Composite roles in Keycloak are roles that combine other roles, allowing you to group multiple permissions 
into a single, higher-level role. A composite role can include roles from the same realm as well
as roles from different clients. When you assign a composite role to a user, 
they automatically inherit all the roles it contains.


```js
 // create a  composite role where "admin" include anche "reader".
const adminRole = await client.roles.findOneByName({ name: 'admin' });
const readerRole = await client.roles.findOneByName({ name: 'reader' });

await client.roles.createComposite({ roleId: adminRole.id }, [readerRole]);
 ```

##### `function find()`
get all realm roles and return a JSON
```js
 keycloakAdapter.kcAdminClient.roles.find();
 ```
##### `function findOneByName(filter)`
get a role by name
```js
 // get information about 'my-role' role
 keycloakAdapter.kcAdminClient.roles.findOneByName({ name: 'my-role' });
 ```

##### `function findOneById(filter)`
get a role by its Id
```js
 // get information about 'my-role-id' role
 keycloakAdapter.kcAdminClient.roles.findOneById({ id: 'my-role-id' });
 ```

##### `function updateByName(filter,role_dictionary)`
update a role by its name
```js
 // update 'my-role' role with a new description
 keycloakAdapter.kcAdminClient.roles.updateByName({ name: 'my-role' }, {description:"new Description"});
 ```

##### `function updateById(filter,role_dictionary)`
update a role by its id
```js
 // update role by id 'my-role-id' with a new description
 keycloakAdapter.kcAdminClient.roles.updateById({ id: 'my-role-id' }, {description:"new Description"});
 ```

##### `function delByName(filter)`
delete a role by its name
```js
 // delete role  'my-role' 
 keycloakAdapter.kcAdminClient.roles.delByName({ name: 'my-role' });
 ```

##### `function findUsersWithRole(filter)`
Find all users associated with a specific role.
```js
 // Find all users associated with role named 'my-role' 
 keycloakAdapter.kcAdminClient.roles.findUsersWithRole({ name: 'my-role' });
 ```

##### `function getCompositeRoles({id:roleid})`
Find all composite roles associated with a specific id.
```js
 // Find all composite role named 'my-role' and id 'my-role-id' 
 keycloakAdapter.kcAdminClient.roles.getCompositeRoles({ id: 'my-role-id' });
 ```

##### `function getCompositeRolesForRealm({roleId:roleid})`
The getCompositeRolesForRealm function in the Keycloak Admin client is used to 
retrieve all realm-level roles that are associated with a given composite role. 
When a role is defined as composite, it can include other roles either from the same 
realm or from different clients. This specific method returns only the realm-level roles
that have been added to the composite role. It requires the roleId of the target role as a 
parameter and returns an array of RoleRepresentation objects. If the role is not composite
or has no associated realm roles, the result will be an empty array. This method is useful 
for understanding and managing hierarchical role structures within a realm in Keycloak.
```js
const role = await client.roles.findOneByName({ name: 'admin' });
const compositeRoles = await keycloakAdapter.kcAdminClient.roles.getCompositeRolesForRealm({ roleId: role.id });
console.log('admin composite roles:', compositeRoles.map(r => r.name));
 
 ```

##### `function getCompositeRolesForRealm({roleId:'roleid', clientId:'clientId'})`
The getCompositeRolesForClient function in the Keycloak Admin client is used to retrieve 
all client-level roles that are associated with a given composite role. 
Composite roles in Keycloak can include roles from different clients,
and this method specifically returns the roles belonging to a specified client that
are part of the composite role. It requires the roleId of the composite role 
and the clientId of the client whose roles you want to retrieve. The function returns an array of
RoleRepresentation objects representing the client roles included in the composite. 
This helps manage and inspect client-specific role hierarchies within the composite role structure in Keycloak.
```js
const role = await client.roles.findOneByName({ name: 'admin' });
const compositeRoles = await keycloakAdapter.kcAdminClient.roles.getCompositeRolesForClient({
    roleId: compositeRoleId,
    clientId: clientId,
});
console.log('admin composite roles fo client whith Id:clientId:', compositeRoles.map(r => r.name));
 
 ```




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


