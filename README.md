# gearworks-route
The routing function used by Gearworks apps, complete with full TypeScript definitions. This routing function simplifies Shopify webhook, proxy and request validation, JWT authentication, parameter validation and more. 

[Gearworks](https://github.com/nozzlegear/gearworks) is the fastest way to get started with building Shopify apps!

## Installation

With [Yarn](https://github.com/yarnpkg/yarn):

```shell
yarn install gearworks-route
```

Or from [NPM](https://npmjs.com/package/gearworks-route):

```shell
npm install gearworks-route --save
```

## Importing

Import gearworks-route via ES6 default import:

```js
import getRouter from "gearworks-route";
```

Or via Node's require:

```js
const getRouter = require("gearworks-route").default;
```

## Example

Pass your Express app and a configuration object into the `getRouter` function, which will return a routing function that you can use to quickly configure routes:

```js
import * as express from "express";
import getRouter from "gearworks-route";

const app = express();
const config = {
    sealable_users_props: ["shopify_access_token"],
    shopify_secret_key: "my shopify secret key used to validate Shopify requests",
    iron_password: "My randomly generated password which will encrypt the sealable_users_props",
    jwt_secret_key: "My randomly generated password which will sign JWT auth tokens",
    userAuthIsValid: async (user) => {
        // Use this function to tell the route whether the user's auth is now invalid by e.g. checking a cache or database.

        return true;
    }
}
const route = getRouter(expressApp, config);

// Create a route
route({
    label: "Validate a Shopify webhook",
    method: "post",
    path: "/api/v1/webhooks/app-uninstalled",
    validateShopifyWebhook: true,
    handler: async function (req, res, next) {
        // A user has uninstalled your Shopify app!
        res.json({okay: true});

        // All handlers must call next() when they're done.
        return next();
    }
})
```

## Configuration

The `getRouter` function expects you to pass in both an Express app, and a configuration object with the following values:

| prop | type | required | description |
|------|------|----------|-------------|
| `shopify_secret_key` | string | true | Your Shopify app's secret key, used to validate Shopify requests. |
| `iron_password` | string | true | A randomly-generated string used to encrypt and decrypt the properties in `sealable_user_props`. |
| `jwt_secret_key` | string | true | A randomly-generated string used to sign JWT auth tokens. |
| `sealable_user_props` | string array | false | A list of sensitive properties on your User object that should be encrypted and sealed by Iron. Usually you'd want to encrypt at minimum the user's Shopify access token. |
| `auth_header_name` | string | false | The name of the header to check for auth tokens. Defaults to `gearworks_auth`. | 
| `userAuthIsValid` | function | false | A function that receives the User object to check whether a user's auth is still valid (e.g. they uninstalled your app and should be logged out). Return true for valid, false for invalid. |

## Route Configuration

The `getRouter` function returns a `route` function, which you can use to quickly setup routes. It accepts a single parameter, an object with the following props:

| prop | type | required | description |
|------|------|----------|-------------|
| `label` | string | false | A string which gives a quick summary of the route. Currently only used for developer convenience to quickly scan routes. |
| `path` | string | true | The route's URL path. Can accept Express-style parameters, e.g. `/api/v1/orders/:id`. |
| `method` | string | true | The route's request method. Must be either `get`, `post`, `put`, `delete`, `head` or `all`. Case-sensitive, must be all lowercase. |
| `handler` | function | true | The route's handler, a function which accepts  `req`, `res` and `next` parameters. Can be async. All handlers must call `next()` to end the request. |
| `cors` | boolean | false | A flag which enables Cross-Origin Resource Sharing (CORS) requests for the route. |
| `requireAuth` | boolean | false | A flag which tells the route function whether it should require an authorized user. If true, the deserialized User object will be available to the handler function with `req.user`. |
| `bodyValidation` | object | false | A [Joi](https://npmjs.com/package/joi) validation scheme which will be applied to the request body. Access the validated object with `req.validatedBody` in the handler function. |
| `queryValidation` | object | false | A [Joi](https://npmjs.com/package/joi) validation scheme which will be applied to the request querystring. Access the validated object with `req.validatedQuery` in the handler function. |
| `paramValidation` | object | false | A [Joi](https://npmjs.com/package/joi) validation scheme which will be applied to the request url parameters. Access the validated object with `req.validatedParams` in the handler function. |
| `validateShopifyRequest` | boolean | false | A flag which tells the route function whether it should validate the request as a Shopify request. |
| `validateShopifyWebhook` | boolean | false | A flag which tells the route function whether it should validate the request as a Shopify webhook. |
| `validateShopifyProxyPage` | boolean | false | A flag which tells the route function whether it should validate the request as a Shopify proxy page request. |

## TypeScript interfaces

This package comes complete with full TypeScript definitions! When using the `getRouter` function, you're expected to pass in the type interface for your User object. That will then give you intellisense on the `sealable_user_props` configuration option, and the `req.user` object in your route handlers.

```ts
import getRouter from "gearworks-route";

interface User {
    _id: string;
    username: string;
    shopify_access_token: string;
}

const route = getRouter<User>(expressApp, {
    sealable_users_props: ["shopify_access_token" /* Array only accepts keys from the User interface */],
    ...
})

route({
    label: "Get home page",
    method: "get",
    path: "/home",
    requireAuth: true,
    handler: async function (req, res, next) {
        // req.user is type User

        ...
    }
})
```