import * as joi from "joi";
import * as boom from "boom";
import * as cors from "cors";
import inspect from "logspect";
import * as Bluebird from "bluebird";
import { Auth } from "shopify-prime";
import { seal, unseal } from "iron-async";
import { decode, encode } from "jwt-simple";
import { Express, Request, Response, NextFunction } from "express";
import { json as parseJson, urlencoded as parseUrlEncoded } from "body-parser";

export interface RouterRequest<UserType> extends Request {
    user?: UserType;
    validatedBody?: any;
    validatedQuery?: any;
    validatedParams?: any;
    domainWithProtocol: string;
}

export type WithSessionTokenFunction<UserType> = (user: UserType, expInDays?: number) => Promise<RouterResponse<UserType>>;

export interface RouterResponse<UserType> extends Response {
    withSessionToken: WithSessionTokenFunction<UserType>;
    json: <DataType>(data: DataType) => RouterResponse<UserType>;
}

export interface RouterFunctionConfig<UserType> {
    method: "get" | "post" | "put" | "delete" | "head" | "all",
    path: string,
    handler: (req: RouterRequest<UserType>, res: RouterResponse<UserType>, next: NextFunction) => void | any,
    label?: string,
    cors?: boolean,
    requireAuth?: boolean,
    bodyValidation?: joi.Schema,
    queryValidation?: joi.Schema,
    paramValidation?: joi.Schema,
    validateShopifyRequest?: boolean;
    validateShopifyWebhook?: boolean;
    validateShopifyProxyPage?: boolean;
}

export type RouterFunction<UserType> = (config: RouterFunctionConfig<UserType>) => void;

export interface Config<UserType> {
    iron_password: string;
    jwt_secret_key: string;
    shopify_secret_key: string;
    auth_header_name?: string;
    sealable_user_props?: (keyof UserType)[];
    userAuthIsValid?: (user: UserType) => boolean | Promise<boolean>;
}

export default function getRouter<UserType>(app: Express, config: Config<UserType>) {
    // Add configuration defaults
    config = {
        auth_header_name: "gearworks_auth",
        sealable_user_props: [],
        userAuthIsValid: async (user) => true,
        ...config,
    }

    if (!config.iron_password) {
        const error = new Error(`gearworks-route: iron_password is required in configuration object. Encryption and decryption is impossible.`);

        throw error;
    }

    if (!config.jwt_secret_key) {
        const error = new Error(`gearworks-route: jwt_secret_key is required in configuration object. Signing JWT tokens will be impossible.`);

        throw error;
    }

    if (!config.shopify_secret_key) {
        const error = new Error(`gearworks-route: shopify_secret_key is required in configuration object. Validating Shopify requests will be impossible.`);

        throw error;
    }

    const jwtAlgorithm = "HS256";

    // Custom functions for Express request and response objects
    const withSessionToken: WithSessionTokenFunction<UserType> = async function (this: RouterResponse<UserType>, user: UserType, expInDays = 30) {
        // Encrypt any sensitive properties (access tokens, api keys, etc.) with Iron.
        const sealedProps = await Bluebird.reduce(config.sealable_user_props, async (result, propName: string) => {
            if (!!user[propName]) {
                try {
                    result[propName] = await seal(user[propName], config.iron_password);
                } catch (e) {
                    inspect(`Failed to encrypt Iron-sealed property ${propName}. Removing property from resulting session token object.`, e);

                    // Prevent sending the unencrypted value to the client.
                    result[propName] = undefined;
                }
            }

            return result;
        }, {});

        // exp: Part of the jwt spec, specifies an expiration date for the token.
        const exp = Date.now() + (expInDays * 24 * 60 * 60 * 1000);
        const session = {
            ...user as any,
            exp,
            ...sealedProps,
        }

        return this.json({ token: encode(session, config.jwt_secret_key, jwtAlgorithm) }) as RouterResponse<UserType>;
    };

    // Shim the app.response and app.request objects with our custom functions
    app.response["withSessionToken"] = withSessionToken;

    // A custom routing function that handles authentication and body/query/param validation
    const route: RouterFunction<UserType> = (routeConfig) => {
        const method = routeConfig.method.toLowerCase();
        const corsMiddleware = routeConfig.cors ? cors() : (req, res, next) => next();
        let jsonParserMiddleware = (req, res, next) => next();
        let formParserMiddleware = (req, res, next) => next();

        if (routeConfig.cors && routeConfig.method !== "all") {
            // Add an OPTIONS request handler for the path. All non-trivial CORS requests from browsers 
            // send an OPTIONS preflight request.
            app.options(routeConfig.path, cors());
        }

        // Webhook validation must read the body exactly as its sent by Shopify, which is impossible when using parser middleware.
        // If the route requires validation a Shopify webhook, we'll skip parser middleware and parse it ourselves.
        if (!routeConfig.validateShopifyWebhook) {
            // Set up request body parsers
            jsonParserMiddleware = parseJson();
            formParserMiddleware = parseUrlEncoded({ extended: true });
        }

        app[method](routeConfig.path, corsMiddleware, jsonParserMiddleware, formParserMiddleware, async function (req: RouterRequest<UserType>, res: RouterResponse<UserType>, next: NextFunction) {
            req.domainWithProtocol = `${req.protocol}://${req.hostname}` + (req.hostname === "localhost" ? ":3000" : "");

            if (routeConfig.requireAuth) {
                const header = req.header(config.auth_header_name || "gearworks_auth");
                let user;

                try {
                    user = decode(header, config.jwt_secret_key, false, jwtAlgorithm);
                } catch (e) {
                    return next(boom.unauthorized(`Missing or invalid ${config.auth_header_name || "gearworks_auth"} header.`));
                }

                // Ensure the decoded object is a user
                if (!user) {
                    return next(boom.unauthorized(`Decoded JWT token does not appear to be a valid user object.`));
                }

                // If user id exists in invalidation cache, return a 401 unauthed response.
                try {
                    const authIsValid = await Bluebird.resolve(config.userAuthIsValid(user));

                    if (!authIsValid) {
                        return next(boom.unauthorized(`userAuthIsValid function indicates that user's JWT token is no longer valid.`));
                    }
                } catch (e) {
                    inspect(`Error attempting to check if user's auth is valid. Assuming true.`, e);
                }

                // Decrypt sensitive Iron-sealed properties
                const unsealedProps = await Bluebird.reduce(config.sealable_user_props, async (result, propName: string) => {
                    if (!!user[propName]) {
                        try {
                            result[propName] = await unseal(user[propName], config.iron_password);
                        } catch (e) {
                            inspect(`Failed to decrypt Iron-sealed property ${propName}.`, e);
                        }
                    }

                    return result;
                }, {});

                req.user = Object.assign(user, unsealedProps);
            };

            if (routeConfig.bodyValidation) {
                const validation = joi.validate(req.body, routeConfig.bodyValidation);

                if (validation.error) {
                    const error = boom.badData(validation.error.message, validation.error.details);

                    return next(error);
                }

                req.validatedBody = validation.value;
            }

            if (routeConfig.queryValidation) {
                const validation = joi.validate(req.query, routeConfig.queryValidation);

                if (validation.error) {
                    const error = boom.badData(validation.error.message, validation.error.details);

                    return next(error);
                }

                req.validatedQuery = validation.value;
            }

            if (routeConfig.paramValidation) {
                const validation = joi.validate(req.params, routeConfig.paramValidation);

                if (validation.error) {
                    const error = boom.badData(validation.error.message, validation.error.details);

                    return next(error);
                }

                req.validatedParams = validation.value;
            }

            if (routeConfig.validateShopifyRequest) {
                const isValid = await Auth.isAuthenticRequest(req.query, config.shopify_secret_key);

                if (!isValid) {
                    const error = boom.forbidden("Request does not pass Shopify's request validation scheme.");

                    return next(error);
                }
            }

            if (routeConfig.validateShopifyWebhook) {
                // If the body is empty, there's no way to validate the webhook.
                if (req.headers['transfer-encoding'] === undefined && isNaN(req.headers['content-length'] as any)) {
                    const error = boom.forbidden("Request does not pass Shopify's webhook validation scheme.");
                    inspect("Webhook body appears to be empty and cannot be validated. Headers:", req.headers);

                    return next(error);
                }

                // To validate a webhook request, we must read the raw body as it was sent by Shopify — not the parsed body.
                const rawBody = await new Bluebird<string>((res, rej) => {
                    let body: string = "";

                    req.on("data", chunk => body += chunk);
                    req.on("end", () => res(body));
                })

                const isValid = await Auth.isAuthenticWebhook(req.headers, rawBody, config.shopify_secret_key);

                if (!isValid) {
                    const error = boom.forbidden("Request does not pass Shopify's webhook validation scheme.")

                    return next(error);
                }

                if (req.header("content-type") === "application/json") {
                    req.body = JSON.parse(rawBody);
                }
            }

            if (routeConfig.validateShopifyProxyPage) {
                const isValid = await Auth.isAuthenticProxyRequest(req.query, config.shopify_secret_key);

                if (!isValid) {
                    const error = boom.forbidden("Request does not pass Shopify's proxy page validation scheme.");

                    return next(error);
                }
            }

            // Pass control to the route's handler. Handlers can be async, so wrap them in a bluebird resolve which can catch unhandled promise rejections.
            Bluebird.resolve(routeConfig.handler(req, res, next)).catch(e => {
                return next(e);
            });
        });
    }

    return route;
}