import * as Bluebird from "bluebird";
import * as boom from "boom";
import * as cors from "cors";
import * as joi from "joi";
import inspect from "logspect";
import { Auth } from "shopify-prime";
import { decode, encode } from "jwt-simple";
import { Express, NextFunction, Request, Response } from "express";
import { json as parseJson, urlencoded as parseUrlEncoded } from "body-parser";
import { seal, unseal } from "iron-async";
import parseFiles = require("express-fileupload");

export interface UploadedFile {
    /**
     * The file's filename.
     */
    name: string;
    /**
     * A helper function to move the file elsewhere on your server.
     */
    mv: (destination: string) => Promise<void>;
    /**
     * The file's mimetype, e.g. image/png.
     */
    mimetype: string;
    /**
     * The file in buffer format.
     */
    data: Buffer;
}

export interface RouterRequest<UserType, ServerSettings extends object> extends Request {
    settings: ServerSettings;
    user?: UserType;
    validatedBody?: any;
    validatedQuery?: any;
    validatedParams?: any;
    domainWithProtocol: string;
    /**
     * Files uploaded with the request. Will be undefined if the route config didn't set receivesFiles to true.
     */
    files?: { [propName: string]: UploadedFile };
}

export type WithSessionTokenFunction<UserType> = (
    user: UserType,
    expInDays?: number
) => Promise<RouterResponse<UserType>>;

export interface RouterResponse<UserType> extends Response {
    withSessionToken: WithSessionTokenFunction<UserType>;
    json: <DataType>(data: DataType) => RouterResponse<UserType>;
}

export interface RouterFunctionConfig<UserType, ServerSettings extends object = {}> {
    method: "get" | "post" | "put" | "delete" | "head" | "all";
    path: string;
    handler: (
        req: RouterRequest<UserType, ServerSettings>,
        res: RouterResponse<UserType>,
        next: NextFunction
    ) => void | any;
    label?: string;
    cors?: boolean;
    requireAuth?: boolean;
    bodyValidation?: joi.Schema;
    queryValidation?: joi.Schema;
    paramValidation?: joi.Schema;
    validateShopifyRequest?: boolean;
    validateShopifyWebhook?: boolean;
    validateShopifyProxyPage?: boolean;
    /**
     * Size limit for incoming requests to the route. Can be set to a string (e.g. '50mb') or a number representing byte length (e.g. 52428800). Defaults to 1mb.
     */
    requestSizeLimit?: number | string;
    /**
     * Whether requests to this route will receive files. Be sure to set requestSizeLimit when receiving files.
     */
    receivesFiles?: boolean;
}

export type RouterFunction<UserType> = (config: RouterFunctionConfig<UserType>) => void;

export type SealableUserProps<UserType> = (keyof UserType)[];

type UserProperty<UserType> = UserType[keyof UserType];

type SealedUserProps<UserType> = { [K in keyof UserType]: UserProperty<UserType> | string };

export interface Config<UserType, ServerSettings extends object = {}> {
    iron_password: string;
    jwt_secret_key: string;
    shopify_secret_key: string;
    auth_header_name?: string;
    sealable_user_props?: SealableUserProps<UserType>;
    serverSettings?: ServerSettings;
    userAuthIsValid?: (user: UserType) => boolean | Promise<boolean>;
}

export interface SessionTokenResponse {
    token: string;
}

/**
 * The object sent to a client after calling res.withSessionToken<UserType>(user);
 */
export type SessionToken<UserType> = UserType & { exp: number };

export interface CreateSessionTokenConfig<UserType> {
    iron_password: string;
    jwt_secret_key: string;
    sealable_user_props: SealableUserProps<UserType>;
}

const JWT_ALGORITHM = "HS256";

/**
 * Encrypts a user object, converting it to a session token string.
 */
export async function createSessionToken<UserType extends {}>(
    user: UserType,
    config: CreateSessionTokenConfig<UserType>,
    expInDays = 30
): Promise<SessionTokenResponse> {
    // Encrypt any sensitive properties (access tokens, api keys, etc.) with Iron.
    const sealedProps = await Bluebird.reduce(
        config.sealable_user_props,
        async (result, propName: keyof UserType) => {
            if (!!user[propName]) {
                try {
                    result[propName] = await seal(user[propName], config.iron_password);
                } catch (e) {
                    inspect(
                        `Failed to encrypt Iron-sealed property ${propName}. Removing property from resulting session token object.`,
                        e
                    );

                    // Prevent sending the unencrypted value to the client.
                    result[propName] = undefined;
                }
            }

            return result;
        },
        {} as SealedUserProps<UserType>
    );

    // exp: Part of the jwt spec, specifies an expiration date for the token.
    const exp = Date.now() + expInDays * 24 * 60 * 60 * 1000;
    const session: SessionToken<UserType> = {
        // Apparently typescript can't spread generic objects, even as of TS 3.0. They must be cast to any.
        // https://github.com/Microsoft/TypeScript/pull/13288
        ...(user as any),
        exp,
        ...(sealedProps as any)
    };

    return { token: encode(session, config.jwt_secret_key, JWT_ALGORITHM) };
}

export default function getRouter<UserType, ServerSettings extends object>(
    app: Express,
    config: Config<UserType, ServerSettings>
) {
    // Add configuration defaults
    config = {
        auth_header_name: "gearworks_auth",
        sealable_user_props: [],
        userAuthIsValid: async user => true,
        serverSettings: {} as ServerSettings,
        ...config
    };

    if (!config.iron_password) {
        const error = new Error(
            `gearworks-route: iron_password is required in configuration object. Encryption and decryption is impossible.`
        );

        throw error;
    }

    if (!config.jwt_secret_key) {
        const error = new Error(
            `gearworks-route: jwt_secret_key is required in configuration object. Signing JWT tokens will be impossible.`
        );

        throw error;
    }

    if (!config.shopify_secret_key) {
        const error = new Error(
            `gearworks-route: shopify_secret_key is required in configuration object. Validating Shopify requests will be impossible.`
        );

        throw error;
    }

    // Custom functions for Express request and response objects
    const withSessionToken: WithSessionTokenFunction<UserType> = async function(
        this: RouterResponse<UserType>,
        user: UserType,
        expInDays = 30
    ) {
        const token = await createSessionToken(
            user,
            {
                iron_password: config.iron_password,
                jwt_secret_key: config.jwt_secret_key,
                sealable_user_props: config.sealable_user_props || []
            },
            expInDays
        );

        return this.json<SessionTokenResponse>(token) as RouterResponse<UserType>;
    };

    // Shim the app.response and app.request objects with our custom functions
    app.response["withSessionToken"] = withSessionToken;

    // A custom routing function that handles authentication and body/query/param validation
    const route: RouterFunction<UserType> = routeConfig => {
        const method = routeConfig.method.toLowerCase();
        const requestSizeLimit = routeConfig.requestSizeLimit || 1 * 1024 * 1024 /* 1mb in bytes */;
        const corsMiddleware = routeConfig.cors ? cors() : (req, res, next) => next();
        let jsonParserMiddleware = (req, res, next) => next();
        let formParserMiddleware = (req, res, next) => next();
        let fileParserMiddleware = (req, res, next) => next();

        if (routeConfig.cors && routeConfig.method !== "all") {
            // Add an OPTIONS request handler for the path. All non-trivial CORS requests from browsers
            // send an OPTIONS preflight request.
            app.options(routeConfig.path, cors());
        }

        // Webhook validation must read the body exactly as its sent by Shopify, which is impossible when using parser middleware.
        // If the route requires validation a Shopify webhook, we'll skip parser middleware and parse it ourselves.
        if (!routeConfig.validateShopifyWebhook) {
            if (routeConfig.receivesFiles) {
                fileParserMiddleware = parseFiles({
                    limits: {
                        fileSize: requestSizeLimit
                    },
                    safeFileNames: true,
                    preserveExtension: true
                });
            }

            // Set up request body parsers
            jsonParserMiddleware = parseJson();
            formParserMiddleware = parseUrlEncoded({ extended: true, limit: requestSizeLimit });
        }

        app[method](
            routeConfig.path,
            corsMiddleware,
            jsonParserMiddleware,
            fileParserMiddleware,
            formParserMiddleware,
            async function(
                req: RouterRequest<UserType, ServerSettings>,
                res: RouterResponse<UserType>,
                next: NextFunction
            ) {
                if (res.finished) {
                    // Letting routes continue after a previous route has set headers causes more bugs than good.
                    // For example, we have two PUT routes: api/orders/ship and api/orders/:id. When the ship route finishes
                    // it sends its response, then transfers control to the next route (api/orders/:id) which tries to update
                    // the order itself and probably breaks. We almost never want that to happen, so we check here if the
                    // response has been sent and call next() if so, skipping all further routes.
                    return next();
                }

                req.domainWithProtocol =
                    `${req.protocol}://${req.hostname}` +
                    (req.hostname === "localhost" ? ":3000" : "");
                req.files = req.files || {};

                // Merge server settings with regular settings
                req.settings = {
                    ...(req.settings as any),
                    ...(config.serverSettings as any)
                };

                // Promisify the mv function on all files
                Object.keys(req.files).forEach(key => {
                    const file = req.files[key];
                    const originalMv = file.mv as (
                        destination: string,
                        cb: (err?: Error) => void
                    ) => void;

                    if (typeof file.mv !== "function") {
                        return;
                    }

                    file.mv = destination =>
                        new Promise((resolve, reject) =>
                            originalMv(destination, err => {
                                if (err) {
                                    return reject(err);
                                }

                                return resolve();
                            })
                        );
                });

                if (routeConfig.requireAuth) {
                    const header = req.header(config.auth_header_name || "gearworks_auth");
                    let decodedUser: SealedUserProps<UserType>;

                    try {
                        decodedUser = decode(header, config.jwt_secret_key, false, JWT_ALGORITHM);
                    } catch (e) {
                        return next(
                            boom.unauthorized(
                                `Missing or invalid ${config.auth_header_name ||
                                    "gearworks_auth"} header.`
                            )
                        );
                    }

                    // Ensure the decoded object is a user
                    if (!decodedUser) {
                        return next(
                            boom.unauthorized(
                                `Decoded JWT token does not appear to be a valid user object.`
                            )
                        );
                    }

                    // Decrypt sensitive Iron-sealed properties
                    const unsealedProps = await Bluebird.reduce(
                        config.sealable_user_props as (keyof UserType)[],
                        async (result, propName) => {
                            const prop = decodedUser[propName];

                            if (prop && typeof prop === "string") {
                                try {
                                    const unsealed = await unseal<UserProperty<UserType>>(
                                        prop,
                                        config.iron_password
                                    );

                                    result[propName] = unsealed;
                                } catch (e) {
                                    inspect(
                                        `Failed to decrypt Iron-sealed property ${propName}.`,
                                        e
                                    );
                                }
                            }

                            return result;
                        },
                        {} as UserType
                    );

                    // Apparently typescript can't spread generic objects, even as of TS 3.0. They must be cast to any.
                    // https://github.com/Microsoft/TypeScript/pull/13288
                    const user = {
                        ...(decodedUser as any),
                        ...(unsealedProps as any)
                    };

                    // If user id exists in invalidation cache, return a 401 unauthed response.
                    try {
                        const authIsValid = await Bluebird.resolve(config.userAuthIsValid(user));

                        if (!authIsValid) {
                            return next(
                                boom.unauthorized(
                                    `userAuthIsValid function indicates that user's JWT token is no longer valid.`
                                )
                            );
                        }
                    } catch (e) {
                        inspect(
                            `Error attempting to check if user's auth is valid. Assuming true.`,
                            e
                        );
                    }

                    req.user = user;
                }

                if (routeConfig.bodyValidation) {
                    const validation = joi.validate(req.body, routeConfig.bodyValidation, {
                        stripUnknown: true
                    });

                    if (validation.error) {
                        const error = boom.badData(
                            validation.error.message,
                            validation.error.details
                        );

                        return next(error);
                    }

                    req.validatedBody = validation.value;
                }

                if (routeConfig.queryValidation) {
                    const validation = joi.validate(req.query, routeConfig.queryValidation, {
                        stripUnknown: true
                    });

                    if (validation.error) {
                        const error = boom.badData(
                            validation.error.message,
                            validation.error.details
                        );

                        return next(error);
                    }

                    req.validatedQuery = validation.value;
                }

                if (routeConfig.paramValidation) {
                    const validation = joi.validate(req.params, routeConfig.paramValidation, {
                        stripUnknown: true
                    });

                    if (validation.error) {
                        const error = boom.badData(
                            validation.error.message,
                            validation.error.details
                        );

                        return next(error);
                    }

                    req.validatedParams = validation.value;
                }

                if (routeConfig.validateShopifyRequest) {
                    const isValid = await Auth.isAuthenticRequest(
                        req.query,
                        config.shopify_secret_key
                    );

                    if (!isValid) {
                        const error = boom.forbidden(
                            "Request does not pass Shopify's request validation scheme."
                        );

                        return next(error);
                    }
                }

                if (routeConfig.validateShopifyWebhook) {
                    // If the body is empty, there's no way to validate the webhook.
                    if (
                        req.headers["transfer-encoding"] === undefined &&
                        isNaN(req.headers["content-length"] as any)
                    ) {
                        const error = boom.forbidden(
                            "Request does not pass Shopify's webhook validation scheme."
                        );
                        inspect(
                            "Webhook body appears to be empty and cannot be validated. Headers:",
                            req.headers
                        );

                        return next(error);
                    }

                    // To validate a webhook request, we must read the raw body as it was sent by Shopify — not the parsed body.
                    const rawBody = await new Bluebird<string>((res, rej) => {
                        let body: string = "";

                        req.on("data", chunk => (body += chunk));
                        req.on("end", () => res(body));
                    });

                    const isValid = await Auth.isAuthenticWebhook(
                        req.headers,
                        rawBody,
                        config.shopify_secret_key
                    );

                    if (!isValid) {
                        const error = boom.forbidden(
                            "Request does not pass Shopify's webhook validation scheme."
                        );

                        return next(error);
                    }

                    if (req.header("content-type") === "application/json") {
                        req.body = JSON.parse(rawBody);
                    }
                }

                if (routeConfig.validateShopifyProxyPage) {
                    const isValid = await Auth.isAuthenticProxyRequest(
                        req.query,
                        config.shopify_secret_key
                    );

                    if (!isValid) {
                        const error = boom.forbidden(
                            "Request does not pass Shopify's proxy page validation scheme."
                        );

                        return next(error);
                    }
                }

                // Pass control to the route's handler. Handlers can be async, so wrap them in a bluebird resolve which can catch unhandled promise rejections.
                Bluebird.resolve(routeConfig.handler(req, res, next)).catch(e => {
                    return next(e);
                });
            }
        );
    };

    return route;
}
