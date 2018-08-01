import router from "./";
import { Config } from "./";
import express = require("express");

interface User {
    id: string;
    rev: string;
    name: string;
}

interface ServerSettings {
    cityName: "Teldrassil" | "Undercity";
}

const route = router<User, ServerSettings>(express(), {
    iron_password: "test",
    jwt_secret_key: "test",
    shopify_secret_key: "",
    onBeforeRequest: (req, res, next) => {},
    serverSettings: {
        cityName: "Teldrassil"
    }
});

route({
    path: "",
    method: "post",
    handler: async (req, res, next) => {}
});
