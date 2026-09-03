const FRONTEND_URL = process.env.FRONTEND_URL || "";
const NODE_ENV = process.env.NODE_ENV || "development";
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_PRODUCTION";

if (NODE_ENV === "production" && JWT_SECRET === "CHANGE_ME_IN_PRODUCTION") {
  throw new Error("JWT_SECRET doit être défini en production.");
}

module.exports = { FRONTEND_URL, NODE_ENV, PORT, JWT_SECRET };
