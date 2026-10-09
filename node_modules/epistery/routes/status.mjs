import express from "express";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");

/**
 * Status routes - root, status page, client libraries, contract artifacts
 * @param {Object} epistery - The EpisteryAttach instance
 * @returns {express.Router}
 */
export default function statusRoutes(epistery) {
  const router = express.Router();

  // Root endpoint — JSON server status only. Witness.connect() probes this with
  // Accept: json for chain/provider info. Epistery serves machine endpoints under
  // its .well-known path; it deliberately provides no HTML UI.
  router.get("/", (req, res) => {
    res.json(epistery.buildStatus());
  });

  // Client library files
  const library = {
    "client.js": path.resolve(rootDir, "client/client.js"),
    "witness.js": path.resolve(rootDir, "client/witness.js"),
    "tab.js": path.resolve(rootDir, "client/tab.js"),
    "wallet.js": path.resolve(rootDir, "client/wallet.js"),
    "ethers.js": path.resolve(rootDir, "client/ethers.js"),
    "ethers.min.js": path.resolve(rootDir, "client/ethers.min.js"),
    // The wire, browser-importable (pure ESM): witness.js imports the
    // key-exchange message; hosts import the rest by these names.
    "key-exchange-message.mjs": path.resolve(rootDir, "client/key-exchange-message.mjs"),
    "peer-cipher.mjs": path.resolve(rootDir, "client/peer-cipher.mjs"),
    "bot-auth-message.mjs": path.resolve(rootDir, "client/bot-auth-message.mjs"),
    "storage-message.mjs": path.resolve(rootDir, "client/storage-message.mjs"),
    "boost-message.mjs": path.resolve(rootDir, "client/boost-message.mjs"),
    "origin-certificate.mjs": path.resolve(rootDir, "client/origin-certificate.mjs"),
    "chain-read.mjs": path.resolve(rootDir, "client/chain-read.mjs"),
  };

  // Serve client library files
  router.get("/lib/:module", (req, res) => {
    const modulePath = library[req.params.module];
    if (!modulePath) return res.status(404).send("Library not found");

    if (!fs.existsSync(modulePath))
      return res.status(404).send("File not found");

    const ext = modulePath.slice(modulePath.lastIndexOf(".") + 1);
    const contentTypes = {
      js: "text/javascript",
      mjs: "text/javascript",
      css: "text/css",
      html: "text/html",
      json: "application/json",
    };

    if (contentTypes[ext]) {
      res.set("Content-Type", contentTypes[ext]);
    }

    res.sendFile(modulePath);
  });

  // Serve contract artifacts
  router.get("/artifacts/:contractFile", (req, res) => {
    const contractFile = req.params.contractFile;
    const artifactPath = path.resolve(
      rootDir,
      "artifacts/contracts",
      contractFile.replace(".json", ".sol"),
      contractFile,
    );

    if (!fs.existsSync(artifactPath)) {
      return res.status(404).send("Contract artifact not found");
    }

    res.set("Content-Type", "application/json");
    res.sendFile(artifactPath);
  });

  return router;
}
