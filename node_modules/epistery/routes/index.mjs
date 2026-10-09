import express from "express";

// Import all route modules
import statusRoutes from "./status.mjs";
import connectRoutes from "./connect.mjs";
import fidoRoutes from "./fido.mjs";

/**
 * Creates and configures all Epistery routes
 *
 * Route structure:
 *   /                     - Status (JSON)
 *   /lib/:module          - Client library files
 *   /artifacts/:file      - Contract artifacts
 *   /connect              - Key exchange (binds a rivet to its IdentityContract)
 *   /fido/*               - FIDO PRF-wrapped rivet key blob storage
 *
 * @param {Object} epistery - The EpisteryAttach instance
 * @returns {express.Router}
 */
export default function createRoutes(epistery) {
  const router = express.Router();

  // Status routes (/, /lib/:module, /artifacts/:contractFile)
  router.use(statusRoutes(epistery));

  // Connect routes (/connect)
  router.use(connectRoutes(epistery));

  // FIDO routes (/fido/blob — PRF-wrapped rivet private key storage)
  router.use("/fido", fidoRoutes(epistery));

  return router;
}