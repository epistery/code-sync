import express from "express";

/**
 * FIDO routes — store and retrieve encrypted (PRF-wrapped) rivet private keys.
 *
 * The blob is AES-GCM ciphertext, encrypted on the client with a key derived
 * from a WebAuthn PRF output. The server holds ciphertext only; the
 * decryption key never leaves the user's device. Existence of the blob is
 * not sensitive — without the FIDO credential it cannot be decrypted.
 *
 * Endpoints:
 *   POST /fido/blob            - Store blob keyed by credential ID
 *   GET  /fido/blob/:credId    - Retrieve blob by credential ID
 *
 * Storage: under the domain config path /{domain}/fido/{credentialId}.json
 *
 * Auth model (v1): anonymous read/write. The blob is encrypted; the only
 * abuse vector is storage spam, which we limit by validating shape and
 * rejecting oversized payloads. Production deployments should gate writes
 * behind a host-side authorization check.
 *
 * @param {Object} epistery - The EpisteryAttach instance
 * @returns {express.Router}
 */
export default function fidoRoutes(epistery) {
  const router = express.Router();

  // base64url charset, length-bounded to keep filenames sane
  const isValidCredId = (s) =>
    typeof s === "string" && s.length > 0 && s.length <= 512 && /^[A-Za-z0-9_-]+$/.test(s);

  const isHexAddress = (s) =>
    typeof s === "string" && /^0x[a-fA-F0-9]{40}$/.test(s);

  const isHexString = (s) =>
    typeof s === "string" && /^0x[a-fA-F0-9]+$/.test(s) && s.length <= 4096;

  // Body parser scoped here so we don't expand global limits
  const json = express.json({ limit: "16kb" });

  router.post("/blob", json, async (req, res) => {
    try {
      const { credentialId, rivetAddress, publicKey, ciphertext, iv, label } =
        req.body || {};

      if (!isValidCredId(credentialId)) {
        return res.status(400).json({ error: "Invalid credentialId" });
      }
      if (!isHexAddress(rivetAddress)) {
        return res.status(400).json({ error: "Invalid rivetAddress" });
      }
      if (!isHexString(publicKey)) {
        return res.status(400).json({ error: "Invalid publicKey" });
      }
      if (!isHexString(ciphertext)) {
        return res.status(400).json({ error: "Invalid ciphertext" });
      }
      if (!isHexString(iv)) {
        return res.status(400).json({ error: "Invalid iv" });
      }

      const domain = epistery.domainName;
      if (!domain) {
        return res.status(500).json({ error: "Domain not set" });
      }

      await epistery.config.setPath(`/${domain}/fido`);
      await epistery.config.writeFile(
        `${credentialId}.json`,
        JSON.stringify({
          credentialId,
          rivetAddress,
          publicKey,
          ciphertext,
          iv,
          label: typeof label === "string" ? label.slice(0, 128) : undefined,
          createdAt: new Date().toISOString(),
        }),
      );

      res.json({ stored: true, credentialId, rivetAddress });
    } catch (error) {
      console.error("[fido] Blob store error:", error);
      res.status(500).json({ error: error.message });
    }
  });

  router.get("/blob/:credentialId", async (req, res) => {
    try {
      const { credentialId } = req.params;
      if (!isValidCredId(credentialId)) {
        return res.status(400).json({ error: "Invalid credentialId" });
      }

      const domain = epistery.domainName;
      if (!domain) {
        return res.status(500).json({ error: "Domain not set" });
      }

      await epistery.config.setPath(`/${domain}/fido`);

      let buf;
      try {
        buf = await epistery.config.readFile(`${credentialId}.json`);
      } catch (e) {
        return res.status(404).json({ error: "Blob not found" });
      }

      const blob = JSON.parse(buf.toString("utf8"));
      res.json(blob);
    } catch (error) {
      console.error("[fido] Blob retrieve error:", error);
      res.status(500).json({ error: error.message });
    }
  });

  return router;
}