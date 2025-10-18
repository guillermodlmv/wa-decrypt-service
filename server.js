// server.js
import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
app.use(express.json({ limit: "30mb" }));

/**
 * Protege el endpoint con una API key simple (establecer API_KEY en Render).
 */
function requireApiKey(req, res, next) {
  const key = req.headers["x-api-key"] || req.query.api_key;
  if (!process.env.API_KEY) return res.status(500).json({ error: "API_KEY not configured on server" });
  if (!key || key !== process.env.API_KEY) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function deriveKeys(mediaKeyBase64) {
  const mediaKey = Buffer.from(mediaKeyBase64, "base64");
  const info = Buffer.concat([
    Buffer.from("WhatsApp Audio Keys", "utf8"),
    Buffer.alloc(1, 0x01),
  ]);
  const hash = crypto.createHmac("sha256", mediaKey).update(info).digest();
  return {
    iv: hash.subarray(0, 16),
    cipherKey: hash.subarray(16, 48),
  };
}

app.post("/decrypt", requireApiKey, async (req, res) => {
  try {
    const { url, mediaKey } = req.body;
    if (!url || !mediaKey) return res.status(400).json({ error: "Missing 'url' or 'mediaKey' in body" });

    // Descargar el archivo cifrado (.enc)
    const encResponse = await fetch(url);
    if (!encResponse.ok) return res.status(502).json({ error: "Failed to download media", status: encResponse.status });
    const encArrayBuffer = await encResponse.arrayBuffer();
    const encBuffer = Buffer.from(encArrayBuffer);

    // Derivar claves y descifrar
    const { iv, cipherKey } = deriveKeys(mediaKey);
    const decipher = crypto.createDecipheriv("aes-256-cbc", cipherKey, iv);
    const decrypted = Buffer.concat([decipher.update(encBuffer), decipher.final()]);

    // Responder con base64 (n8n lo convertirá a binario)
    res.json({
      success: true,
      audio_base64: decrypted.toString("base64"),
      mimetype: "audio/ogg"
    });
  } catch (err) {
    console.error("decrypt error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Healthcheck
app.get("/health", (req, res) => res.json({ ok: true }));

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`Decrypt service listening on port ${port}`));
