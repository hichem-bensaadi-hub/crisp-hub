const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const HUB_PASSWORD = process.env.HUB_PASSWORD || "";
const COOKIE_NAME = "hub_auth";
const DAY = 24 * 60 * 60;

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i === -1) return;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

function isAuthed(req) {
  if (!HUB_PASSWORD) return true; // pas de mot de passe configuré = accès libre (fallback safe, comme les autres projets Crisp)
  const cookies = parseCookies(req);
  return cookies[COOKIE_NAME] === sha256(HUB_PASSWORD);
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
  });
}

function serveFile(res, filePath, contentType) {
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }
    res.writeHead(200, { "Content-Type": contentType });
    res.end(content);
  });
}

function renderLogin(error) {
  const errorBlock = error
    ? `<div class="error">Mot de passe incorrect.</div>`
    : "";
  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>cRISp — Hub</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #0a0a0a;
    color: #f4f4f4;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  form {
    background: #18181b;
    border: 1px solid #27272a;
    border-radius: 16px;
    padding: 32px 28px;
    width: 100%;
    max-width: 320px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  h1 {
    font-size: 1.1rem;
    text-align: center;
    margin-bottom: 6px;
    letter-spacing: 0.02em;
  }
  input {
    background: #0a0a0a;
    border: 1px solid #27272a;
    border-radius: 10px;
    color: #f4f4f4;
    padding: 12px 14px;
    font-size: 1rem;
  }
  input:focus { outline: none; border-color: #FFC30C; }
  button {
    background: #FFC30C;
    color: #0a0a0a;
    border: none;
    border-radius: 10px;
    padding: 12px 14px;
    font-size: 0.95rem;
    font-weight: 700;
    cursor: pointer;
  }
  .error {
    color: #f87171;
    font-size: 0.82rem;
    text-align: center;
  }
</style>
</head>
<body>
  <form method="POST" action="/login">
    <h1>🐔 Chicken Hub</h1>
    ${errorBlock}
    <input type="password" name="password" placeholder="Mot de passe" autofocus required />
    <button type="submit">Entrer</button>
  </form>
</body>
</html>`;
}

function renderCredentialsTable() {
  let entries = [];
  try {
    entries = JSON.parse(process.env.HUB_CREDENTIALS || "[]");
  } catch {
    entries = [];
  }

  const rows = entries
    .map(
      (e) => `
        <tr>
          <td class="service">${e.service || ""}</td>
          <td>${e.label || ""}<div class="hint">${e.hint || ""}</div></td>
          <td class="value-cell">
            <code class="value" data-value="${(e.value || "").replace(/"/g, "&quot;")}">••••••••</code>
            <button class="reveal" type="button">👁</button>
            <button class="copy" type="button">Copier</button>
          </td>
        </tr>`
    )
    .join("");

  const noAuthNote = `
    <tr class="no-auth-row">
      <td class="service">Crisp Kiosk / Crisp Compta / Crisp Food Cost</td>
      <td>Aucune protection</td>
      <td class="value-cell"><span class="no-auth">pas de mot de passe configuré côté code</span></td>
    </tr>`;

  return rows + noAuthNote;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === "/login" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(renderLogin(false));
    return;
  }

  if (url.pathname === "/login" && req.method === "POST") {
    const body = await readBody(req);
    const params = new URLSearchParams(body);
    const password = params.get("password") || "";
    if (HUB_PASSWORD && password === HUB_PASSWORD) {
      res.writeHead(302, {
        "Set-Cookie": `${COOKIE_NAME}=${sha256(HUB_PASSWORD)}; Path=/; Max-Age=${90 * DAY}; HttpOnly; SameSite=Lax`,
        Location: "/",
      });
      res.end();
    } else {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderLogin(true));
    }
    return;
  }

  if (url.pathname === "/logout") {
    res.writeHead(302, {
      "Set-Cookie": `${COOKIE_NAME}=; Path=/; Max-Age=0`,
      Location: "/login",
    });
    res.end();
    return;
  }

  // Logo servi sans auth (juste une image, sert aussi sur la page de login si besoin plus tard)
  if (url.pathname === "/crisp-logo.jpg") {
    serveFile(res, path.join(__dirname, "crisp-logo.jpg"), "image/jpeg");
    return;
  }

  if (!isAuthed(req)) {
    res.writeHead(302, { Location: "/login" });
    res.end();
    return;
  }

  if (url.pathname === "/" || url.pathname === "/index.html") {
    serveFile(res, path.join(__dirname, "index.html"), "text/html; charset=utf-8");
    return;
  }

  if (url.pathname === "/mots-de-passe") {
    fs.readFile(path.join(__dirname, "mots-de-passe.html"), "utf8", (err, template) => {
      if (err) {
        res.writeHead(500);
        res.end("Erreur");
        return;
      }
      const html = template.replace("<!--CREDENTIALS-->", renderCredentialsTable());
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(html);
    });
    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Crisp Hub listening on ${PORT}`);
  if (!HUB_PASSWORD) {
    console.warn("⚠️  HUB_PASSWORD non défini — le hub est accessible sans mot de passe.");
  }
});
