const express = require("express");
const app = express();
const fs = require("fs");
const jose = require("node-jose");
const jwt = require("jsonwebtoken");
const jwktopem = require("jwk-to-pem");
const _ = require("lodash");
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

app.get("/", async (req, res) => {
  const fs = require("fs");

  const jose = require("node-jose");

  const keyStore = jose.JWK.createKeyStore();

  keyStore.generate("RSA", 2048, { alg: "RS256", use: "sig" }).then(result => {
    fs.writeFileSync(
      "Keys.json",
      JSON.stringify(keyStore.toJSON(true), null, "  ")
    );
  });
  res.sendStatus(200);
});

app.get("/jwks", async (req, res) => {
  const ks = fs.readFileSync("keys.json");

  const keyStore = await jose.JWK.asKeyStore(ks.toString());

  res.send(keyStore.toJSON());
});

app.get("/tokens", async (req, res) => {
  const JWKeys = fs.readFileSync("keys.json");

  const keyStore = await jose.JWK.asKeyStore(JWKeys.toString());

  const [key] = keyStore.all({ use: "sig" });

  const opt = { compact: true, jwk: key, fields: { typ: "jwt" } };

  const payload = JSON.stringify({
    exp: Math.floor((Date.now() + 36000) / 1000),
    iat: Math.floor(Date.now() / 1000),
    sub: "test",
  });

  const token = await jose.JWS.createSign(opt, key).update(payload).final();

  res.send({ token });
});

app.get("/verify", async (req, res) => {
  let resourcePath = "/jwks";

  let token =
    "eyJ0eXAiOiJqd3QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjJzZmtNN2F1VllhQlZrbGU0d0hPai1fNElFTV9qNHVYbEFyVUhORUk5V3cifQ.eyJleHAiOjE2NjAyOTkyMjEsImlhdCI6MTY2MDI5OTE4NSwic3ViIjoidGVzdCJ9.v_7S4ux8bHo67IhgCA2H1176_xwm3eKAeW_Bm3bY-Zfrs9VCtCAeF3PVEOihZXSPhPlpTJhs6DTjS0EqisjHwb5fKsS657ZsKTgE9VeLgoTAg4IiFT9GHqgo9i-L0Y6x5YYe6qPqMBy__wL_sBcqqSktwBgozWmSPni5-zw7uZMk7db_e3OspYkfmzBykAPiZWtT1a2WF19Rt8iRuhhY4npCwQmUQeBalO-j7GJrFgWBJHR2BpGf3D9q5cnmidm8Ithjw-vpxcuxQ9PRUf5oXt9LhWSNITP9rBPz2qX_PESKyFoce6bnHm5-pHJ-wvOBUgPa22ez3tZ_eSZh1YLzug";

  let decodedToken = jwt.decode(token, { complete: true });

  let kid = decodedToken.header.kid;
  const ks = fs.readFileSync("keys.json");
  const keyStore = await jose.JWK.asKeyStore(ks.toString());
  const jwksResponse = keyStore.toJSON();
  const firstKey = jwksResponse.keys[0];
  const publicKey = jwktopem(firstKey);
  try {
    const decoded = jwt.verify(token, publicKey);
    res.send(decoded);
  } catch (e) {
    console.error(e);
  }
});

app.listen(4703, () => {
  console.log("server is running..");
});
