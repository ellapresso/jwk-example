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
  const ks = fs.readFileSync("keys.json");
  const temp = JSON.parse(ks);

  const keyStore = jose.JWK.createKeyStore();

  keyStore.generate("RSA", 2048, { alg: "RS256", use: "sig" }).then(result => {
    const newKey = keyStore.toJSON(true);
    newKey.keys.push(temp.keys[0]);
    fs.writeFileSync("Keys.json", JSON.stringify(newKey, null, "  "));
  });
  res.sendStatus(200);
});

app.get("/jwks", async (req, res) => {
  const ks = fs.readFileSync("keys.json") || { keys: [] };

  const keyStore = ks.keys.length
    ? await jose.JWK.asKeyStore(ks.toString())
    : "{keys:[]}";

  res.send(keyStore);
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
    "eyJ0eXAiOiJqd3QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImhwUnFvSUtIU0pVUE94eHhkZ1BzbU8yaTF3dWp6cjF0cTBOMXlGVlREdmcifQ.eyJleHAiOjE2NjA2MTcyMTYsImlhdCI6MTY2MDYxNzE4MCwic3ViIjoidGVzdCJ9.HVOWSsSRZ9W4kWTofYLC09iWI7huH_L8IuziskXX_xuVRb8uaHMCU8oLE7I9j4u_tSyiND1y2EVOIE4GH3pYwzQNayCr_T1ExEBNdXt_0PtjutKfbIOvaSxKx3D09wbtUzqBdV71Np5oR6Cj0Dlys7cW8yaiGQ3BVr1tpqA1pR-YNRihdQE9Tc7raqnCp8tYz4iEmVw2Hiz9WFjpQweSGf0Ss1pwpTX-6UIu4V7XgQZN2cAdHfEZ1oyqI3k-ARkLnawIfaViMt7wuVEwtnIiPPs5699c6dPzy291FEgDnIzHun21acJ9OoARb_fVdlQI4A2VwvKFgeJYlQVYf5C_sg";

  let decodedToken = jwt.decode(token, { complete: true });

  const kid = decodedToken.header.kid;
  const ks = fs.readFileSync("keys.json");
  const keyStore = await jose.JWK.asKeyStore(ks.toString());
  const jwksResponse = keyStore.toJSON();
  const publicKey = jwktopem(_.find(jwksResponse.keys, { kid }));

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
