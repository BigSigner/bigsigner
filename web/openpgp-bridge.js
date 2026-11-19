/* OpenPGP.js for the browser emulator. The device keeps the gpg command. */

import * as openpgp from "./external-assets/openpgp/openpgp.min.mjs";

const VERSION = "OpenPGP.js 6.3.0";
const CONFIG = {
  v6Keys: false,
  preferredHashAlgorithm: openpgp.enums.hash.sha256,
  preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes256,
  nonDeterministicSignaturesViaNotation: false,
  allowMissingKeyFlags: true,
};
const ring = new Map();

export async function handle(request) {
  try {
    return {ok: true, ...(await dispatch(request || {}))};
  } catch (error) {
    return {ok: false, error: (error && error.message) || String(error)};
  }
}

async function dispatch(request) {
  if (request.op === "version") return {version: VERSION};
  if (request.op === "list") return {keys: await Promise.all([...ring.values()].map(describe))};
  if (request.op === "inspect") return {keys: await Promise.all((await loadKeys(request)).map(describe))};
  if (request.op === "import") {
    const keys = await loadKeys(request);
    for (const key of keys) await store(key);
    return {keys: await Promise.all([...ring.values()].map(describe))};
  }
  if (request.op === "delete") return deleteKey(request.fingerprint);
  if (request.op === "export") return exportKey(request.fingerprint, request.secret, request.subkey);
  if (request.op === "add-subkey") return addSubkey(request);
  if (request.op === "sign") return sign(request);
  if (request.op === "verify-detached") return verifyDetached(request);
  if (request.op === "verify-cleartext") return verifyCleartext(request);
  if (request.op === "encrypt") return encrypt(request);
  throw new Error("The GPG command is not available in the web emulator.");
}

async function loadKeys(request) {
  const config = CONFIG;
  if (request.armored) return openpgp.readKeys({armoredKeys: request.armored, config});
  if (request.binary) return openpgp.readKeys({binaryKeys: bytes(request.binary), config});
  throw new Error("The GPG key could not be read.");
}

async function deleteKey(fingerprint) {
  const want = String(fingerprint || "").toUpperCase();
  if (!/^[0-9A-F]{32}$|^[0-9A-F]{40}$|^[0-9A-F]{64}$/.test(want)) {
    throw new Error("The key fingerprint is not valid.");
  }
  for (const key of ring.values()) {
    if ((await key.getFingerprint()).toUpperCase() === want) {
      ring.delete(want);
      return {};
    }
  }
  throw new Error("The GPG key could not be deleted.");
}

async function store(key) {
  const fingerprint = (await key.getFingerprint()).toUpperCase();
  const existing = ring.get(fingerprint);
  if (existing && existing.isPrivate() && !key.isPrivate()) return existing;
  ring.set(fingerprint, key);
  return key;
}

async function locate(fingerprint) {
  const want = String(fingerprint || "").toUpperCase();
  for (const key of ring.values()) {
    if ((await key.getFingerprint()).toUpperCase() === want) return {key, packet: key.keyPacket, sub: null};
    for (const sub of key.subkeys || []) {
      if ((await sub.getFingerprint()).toUpperCase() === want) return {key, packet: sub.keyPacket, sub};
    }
  }
  throw new Error("The key is not loaded.");
}

async function exportKey(fingerprint, secret, subkey) {
  const found = await locate(fingerprint);
  if (subkey) {
    if (!found.sub || !secretStatus(found.sub.keyPacket).containsPrivate) {
      throw new Error("The subkey could not be exported.");
    }
    return {
      armor: await text(found.key.armor(CONFIG)),
      primary: (await found.key.getFingerprint()).toUpperCase(),
      sub: (await found.sub.getFingerprint()).toUpperCase(),
      patch: true,
    };
  }
  if (secret) {
    if (!found.key.isPrivate() || !secretStatus(found.key.keyPacket).containsPrivate) {
      throw new Error("The key could not be exported.");
    }
    return {armor: await text(found.key.armor(CONFIG)), patch: false};
  }
  return {armor: await text(found.key.toPublic().armor(CONFIG)), patch: false};
}

async function addSubkey(request) {
  const found = await locate(request.fingerprint);
  const packet = found.key.keyPacket;
  if (!found.key.isPrivate() || (typeof packet.isDummy === "function" && packet.isDummy()) || !packet.isDecrypted()) {
    throw new Error("Adding a subkey requires the certificate's private key.");
  }
  const algo = request.algo;
  const usage = request.usage;
  if ((algo === "cv25519" && usage !== "encr") || (algo === "ed25519" && usage === "encr")) {
    throw new Error("The subkey choice is not valid.");
  }
  const date = new Date(Number(request.timestamp) * 1000);
  const expireSeconds = expirationSeconds(date, request.expire);
  const options = {
    type: String(algo).startsWith("rsa") ? "rsa" : "ecc",
    curve: algo === "cv25519" ? "curve25519Legacy" : "ed25519Legacy",
    sign: usage !== "encr",
    date,
    keyExpirationTime: expireSeconds,
    config: CONFIG,
  };
  if (options.type === "rsa") options.rsaBits = algo === "rsa3072" ? 3072 : 4096;
  let updated = await found.key.addSubkey(options);
  if (usage === "auth") updated = await authenticationBinding(updated, date, expireSeconds);
  const fingerprint = (await updated.getFingerprint()).toUpperCase();
  ring.set(fingerprint, updated);
  return {keys: [await describe(updated)]};
}

async function authenticationBinding(key, date, expireSeconds) {
  const items = [...key.toPacketList()];
  const subPacket = items[items.length - 2];
  const signature = new openpgp.SignaturePacket();
  signature.signatureType = openpgp.enums.signature.subkeyBinding;
  signature.keyFlags = [openpgp.enums.keyFlags.authentication];
  signature.publicKeyAlgorithm = subPacket.algorithm;
  signature.hashAlgorithm = openpgp.enums.hash.sha256;
  if (expireSeconds > 0) {
    signature.keyExpirationTime = expireSeconds;
    signature.keyNeverExpires = false;
  }
  await signature.sign(key.keyPacket, {key: key.keyPacket, bind: subPacket}, date, false, CONFIG);
  const list = new openpgp.PacketList();
  items.slice(0, -1).forEach((item) => list.push(item));
  list.push(signature);
  return new openpgp.PrivateKey(list);
}

async function sign(request) {
  const found = await locate(request.fingerprint);
  const status = secretStatus(found.packet);
  if (!status.secretAvailable) {
    throw new Error(status.needsPassphrase
      ? "Signing a file requires a key with no passphrase."
      : "Signing a file requires this key's private key.");
  }
  const message = await openpgp.createMessage({binary: bytes(request.data)});
  const armored = await openpgp.sign({
    message,
    signingKeys: found.key,
    signingKeyIDs: [await keyIdentifier(found.sub || found.key)],
    detached: true,
    format: "armored",
    date: new Date(Number(request.timestamp) * 1000),
    config: CONFIG,
  });
  return {armor: await text(armored)};
}

async function verifyDetached(request) {
  const message = await openpgp.createMessage({binary: bytes(request.data)});
  const signature = await openpgp.readSignature({armoredSignature: request.armored});
  const result = await openpgp.verify({
    message,
    signature,
    verificationKeys: publicKeys(),
    expectSigned: true,
    date: new Date(Number(request.timestamp) * 1000),
    format: "utf8",
    config: CONFIG,
  });
  await accepted(result.signatures);
  return {};
}

async function verifyCleartext(request) {
  const message = await openpgp.readCleartextMessage({cleartextMessage: request.armored});
  const result = await openpgp.verify({
    message,
    verificationKeys: publicKeys(),
    expectSigned: true,
    date: new Date(Number(request.timestamp) * 1000),
    format: "utf8",
    config: CONFIG,
  });
  await accepted(result.signatures);
  const data = typeof result.data === "string" ? result.data : new TextDecoder().decode(result.data);
  return {text: data};
}

async function encrypt(request) {
  const encryptionKeys = [];
  const encryptionKeyIDs = [];
  for (const fingerprint of request.fingerprints || []) {
    const found = await locate(fingerprint);
    encryptionKeys.push(found.key.toPublic());
    encryptionKeyIDs.push(await keyIdentifier(found.sub || found.key));
  }
  if (!encryptionKeys.length) throw new Error("Select an encryption key.");
  const message = await openpgp.createMessage({binary: bytes(request.data)});
  const armored = await openpgp.encrypt({
    message,
    encryptionKeys,
    encryptionKeyIDs,
    format: "armored",
    config: CONFIG,
  });
  return {armor: await text(armored)};
}

function publicKeys() {
  return [...ring.values()].map((key) => key.toPublic());
}

async function accepted(signatures) {
  if (!signatures || !signatures.length) throw new Error("Signature verification failed.");
  await Promise.all(signatures.map((signature) => signature.verified));
}

function keyIdentifier(key) {
  return key.getKeyID();
}

async function describe(key) {
  const fingerprint = (await key.getFingerprint()).toUpperCase();
  let expires = "Never";
  try {
    expires = formatDate(await key.getExpirationTime());
  } catch (error) {
    expires = "Never";
  }
  const subkeys = [];
  for (const sub of key.subkeys || []) {
    const subFingerprint = (await sub.getFingerprint()).toUpperCase();
    let subExpires = "Never";
    try {
      subExpires = formatDate(await sub.getExpirationTime());
    } catch (error) {
      subExpires = "Never";
    }
    const status = secretStatus(sub.keyPacket);
    subkeys.push({
      fingerprint: subFingerprint,
      keyId: subFingerprint.slice(-16),
      algorithm: algorithmText(sub.keyPacket.getAlgorithmInfo()),
      created: formatDate(sub.keyPacket.created),
      expires: subExpires,
      validity: "Unknown",
      capabilities: flagText((sub.bindingSignatures || []).at(-1)),
      secret: status.secret,
      secretAvailable: status.secretAvailable,
      containsPrivate: status.containsPrivate,
      needsPassphrase: status.needsPassphrase,
    });
  }
  const status = secretStatus(key.keyPacket);
  return {
    fingerprint,
    keyId: fingerprint.slice(-16),
    algorithm: algorithmText(key.getAlgorithmInfo()),
    created: formatDate(await key.getCreationTime()),
    expires,
    validity: "Unknown",
    userIds: await key.getUserIDs(),
    capabilities: primaryFlags(key),
    secret: status.secret,
    secretAvailable: status.secretAvailable,
    containsPrivate: status.containsPrivate,
    needsPassphrase: status.needsPassphrase,
    subkeys,
  };
}

function primaryFlags(key) {
  for (const user of key.users || []) {
    const certificates = user.selfCertifications || [];
    if (certificates.length) return flagText(certificates.at(-1));
  }
  return "";
}

function flagText(signature) {
  const bits = signature && signature.keyFlags && signature.keyFlags.length ? Number(signature.keyFlags[0]) : 0;
  let text = "";
  if (bits & 0x01) text += "c";
  if (bits & 0x02) text += "s";
  if (bits & 0x0c) text += "e";
  if (bits & 0x20) text += "a";
  return text;
}

function secretStatus(packet) {
  // A public packet implements isDecrypted and returns null. isDummy exists only on secret packets.
  if (!packet || typeof packet.isDecrypted !== "function" || packet.isDecrypted() === null) {
    return {secret: false, secretAvailable: false, containsPrivate: false, needsPassphrase: false};
  }
  if (typeof packet.isDummy === "function" && packet.isDummy()) {
    return {secret: true, secretAvailable: false, containsPrivate: false, needsPassphrase: false};
  }
  const decrypted = packet.isDecrypted();
  return {secret: true, secretAvailable: true, containsPrivate: true, needsPassphrase: !decrypted};
}

function algorithmText(info) {
  const algo = String((info && info.algorithm) || "");
  let label = algo;
  if (algo === "eddsaLegacy") label = "EdDSA";
  else if (algo === "ed25519") label = "Ed25519";
  else if (algo === "ecdh") label = "ECDH";
  else if (algo === "x25519") label = "X25519";
  else if (algo === "ecdsa") label = "ECDSA";
  else if (algo.toLowerCase().startsWith("rsa")) label = "RSA";
  else if (algo === "dsa") label = "DSA";
  else if (algo === "elgamal") label = "ElGamal";
  const assumed = label === "EdDSA" || label === "ECDH" || label === "Ed25519" || label === "X25519" ? 255 : 0;
  const bits = (info && info.bits) || assumed;
  return bits ? `${label} (${bits} bits)` : (label || "Unknown");
}

function formatDate(value) {
  if (value == null || value === Infinity) return "Never";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "Never";
  const pad = (number) => String(number).padStart(2, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`;
}

function expirationSeconds(created, expire) {
  if (!expire || expire === "never") return 0;
  const match = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})$/.exec(expire);
  if (!match) throw new Error("The subkey expiration is not valid.");
  const instant = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6]));
  const seconds = Math.floor((instant - created.getTime()) / 1000);
  if (seconds <= 0) throw new Error("The expiration is not after the creation time.");
  return seconds;
}

function bytes(value) {
  const binary = atob(value || "");
  const data = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) data[index] = binary.charCodeAt(index);
  return data;
}

async function text(value) {
  if (typeof value === "string") return value;
  if (value && typeof value.getReader === "function") {
    const reader = value.getReader();
    const chunks = [];
    while (true) {
      const step = await reader.read();
      if (step.done) break;
      chunks.push(typeof step.value === "string" ? step.value : new TextDecoder().decode(step.value));
    }
    return chunks.join("");
  }
  return String(await value);
}

globalThis.bigsignerOpenpgp = (json) => handle(JSON.parse(json)).then((value) => JSON.stringify(value));
