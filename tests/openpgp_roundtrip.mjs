/* Cross-check the emulator bridge with the gpg on this machine. */

import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { handle } from "../web/openpgp-bridge.js";

const dir = process.argv[2];
const home = join(dir, "gnupg");
mkdirSync(home, {recursive: true});
const env = {...process.env, GNUPGHOME: home, LC_ALL: "C", LANG: "C", TZ: "UTC"};

function gpg(args, input) {
  const result = spawnSync("gpg", ["--batch", "--pinentry-mode", "loopback", "--passphrase", "", ...args], {
    input,
    env,
    encoding: "buffer",
  });
  if (result.status !== 0) {
    throw new Error(result.stderr.toString() || result.stdout.toString() || "gpg failed");
  }
  return result.stdout;
}

function text(value) {
  return Buffer.isBuffer(value) ? value.toString("utf8") : String(value);
}

const stamp = Math.floor(Date.now() / 1000);
gpg(["--faked-system-time", String(stamp), "--quick-gen-key", "Round <round@example.invalid>", "ed25519", "cert", "never"]);
const primary = fingerprintOf(gpg(["--with-colons", "--list-keys"]));
gpg(["--faked-system-time", String(stamp), "--quick-add-key", primary, "ed25519", "sign", "never"]);
gpg(["--faked-system-time", String(stamp), "--quick-add-key", primary, "cv25519", "encrypt", "never"]);
const secretList = text(gpg(["--with-colons", "--with-fingerprint", "--list-secret-keys"]));
const signing = subFingerprint(secretList, "s");
const encryption = subFingerprint(secretList, "e");
const note = Buffer.from("hello airgap\n");
writeFileSync(join(dir, "note.bin"), note);
gpg(["--faked-system-time", String(stamp), "--local-user", `${signing}!`, "--armor", "--detach-sign", "--output", join(dir, "gpg-signature.asc"), join(dir, "note.bin")]);
gpg(["--clearsign", "--faked-system-time", String(stamp), "--local-user", `${signing}!`, "--output", join(dir, "gpg-clear.asc"), join(dir, "note.bin")]);

const secretArmor = text(gpg(["--armor", "--export-secret-keys", primary]));
const preview = await handle({op: "inspect", armored: secretArmor});
if (!preview.ok || preview.keys.some((key) => key.validity !== "Unknown" || key.subkeys.some((sub) => sub.validity !== "Unknown"))) {
  throw new Error(preview.error || "A key was trusted before it was imported.");
}
const imported = await handle({op: "import", armored: secretArmor});
if (!imported.ok) throw new Error(imported.error);
const loaded = imported.keys.find((key) => key.fingerprint === primary);
if (!loaded || loaded.validity !== "Ultimate" || loaded.subkeys.some((sub) => sub.validity !== "Ultimate")) {
  throw new Error(`The imported key was not trusted: ${JSON.stringify(loaded)}`);
}
const signed = await handle({op: "sign", fingerprint: signing, data: note.toString("base64"), timestamp: stamp});
if (!signed.ok) throw new Error(signed.error);
writeFileSync(join(dir, "signature.asc"), signed.armor);
gpg(["--verify", join(dir, "signature.asc"), join(dir, "note.bin")]);
const verified = await handle({
  op: "verify-detached",
  armored: text(readFileSync(join(dir, "gpg-signature.asc"))),
  data: note.toString("base64"),
  timestamp: stamp,
});
if (!verified.ok) throw new Error(verified.error);
const clear = await handle({op: "verify-cleartext", armored: text(readFileSync(join(dir, "gpg-clear.asc"))), timestamp: stamp});
if (!clear.ok || clear.text.replace(/\n$/, "") !== "hello airgap") throw new Error(clear.error || `cleartext ${JSON.stringify(clear.text)}`);
const encrypted = await handle({op: "encrypt", fingerprints: [encryption], data: note.toString("base64")});
if (!encrypted.ok) throw new Error(encrypted.error);
writeFileSync(join(dir, "encrypted.asc"), encrypted.armor);
const decrypted = gpg(["--decrypt", join(dir, "encrypted.asc")]);
if (!decrypted.equals(note)) throw new Error("The decrypted text did not match.");
const packets = text(gpg(["--list-packets", join(dir, "encrypted.asc")]));
if (!packets.toLowerCase().includes(encryption.slice(-16).toLowerCase())) throw new Error("The ciphertext is not for the selected subkey.");
const exported = await handle({op: "export", fingerprint: signing, secret: true, subkey: true});
if (!exported.ok || !exported.patch) throw new Error(exported.error || "The subkey export was not marked for patching.");
writeFileSync(join(dir, "private-full.asc"), exported.armor);
const added = await handle({op: "add-subkey", fingerprint: primary, algo: "ed25519", usage: "auth", expire: "never", timestamp: stamp});
if (!added.ok) throw new Error(added.error);
const auth = (added.keys[0].subkeys || []).find((sub) => sub.capabilities.includes("a"));
if (!auth) throw new Error(`No authentication subkey in ${JSON.stringify(added.keys[0].subkeys)}`);
const pub = await handle({op: "export", fingerprint: primary, secret: false, subkey: false});
if (!pub.ok) throw new Error(pub.error);
writeFileSync(join(dir, "auth-public.asc"), pub.armor);
gpg(["--import", join(dir, "auth-public.asc")]);
const after = text(gpg(["--with-colons", "--with-fingerprint", "--list-keys"]));
if (!after.includes(`:${auth.fingerprint}:`) || !subCapabilities(after, auth.fingerprint).includes("a")) {
  throw new Error("GnuPG did not accept the authentication subkey.");
}
const bip85Path = join(dir, "bip85.asc");
let bip85 = null;
try {
  const armor = text(readFileSync(bip85Path));
  const loaded = await handle({op: "import", armored: armor});
  if (!loaded.ok) throw new Error(loaded.error);
  bip85 = (loaded.keys || []).find((key) => (key.userIds || []).some((user) => user.includes("Ada Lovelace")));
  if (!bip85) throw new Error("The BIP-85 key was not imported.");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}
writeFileSync(join(dir, "meta.json"), JSON.stringify({
  primary, signing, encryption, timestamp: stamp,
  bip85: bip85 && {fingerprint: bip85.fingerprint, capabilities: bip85.capabilities},
}));

function fingerprintOf(output) {
  const line = text(output).split("\n").find((item) => item.startsWith("fpr:"));
  if (!line) throw new Error("No fingerprint.");
  return line.split(":")[9];
}

function subFingerprint(listing, usage) {
  const lines = listing.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const parts = lines[index].split(":");
    if (parts[0] === "ssb" && parts[11].toLowerCase().includes(usage)) {
      const fingerprint = lines.slice(index + 1).find((item) => item.startsWith("fpr:"));
      return fingerprint.split(":")[9];
    }
  }
  throw new Error(`No ${usage} subkey.`);
}

function subCapabilities(listing, fingerprint) {
  const lines = listing.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    if (lines[index].startsWith("fpr:") && lines[index].split(":")[9] === fingerprint) {
      for (let back = index; back >= 0; back -= 1) {
        const parts = lines[back].split(":");
        if (parts[0] === "sub" || parts[0] === "ssb") return parts[11].toLowerCase();
      }
    }
  }
  return "";
}
