// encrypt.js (示例，仅供测试/演示)
// Usage: node encrypt.js "<plaintext>" "<password>"

const crypto = require("crypto");

const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const PREFIX = "casego:";

function deriveKey(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, KEY_LEN, { N: 16384, r: 8, p: 1 }, (err, key) => {
      if (err) reject(err); else resolve(key);
    });
  });
}

async function encryptWithPassword(plaintext, password) {
  const salt = crypto.randomBytes(SALT_LEN);
  const key = await deriveKey(password, salt);
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  // (Optional) cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  const packed = Buffer.concat([salt, iv, tag, ct]).toString("base64");
  return PREFIX + packed;
}

async function main() {
  const [,, plaintext, password] = process.argv;
  if (!plaintext || !password) {
    console.error("Usage: node encrypt.js <plaintext> <password>");
    process.exit(2);
  }
  try {
    const token = await encryptWithPassword(plaintext, password);
    console.log("token:", token);
  } catch (err) {
    console.error("encrypt failed:", err);
    process.exit(1);
  }
}

main();
