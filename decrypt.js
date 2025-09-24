// decrypt.js
// Usage: node decrypt.js "<token>" "<password>"
// Example:
// node decrypt.js "casego:..." "your-password-here"

const crypto = require("crypto");

const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const PREFIX = "casego:";

function unpack(token) {
  if (typeof token !== "string" || !token.startsWith(PREFIX)) {
    throw new Error("token 格式错误：必须以 'casego:' 前缀开头");
  }
  return Buffer.from(token.slice(PREFIX.length), "base64");
}

function split(buf) {
  if (buf.length < SALT_LEN + IV_LEN + TAG_LEN + 1) {
    throw new Error("加密数据过短或格式错误");
  }
  const salt = buf.subarray(0, SALT_LEN);
  const iv = buf.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const tag = buf.subarray(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + TAG_LEN);
  const ciphertext = buf.subarray(SALT_LEN + IV_LEN + TAG_LEN);
  return { salt, iv, tag, ciphertext };
}

function deriveKey(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, KEY_LEN, { N: 16384, r: 8, p: 1 }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

async function decryptWithPassword(token, password) {
  const buf = unpack(token);
  const { salt, iv, tag, ciphertext } = split(buf);
  const key = await deriveKey(password, salt);
  const dec = crypto.createDecipheriv("aes-256-gcm", key, iv);
  dec.setAuthTag(tag);
  // (Optional) If you used AAD, set it here before finalizing: dec.setAAD(aad);
  return Buffer.concat([dec.update(ciphertext), dec.final()]);
}

async function main() {
  const [,, token, password] = process.argv;
  if (!token || !password) {
    console.error("用法: node decrypt.js <token> <password>");
    process.exit(2);
  }
  try {
    const plaintext = await decryptWithPassword(token, password);
    console.log("解密成功（UTF-8）:");
    console.log(plaintext.toString("utf8"));
  } catch (err) {
    console.error("解密失败：", err && err.message ? err.message : err);
    process.exit(1);
  }
}

main();
