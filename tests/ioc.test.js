// Run with: node tests/ioc.test.js
const assert = require("assert");
const IOC = require("../assets/ioc.js");

const types = (text, opts) => IOC.extract(text, opts).map((x) => x.type + ":" + x.value);

// Refang and defang
assert.strictEqual(IOC.refang("hxxps://evil[.]example[.]com/a"), "https://evil.example.com/a");
assert.strictEqual(IOC.refang("user[@]phish(.)org"), "user@phish.org");
assert.strictEqual(IOC.defang("http://a.b.com/x"), "hxxp://a[.]b[.]com/x");

// URLs also yield their domain
let r = types("see hxxps://evil[.]example[.]com/login.php?id=1 now");
assert(r.includes("url:https://evil.example.com/login.php?id=1"));
assert(r.includes("domain:evil.example.com"));

// IPs, private flag
let ips = IOC.extract("185.220.101.4 and 10.1.2.3");
assert.strictEqual(ips.find((x) => x.value === "185.220.101.4").private, false);
assert.strictEqual(ips.find((x) => x.value === "10.1.2.3").private, true);

// Hashes
assert(types("44d88612fea8a8f36de82e1278abb02f").includes("md5:44d88612fea8a8f36de82e1278abb02f"));
assert(types("a".repeat(40)).includes("sha1:" + "a".repeat(40)));
assert(types("b".repeat(64)).includes("sha256:" + "b".repeat(64)));

// 32-char hex can be an MD5 or a JA3: the caller chooses
assert(types("e7d705a3286e19ea42f587b344ee6865", { hex32: "ja3" }).includes("ja3:e7d705a3286e19ea42f587b344ee6865"));

// JA4 and JA4S
assert(types("t13d1516h2_8daaf6152771_02713d6af862").includes("ja4:t13d1516h2_8daaf6152771_02713d6af862"));
assert(types("t130200_1301_a56c5b993250").includes("ja4s:t130200_1301_a56c5b993250"));

// CVEs, emails
assert(types("exploits cve-2024-3400").includes("cve:CVE-2024-3400"));
assert(types("bad[@]phish[.]org").includes("email:bad@phish.org"));

// File names are not domains
assert(!types("run payload.exe then report.pdf").some((x) => x.startsWith("domain:")));

// De-duplication and counting
let d = IOC.extract("1.2.3.4 1.2.3.4 1[.]2[.]3[.]4");
assert.strictEqual(d.length, 1);
assert.strictEqual(d[0].count, 3);

// Pivots exist for every type and are URL-encoded
assert(IOC.pivots({ type: "ip", value: "8.8.8.8" }).length >= 4);
assert(IOC.pivots({ type: "ja4", value: "t13d1516h2_8daaf6152771_02713d6af862" }).length >= 3);
assert(IOC.platforms().includes("Talos"));

console.log("All IOC checker tests passed.");
