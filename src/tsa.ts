// RFC 3161 timestamp tokens, checked offline against roots you supply (ROADMAP2 S5.5). This is the one part of
// ti-verify with dependencies (pkijs and asn1js, both BSD-3-Clause), kept out of src/h2a so the verifier core
// stays dependency-free and readable on its own.
//
// A token passes when: it is a granted TimeStampResp holding a SHA-256 TSTInfo; its imprint is the record's
// entry hash; and its signature verifies, by a certificate that chains to one of the roots given, valid at the
// token's own time. Take the roots from the authorities themselves, not from us: their fingerprints are on
// trulyimagined.com/trust so you can compare.
import * as pkijs from "pkijs";
import { toHex, utf8 } from "./h2a/index.js";

pkijs.setEngine("ti-verify", new pkijs.CryptoEngine({ name: "ti-verify", crypto: globalThis.crypto }));

const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const TST_INFO_OID = "1.2.840.113549.1.9.16.1.4";

export type StampVerdict = { ok: true; genTime: Date } | { ok: false; detail: string };

/** A PEM certificate as DER. */
export function certificateDer(pem: string): Uint8Array {
  const body = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(pem)?.[1];
  if (!body) throw new Error("expected a PEM CERTIFICATE block");
  return Uint8Array.from(atob(body.replace(/\s+/g, "")), (c) => c.charCodeAt(0));
}

/**
 * Checks one token. `entryPreimage` is what the entry hash is the SHA-256 of (the previous hash and the
 * payload hash, joined as text); pkijs checks the imprint against it as well as the comparison here.
 */
export async function verifyStamp(input: { token: Uint8Array; entryHash: string; prevHash: string; payloadHash: string; roots: readonly Uint8Array[] }): Promise<StampVerdict> {
  let response: pkijs.TimeStampResp;
  try {
    response = pkijs.TimeStampResp.fromBER(input.token as Uint8Array<ArrayBuffer>);
  } catch {
    return { ok: false, detail: "not a DER TimeStampResp" };
  }
  const status = response.status.status;
  if (status !== pkijs.PKIStatus.granted && status !== pkijs.PKIStatus.grantedWithMods) return { ok: false, detail: `status ${status}, not granted` };
  if (!response.timeStampToken) return { ok: false, detail: "granted, but carries no token" };
  const signed = new pkijs.SignedData({ schema: response.timeStampToken.content });
  if (signed.encapContentInfo.eContentType !== TST_INFO_OID || !signed.encapContentInfo.eContent) return { ok: false, detail: "does not hold a TSTInfo" };
  const tst = pkijs.TSTInfo.fromBER(signed.encapContentInfo.eContent.getValue());
  if (tst.messageImprint.hashAlgorithm.algorithmId !== SHA256_OID) return { ok: false, detail: "its imprint is not SHA-256" };
  if (toHex(new Uint8Array(tst.messageImprint.hashedMessage.valueBlock.valueHexView)) !== input.entryHash) {
    return { ok: false, detail: "it does not stamp this record's entry hash" };
  }

  const roots = input.roots.map((der) => pkijs.Certificate.fromBER(der as Uint8Array<ArrayBuffer>));
  // An authority may include a cross-signed copy of its own root; path building would follow it away from the
  // root given, so a certificate that is the same CA as a given root is set aside.
  const same = (a: pkijs.Certificate, b: pkijs.Certificate) =>
    toHex(new Uint8Array(a.subject.toSchema().toBER(false))) === toHex(new Uint8Array(b.subject.toSchema().toBER(false))) &&
    toHex(a.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView) === toHex(b.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
  if (signed.certificates) signed.certificates = signed.certificates.filter((cert) => !(cert instanceof pkijs.Certificate) || !roots.some((root) => same(cert, root)));

  let result: { signatureVerified?: boolean | null; signerCertificateVerified?: boolean | null; message?: string };
  try {
    result = await signed.verify({
      signer: 0,
      data: utf8(input.prevHash + input.payloadHash).buffer,
      trustedCerts: roots,
      checkChain: true,
      checkDate: tst.genTime,
      extendedMode: true,
    });
  } catch (error) {
    const e = error as { signatureVerified?: boolean | null; signerCertificateVerified?: boolean | null; message?: string };
    result = { signatureVerified: e.signatureVerified ?? null, signerCertificateVerified: e.signerCertificateVerified ?? null, message: e.message ?? String(error) };
  }
  if (result.signerCertificateVerified !== true) return { ok: false, detail: `its certificate does not chain to a root given (${result.message ?? "no path"})` };
  if (result.signatureVerified !== true) return { ok: false, detail: `its signature does not verify (${result.message ?? "invalid"})` };
  return { ok: true, genTime: tst.genTime };
}
