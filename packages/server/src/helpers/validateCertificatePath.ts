/* eslint-disable @typescript-eslint/ban-ts-comment */
// ASN1HEX exists in the lib, but not typings, I swear
// @ts-ignore 2305
import { KJUR, X509, ASN1HEX } from 'jsrsasign';

const { crypto } = KJUR;

/**
 * Traverse an array of PEM certificates and ensure they form a proper chain
 * @param certificates Typically the result of `x5c.map(convertASN1toPEM)`
 */
export default function validateCertificatePath(certificates: string[]): boolean {
  if (new Set(certificates).size !== certificates.length) {
    throw new Error('Invalid certificate path: found duplicate certificates');
  }

  // From leaf to root, make sure each cert is issued by the next certificate in the chain
  for (let i = 0; i < certificates.length; i += 1) {
    const subjectPem = certificates[i];

    const subjectCert = new X509();
    subjectCert.readCertPEM(subjectPem);

    let issuerPem = '';
    if (i + 1 >= certificates.length) {
      issuerPem = subjectPem;
    } else {
      issuerPem = certificates[i + 1];
    }

    const issuerCert = new X509();
    issuerCert.readCertPEM(issuerPem);

    console.log('x issuer:', subjectCert.getIssuerString());
    console.log('x+1 subject:', issuerCert.getSubjectString());

    if (subjectCert.getIssuerString() !== issuerCert.getSubjectString()) {
      throw new Error('Invalid certificate path: subject issuer did not match issuer subject');
    }

    const subjectCertStruct = ASN1HEX.getTLVbyList(subjectCert.hex, 0, [0]);
    const alg = subjectCert.getSignatureAlgorithmField();
    const signatureHex = subjectCert.getSignatureValueHex();

    const Signature = new crypto.Signature({ alg });
    Signature.init(issuerPem);
    Signature.updateHex(subjectCertStruct);

    if (!Signature.verify(signatureHex)) {
      throw new Error('Invalid certificate path: invalid signature');
    }
  }

  return true;
}