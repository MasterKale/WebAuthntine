import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';

import type { AttestationStatement } from '../../helpers/decodeAttestationObject';
import validateCertificatePath from '../../helpers/validateCertificatePath';
import convertX509CertToPEM from '../../helpers/convertX509CertToPEM';
import toHash from '../../helpers/toHash';
import convertCOSEtoPKCS from '../../helpers/convertCOSEtoPKCS';

type Options = {
  attStmt: AttestationStatement;
  authData: Buffer;
  clientDataHash: Buffer;
  credentialPublicKey: Buffer;
};

type AppleVerifierCtorOpts = {
  rootCertificate: string;
};

export class AppleVerifier {
  rootCertificate: string;
  constructor(options: AppleVerifierCtorOpts) {
    this.rootCertificate = options.rootCertificate;
  }

  async verify(options: Options): Promise<boolean> {
    const { attStmt, authData, clientDataHash, credentialPublicKey } = options;
    const { x5c } = attStmt;

    if (!x5c) {
      throw new Error('No attestation certificate provided in attestation statement (Apple)');
    }

    /**
     * Verify certificate path
     */
    const certPath = x5c.map(convertX509CertToPEM);
    certPath.push(this.rootCertificate);

    try {
      await validateCertificatePath(certPath);
    } catch (err) {
      throw new Error(`${err.message} (Apple)`);
    }

    /**
     * Compare nonce in certificate extension to computed nonce
     */
    const parsedCredCert = AsnParser.parse(x5c[0], Certificate);
    const { extensions, subjectPublicKeyInfo } = parsedCredCert.tbsCertificate;

    if (!extensions) {
      throw new Error('credCert missing extensions (Apple)');
    }

    const extCertNonce = extensions.find(ext => ext.extnID === '1.2.840.113635.100.8.2');

    if (!extCertNonce) {
      throw new Error('credCert missing "1.2.840.113635.100.8.2" extension (Apple)');
    }

    const nonceToHash = Buffer.concat([authData, clientDataHash]);
    const nonce = toHash(nonceToHash, 'SHA256');
    /**
     * Ignore the first six ASN.1 structure bytes that define the nonce as an OCTET STRING. Should
     * trim off <Buffer 30 24 a1 22 04 20>
     *
     * TODO: Try and get @peculiar (GitHub) to add a schema for "1.2.840.113635.100.8.2" when we
     * find out where it's defined (doesn't seem to be publicly documented at the moment...)
     */
    const extNonce = Buffer.from(extCertNonce.extnValue.buffer).slice(6);

    if (!nonce.equals(extNonce)) {
      throw new Error(`credCert nonce was not expected value (Apple)`);
    }

    /**
     * Verify credential public key matches the Subject Public Key of credCert
     */
    const credPubKeyPKCS = convertCOSEtoPKCS(credentialPublicKey);
    const credCertSubjectPublicKey = Buffer.from(subjectPublicKeyInfo.subjectPublicKey);

    if (!credPubKeyPKCS.equals(credCertSubjectPublicKey)) {
      throw new Error('Credential public key does not equal credCert public key (Apple)');
    }

    return true;
  }
}

/**
 * Apple WebAuthn Root CA PEM
 *
 * Downloaded from https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem
 *
 * Valid until 03/14/2045 @ 5:00 PM PST
 */
const AppleWebAuthnRootCertificate = `-----BEGIN CERTIFICATE-----
MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w
HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ
bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx
NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG
A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49
AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k
xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/
pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk
2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA
MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3
jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B
1bWeT0vT
-----END CERTIFICATE-----`;

const defaultVerifier = new AppleVerifier({ rootCertificate: AppleWebAuthnRootCertificate });
export default defaultVerifier.verify.bind(defaultVerifier);
