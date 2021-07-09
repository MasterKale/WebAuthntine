import base64url from 'base64url';

import verifyAttestationResponse, { defaultFormatVerifiers } from './verifyAttestationResponse';

import * as decodeAttestationObject from '../helpers/decodeAttestationObject';
import * as decodeClientDataJSON from '../helpers/decodeClientDataJSON';
import * as parseAuthenticatorData from '../helpers/parseAuthenticatorData';
import * as decodeCredentialPublicKey from '../helpers/decodeCredentialPublicKey';

import toHash from '../helpers/toHash';
import { AttestationCredentialJSON } from '@simplewebauthn/typescript-types';

let mockDecodeAttestation: jest.SpyInstance;
let mockDecodeClientData: jest.SpyInstance;
let mockParseAuthData: jest.SpyInstance;
let mockDecodePubKey: jest.SpyInstance;
let mockVerifyFIDOU2F: jest.SpyInstance;

beforeEach(() => {
  mockDecodeAttestation = jest.spyOn(decodeAttestationObject, 'default');
  mockDecodeClientData = jest.spyOn(decodeClientDataJSON, 'default');
  mockParseAuthData = jest.spyOn(parseAuthenticatorData, 'default');
  mockDecodePubKey = jest.spyOn(decodeCredentialPublicKey, 'default');
  mockVerifyFIDOU2F = jest.spyOn(
    defaultFormatVerifiers,
    decodeAttestationObject.ATTESTATION_FORMAT.FIDO_U2F,
  );
});

afterEach(() => {
  mockDecodeAttestation.mockRestore();
  mockDecodeClientData.mockRestore();
  mockParseAuthData.mockRestore();
  mockDecodePubKey.mockRestore();
  mockVerifyFIDOU2F.mockRestore();
});

test('should verify FIDO U2F attestation', async () => {
  const verification = await verifyAttestationResponse({
    credential: attestationFIDOU2F,
    expectedChallenge: attestationFIDOU2FChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.attestationInfo?.fmt).toEqual('fido-u2f');
  expect(verification.attestationInfo?.counter).toEqual(0);
  expect(verification.attestationInfo?.credentialPublicKey).toEqual(
    base64url.toBuffer(
      'pQECAyYgASFYIMiRyw5pUoMhBjCrcQND6lJPaRHA0f-XWcKBb5ZwWk1eIlggFJu6aan4o7epl6qa9n9T-6KsIMvZE2PcTnLj8rN58is',
    ),
  );
  expect(verification.attestationInfo?.credentialID).toEqual(
    base64url.toBuffer(
      'VHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUQ',
    ),
  );
  expect(verification.attestationInfo?.aaguid).toEqual('00000000-0000-0000-0000-000000000000');
  expect(verification.attestationInfo?.credentialType).toEqual('public-key');
  expect(verification.attestationInfo?.userVerified).toEqual(false);
  expect(verification.attestationInfo?.attestationObject).toEqual(
    base64url.toBuffer(attestationFIDOU2F.response.attestationObject),
  );
});

test('should verify Packed (EC2) attestation', async () => {
  const verification = await verifyAttestationResponse({
    credential: attestationPacked,
    expectedChallenge: attestationPackedChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.attestationInfo?.fmt).toEqual('packed');
  expect(verification.attestationInfo?.counter).toEqual(1589874425);
  expect(verification.attestationInfo?.credentialPublicKey).toEqual(
    base64url.toBuffer(
      'pQECAyYgASFYIEoxVVqK-oIGmqoDEyO4KjmMx5R2HeMM4LQQXh8sE01PIlggtzuuoMN5fWnAIuuXdlfshOGu1k3ApBUtDJ8eKiuo_6c',
    ),
  );
  expect(verification.attestationInfo?.credentialID).toEqual(
    base64url.toBuffer(
      'AYThY1csINY4JrbHyGmqTl1nL_F1zjAF3hSAIngz8kAcjugmAMNVvxZRwqpEH-bNHHAIv291OX5ko9eDf_5mu3U' +
        'B2BvsScr2K-ppM4owOpGsqwg5tZglqqmxIm1Q',
    ),
  );
});

test('should verify Packed (X5C) attestation', async () => {
  const verification = await verifyAttestationResponse({
    credential: attestationPackedX5C,
    expectedChallenge: attestationPackedX5CChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.attestationInfo?.fmt).toEqual('packed');
  expect(verification.attestationInfo?.counter).toEqual(28);
  expect(verification.attestationInfo?.credentialPublicKey).toEqual(
    base64url.toBuffer(
      'pQECAyYgASFYIGwlsYCNyRb4AD9cyTw6cH5VS-uzflmmO1UldGGe9eIaIlggvadzKD8p6wKLjgYfxRxldjCMGRV0YyM13osWbKIPrF8',
    ),
  );
  expect(verification.attestationInfo?.credentialID).toEqual(
    base64url.toBuffer(
      '4rrvMciHCkdLQ2HghazIp1sMc8TmV8W8RgoX-x8tqV_1AmlqWACqUK8mBGLandr-htduQKPzgb2yWxOFV56Tlg',
    ),
  );
});

test('should verify None attestation', async () => {
  const verification = await verifyAttestationResponse({
    credential: attestationNone,
    expectedChallenge: attestationNoneChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.attestationInfo?.fmt).toEqual('none');
  expect(verification.attestationInfo?.counter).toEqual(0);
  expect(verification.attestationInfo?.credentialPublicKey).toEqual(
    base64url.toBuffer(
      'pQECAyYgASFYID5PQTZQQg6haZFQWFzqfAOyQ_ENsMH8xxQ4GRiNPsqrIlggU8IVUOV8qpgk_Jh-OTaLuZL52KdX1fTht07X4DiQPow',
    ),
  );
  expect(verification.attestationInfo?.credentialID).toEqual(
    base64url.toBuffer(
      'AdKXJEch1aV5Wo7bj7qLHskVY4OoNaj9qu8TPdJ7kSAgUeRxWNngXlcNIGt4gexZGKVGcqZpqqWordXb_he1izY',
    ),
  );
});

test('should verify None attestation w/RSA public key', async () => {
  const expectedChallenge = 'pYZ3VX2yb8dS9yplNxJChiXhPGBk8gZzTAyJ2iU5x1k';
  const verification = await verifyAttestationResponse({
    credential: {
      id: 'kGXv4RJWLeXRw8Yf3T22K3Gq_GGeDv9OKYmAHLm0Ylo',
      rawId: 'kGXv4RJWLeXRw8Yf3T22K3Gq_GGeDv9OKYmAHLm0Ylo',
      response: {
        attestationObject:
          'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZz3cRxDpwIiyKduonVYyILs59yKa_0ZbCmVrGvuaivigRQAAAABgKLAXsdRMArSzr82vyWuyACCQZe_hElYt5dHDxh_dPbYrcar8YZ4O_04piYAcubRiWqQBAwM5AQAgWQEA8X6V649G2vwB99CSf_luwR0jj7oDg_GhA3TQSnNYIwfQJldxT5dmi9H8IjjCrTP28iNuKl29hc3Mowux1FZB0bc5AEJ2oV3JCOMGP9NZKGmOosF7iBN2GtGY7Nomcs-ruBv2mxp1nTm6mv5B8XNwh0e18uTA5AJCsl-k6lNLYB2XBIQ3fy2-TjSQ8IOMLypWQbWWBJXzLmepaJ6EWe6kf_NaxpA2chWsaekZcr8xG6OIo3iGh0Mpags_qBZtN4n2TDn0R2LheLk4yQ0R_oOAVtX963Yuw0x5NYSZyMNSMi_1RSEPTYn5AILmIzQskglDaWJYtnjKz4QLuXWCRRYyDSFDAQAB',
        clientDataJSON:
          'eyJjaGFsbGVuZ2UiOiJwWVozVlgyeWI4ZFM5eXBsTnhKQ2hpWGhQR0JrOGdaelRBeUoyaVU1eDFrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9',
      },
      type: 'public-key',
      clientExtensionResults: {},
    },
    expectedChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.attestationInfo?.fmt).toEqual('none');
  expect(verification.attestationInfo?.counter).toEqual(0);
  expect(verification.attestationInfo?.credentialPublicKey).toEqual(
    base64url.toBuffer(
      'pAEDAzkBACBZAQDxfpXrj0ba_AH30JJ_-W7BHSOPugOD8aEDdNBKc1gjB9AmV3FPl2aL0fwiOMKtM_byI24qXb2FzcyjC7HUVkHRtzkAQnahXckI4wY_01koaY6iwXuIE3Ya0Zjs2iZyz6u4G_abGnWdObqa_kHxc3CHR7Xy5MDkAkKyX6TqU0tgHZcEhDd_Lb5ONJDwg4wvKlZBtZYElfMuZ6lonoRZ7qR_81rGkDZyFaxp6RlyvzEbo4ijeIaHQylqCz-oFm03ifZMOfRHYuF4uTjJDRH-g4BW1f3rdi7DTHk1hJnIw1IyL_VFIQ9NifkAguYjNCySCUNpYli2eMrPhAu5dYJFFjINIUMBAAE',
    ),
  );
  expect(verification.attestationInfo?.credentialID).toEqual(
    base64url.toBuffer('kGXv4RJWLeXRw8Yf3T22K3Gq_GGeDv9OKYmAHLm0Ylo'),
  );
});

test('should throw when response challenge is not expected value', async () => {
  await expect(
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: 'shouldhavebeenthisvalue',
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    }),
  ).rejects.toThrow(/attestation challenge/i);
});

test('should throw when response origin is not expected value', async () => {
  await expect(
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://different.address',
      expectedRPID: 'dev.dontneeda.pw',
    }),
  ).rejects.toThrow(/attestation origin/i);
});

test('should throw when attestation type is not webauthn.create', async () => {
  const origin = 'https://dev.dontneeda.pw';
  const challenge = attestationNoneChallenge;

  // @ts-ignore 2345
  mockDecodeClientData.mockReturnValue({
    origin,
    type: 'webauthn.badtype',
    challenge: attestationNoneChallenge,
  });

  await expect(
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: 'dev.dontneeda.pw',
    }),
  ).rejects.toThrow(/attestation type/i);
});

test('should throw if an unexpected attestation format is specified', async () => {
  const fmt = 'fizzbuzz';

  const realAtteObj = decodeAttestationObject.default(
    base64url.toBuffer(attestationNone.response.attestationObject),
  );

  mockDecodeAttestation.mockReturnValue({
    ...realAtteObj,
    // @ts-ignore 2322
    fmt,
  });

  await expect(
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    }),
  ).rejects.toThrow(/unsupported attestation format/i);
});

test('should throw error if assertion RP ID is unexpected value', async () => {
  const { authData } = decodeAttestationObject.default(
    base64url.toBuffer(attestationNone.response.attestationObject),
  );
  const actualAuthData = parseAuthenticatorData.default(authData);

  mockParseAuthData.mockReturnValue({
    ...actualAuthData,
    rpIdHash: toHash(Buffer.from('bad.url', 'ascii')),
  });

  await expect(
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    }),
  ).rejects.toThrow(/rp id/i);
});

test('should throw error if user was not present', async () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from('dev.dontneeda.pw', 'ascii')),
    flags: {
      up: false,
    },
  });

  await expect(
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    }),
  ).rejects.toThrow(/not present/i);
});

test('should throw if the authenticator does not give back credential ID', async () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from('dev.dontneeda.pw', 'ascii')),
    flags: {
      up: true,
    },
    credentialID: undefined,
  });

  await expect(
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    }),
  ).rejects.toThrow(/credential id/i);
});

test('should throw if the authenticator does not give back credential public key', async () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from('dev.dontneeda.pw', 'ascii')),
    flags: {
      up: true,
    },
    credentialID: 'aaa',
    credentialPublicKey: undefined,
  });

  await expect(
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    }),
  ).rejects.toThrow(/public key/i);
});

test('should throw error if no alg is specified in public key', async () => {
  mockDecodePubKey.mockReturnValue({
    get: () => undefined,
    credentialID: '',
    credentialPublicKey: '',
  });

  await expect(
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    }),
  ).rejects.toThrow(/missing numeric alg/i);
});

test('should throw error if unsupported alg is used', async () => {
  mockDecodePubKey.mockReturnValue({
    get: () => -999,
    credentialID: '',
    credentialPublicKey: '',
  });

  await expect(
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    }),
  ).rejects.toThrow(/unexpected public key/i);
});

test('should not include authenticator info if not verified', async () => {
  mockVerifyFIDOU2F.mockReturnValue(false);

  const verification = await verifyAttestationResponse({
    credential: attestationFIDOU2F,
    expectedChallenge: attestationFIDOU2FChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toBe(false);
  expect(verification.attestationInfo).toBeUndefined();
});

test('should throw an error if user verification is required but user was not verified', async () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from('dev.dontneeda.pw', 'ascii')),
    flags: {
      up: true,
      uv: false,
    },
  });

  await expect(
    verifyAttestationResponse({
      credential: attestationFIDOU2F,
      expectedChallenge: attestationFIDOU2FChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
      requireUserVerification: true,
    }),
  ).rejects.toThrow(/user could not be verified/i);
});

test('should validate TPM RSA response (SHA256)', async () => {
  const expectedChallenge = '3a07cf85-e7b6-447f-8270-b25433f6018e';
  const verification = await verifyAttestationResponse({
    credential: {
      id: 'lGkWHPe88VpnNYgVBxzon_MRR9-gmgODveQ16uM_bPM',
      rawId: 'lGkWHPe88VpnNYgVBxzon_MRR9-gmgODveQ16uM_bPM',
      response: {
        attestationObject:
          'o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzkBAGNzaWdZAQBoZraUgitkw10bZI2MMWDECGf3LgbkX1XoSUhWhxawE8gX1oQdbYbIx-LjtFZkBqp7Nsq8qdeQBGhSJbSbE1wLfP5Xs3d110KmD4LzrCmt_rn3LYQDhDIonft8xJIpAHppEKCxziHMWCPXbntIeQ8pHEZmjBTIN5CJyxHQeUp1LniMQ0CGRknSlE4Av6aHrnoGUgnrsyXmzMn0BWxtdGIhsheAIiBanXGqMdLQ5cGc1HRmGh9U4NrVE-W7nJBLuA5H9K6-t9TfTySYInzr81XEsh6Ei5ijGT2Cc1MmaU4utbB-LyUG9v_oy9EpdOAu4v2jBOBkms0CxrErdWCKl7b5Y3ZlcmMyLjBjeDVjglkEhzCCBIMwggNroAMCAQICDwS6zyQ0LwxSSoQYLc7HVjANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELUZGOTkwMzM4RTE4NzA3OUE2Q0Q2QTAzQURDNTcyMzc0NDVGNkE0OUEwHhcNMTgwMjAxMDAwMDAwWhcNMjUwMTMxMjM1OTU5WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA-IYIfmLnyIHdgjwb2Y-KzMYI2HjN6WseCH8f9N7G3zZpSE9xZxrutKpgoE5wzV2STtkvgd5xikTdIrneWGcNeIW2xhdH2dAVnhL1OiRdLf1CneJHUO78t5-3pmCynqMlUW1VELC-mpaY_kbpNF0Fxn3MhV_-LwtinS5FCvsHpMdKJ_md2e9CDAiI7IqdeK9_sPA5hzDsq9nXsBn0MCcSEppWojwLG3pqmnBWsrLGJCyT5OBi2yNiD0pWMhgromksz6AfFraVDHX8d7E-GoDHedLujnZIm3fAiWDvmdgmZVxX6bxLSWZqWZoSNuJSRasoulVDzDOBHYBWGKLJGgPdMwIDAQABo4IBtzCCAbMwDgYDVR0PAQH_BAQDAgeAMAwGA1UdEwEB_wQCMAAwewYDVR0gAQH_BHEwbzBtBgkrBgEEAYI3FR8wYDBeBggrBgEFBQcCAjBSHlAARgBBAEsARQAgAEYASQBEAE8AIABUAEMAUABBACAAVAByAHUAcwB0AGUAZAAgAFAAbABhAHQAZgBvAHIAbQAgAEkAZABlAG4AdABpAHQAeTAQBgNVHSUECTAHBgVngQUIAzBKBgNVHREBAf8EQDA-pDwwOjE4MA4GBWeBBQIDDAVpZDoxMzAQBgVngQUCAgwHTlBDVDZ4eDAUBgVngQUCAQwLaWQ6RkZGRkYxRDAwHwYDVR0jBBgwFoAUdOhwbuNi8U8_KoCvb3uGHTvHco0wHQYDVR0OBBYEFNiSs3HuWy41m937TQw7EyHG4L3_MHgGCCsGAQUFBwEBBGwwajBoBggrBgEFBQcwAoZcaHR0cHM6Ly9maWRvYWxsaWFuY2UuY28ubnovdHBtcGtpL05DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QS5jcnQwDQYJKoZIhvcNAQELBQADggEBAHCSnX7NtGUl1gyIRsprAS1y4TfvEfxpmsrbTruacYBDQ4z5o2uoMYYV2txkvI_pH4kxOolSS9oTz7iNGpKv1yB3x40rMRsiUNs7EyhmH7RE73DOBxlMkr1vHJudiIircI1EifC7FKiDqssKKws8apYE1BZYj6swuG2LOx1LUHd-hP473u0XEv8WbRXY3Pr1I9DODhfMkJDLUKg_l7YI2oowgathLG5_ci0Ad2EHn9122Y1StwSr0r7-cfrTwNxt2bPnZ61hkI_Em7IlCsuol0wak1Ba-UqEWDuTMRmMn3AF59rmIQ2yPdj4ae0DBnSsP13DZj8ihPT68SsaY7HiURBZBgUwggYBMIID6aADAgECAg8EV2dM14jMuwRaKXATKH8wDQYJKoZIhvcNAQELBQAwgb8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxNjA0BgNVBAMMLUZJRE8gRmFrZSBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxODExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzAeFw0xNzAyMDEwMDAwMDBaFw0zNTAxMzEyMzU5NTlaMEExPzA9BgNVBAMTNk5DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANc-c30RpQd-_LCoiLJbXz3t_vqciOIovwjez79_DtVgi8G9Ph-tPL-lC0ueFGBMSPcKd_RDdSFe2QCYQd9e0DtiFxra-uWGa0olI1hHI7bK2GzNAZSTKEbwgqpf8vXMQ-7SPajg6PfxSOLH_Nj2yd6tkNkUSdlGtWfY8XGB3n-q--nt3UHdUQWEtgUoTe5abBXsG7MQSuTNoad3v6vk-tLd0W44ivM6pbFqFUHchx8mGLApCpjlVXrfROaCoc9E91hG9B-WNvekJ0dM6kJ658Hy7yscQ6JdqIEolYojCtWaWNmwcfv--OE1Ax_4Ub24gl3hpB9EOcBCzpb4UFmLYUECAwEAAaOCAXUwggFxMAsGA1UdDwQEAwIBhjAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzAbBgNVHSUEFDASBgkrBgEEAYI3FSQGBWeBBQgDMBIGA1UdEwEB_wQIMAYBAf8CAQAwHQYDVR0OBBYEFHTocG7jYvFPPyqAr297hh07x3KNMB8GA1UdIwQYMBaAFEMRFpma7p1QN8JP_uJbFckJMz8yMGgGA1UdHwRhMF8wXaBboFmGV2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9jcmwvRklETyBGYWtlIFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE4LmNybDBvBggrBgEFBQcBAQRjMGEwXwYIKwYBBQUHMAKGU2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9GSURPIEZha2UgVFBNIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTguY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQBI6GeuxIkeKcmRmFQnkPnkvSybRIJEkzWKa2f00vdBygxtzpkXF2WMHbvuMU3_K3WMFzg2xkSPjM3x_-UxOWGYgVIq8fXUdy2NhmLz4tPI65_nQXpS22rzmXFzsj4x9yS0JF2NnW5xm-O8UdckFdwIZx4Ew_zA-rIF3hqbY4Ejz2AdsbvHJo-WTpu-wWDbBQyR19eqNyYZ6vf9K8DB2JZviIDXdOpkuOJLA40MKMlnhv5K4BZs7mDZIaPzNA_MrcH3_dYXq4tIoGu5Pr1ZNCQ--93XYG1eRbvCgSDYUCRza5AgBGCIhmx2-tqLYeCd9qdy4O9R9c9qRjEThbjnGStYZ0DuB6VCaH1WjiRqyq4VNi9cv15-RoC4zswWwuHee97AAJ_Tx29w6S4Kw9DQR6A0vtw_OHLuOkGH63ns0DACf_h1MvsAMnXXX0Q0P8IpNdBQGvLvrRtRdBNx06NHY1HGZOZ9PdJ6J4mnroB2ln3cMGZG9kyRv2vbwq6sCrYZVYjo3tf4MUtkEY4FijoYbMEDK7VlbTiDPnobhkxI1-bz5DTFnR3IfVybYAeGrBCKSg2UUTPvVgM3WZ-oGlP8W9dg1347hqgxP0vLgDM6cV7rhaFC_ZAf2Et9KLRZSj7lNpJWxHxPyz9mM4w3qFwdgWKwlXl3OQtJRT4Kbs6r3gzB5WdwdWJBcmVhWQE2AAEACwAGBHIAIJ3_y_NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi_rSKuABAAEAgAAAAAAAEArcc8OfVrJfMVj_e8D07tk0g5brIcLIS_BnnRwBztUetpt5zcttYQiyZUGm3y3qUVEP7_ZqtzwplfNbQUqrURlOf2JStEdsnru-ekp09_XOoSgtzwT7f8XYy_3HM-B_-9w7p3wet0GTrXXgLLMFe1jy6jAEaH7jPi0Pyx5zYLgsqQ3MYQA7lKkLaIH8GbJJ01SD8cxnH6p0OxERfQ_QDliEPGIzrE4vwds0vEjskiiBVBsMGHDxuw4ghPkCXCPn6cnUQ5xKulMW5GIAe1yuAZZjypcLl5AQ1_XoJfzGuAe1tlib2Gynr7umfCnOcvjiE6TVQ2CmwSt6isoeMiFKQdTWhjZXJ0SW5mb1it_1RDR4AXACIACxHmjtRNtTcuFCluL4Ssx4OYdRiBkh4w_CKgb4tzx5RTACBUXhu5udUi6GBvBBGsIF5MfQKIIDBdBStwWHfPWQx-FQAAAAFHcBdIVWl7S8aFYKUBc375jTRWVfsAIgALjZ3k0w--c4p2uu7urgJWOfxm0k2XJW4x9EEu0o-HzrIAIgAL_U4kZaJRRPAELcp-Gp4lh_iSA_uUtdHNVhq5vjbJ0KVoYXV0aERhdGFZAWc93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAAAep9bZOooNEeialKbPcQcvcwAglGkWHPe88VpnNYgVBxzon_MRR9-gmgODveQ16uM_bPOkAQMDOQEAIFkBAK3HPDn1ayXzFY_3vA9O7ZNIOW6yHCyEvwZ50cAc7VHrabec3LbWEIsmVBpt8t6lFRD-_2arc8KZXzW0FKq1EZTn9iUrRHbJ67vnpKdPf1zqEoLc8E-3_F2Mv9xzPgf_vcO6d8HrdBk6114CyzBXtY8uowBGh-4z4tD8sec2C4LKkNzGEAO5SpC2iB_BmySdNUg_HMZx-qdDsREX0P0A5YhDxiM6xOL8HbNLxI7JIogVQbDBhw8bsOIIT5Alwj5-nJ1EOcSrpTFuRiAHtcrgGWY8qXC5eQENf16CX8xrgHtbZYm9hsp6-7pnwpznL44hOk1UNgpsEreorKHjIhSkHU0hQwEAAQ',
        clientDataJSON:
          'eyJvcmlnaW4iOiJodHRwczovL2Rldi5kb250bmVlZGEucHciLCJjaGFsbGVuZ2UiOiIzYTA3Y2Y4NS1lN2I2LTQ0N2YtODI3MC1iMjU0MzNmNjAxOGUiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
      },
      type: 'public-key',
      clientExtensionResults: {},
    },
    expectedChallenge: expectedChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.attestationInfo?.fmt).toEqual('tpm');
  expect(verification.attestationInfo?.counter).toEqual(30);
  expect(verification.attestationInfo?.credentialPublicKey).toEqual(
    base64url.toBuffer(
      'pAEDAzkBACBZAQCtxzw59Wsl8xWP97wPTu2TSDlushwshL8GedHAHO1R62m3nNy21hCLJlQabfLepRUQ_v9mq3PCmV81tBSqtRGU5_YlK0R2yeu756SnT39c6hKC3PBPt_xdjL_ccz4H_73DunfB63QZOtdeAsswV7WPLqMARofuM-LQ_LHnNguCypDcxhADuUqQtogfwZsknTVIPxzGcfqnQ7ERF9D9AOWIQ8YjOsTi_B2zS8SOySKIFUGwwYcPG7DiCE-QJcI-fpydRDnEq6UxbkYgB7XK4BlmPKlwuXkBDX9egl_Ma4B7W2WJvYbKevu6Z8Kc5y-OITpNVDYKbBK3qKyh4yIUpB1NIUMBAAE',
    ),
  );
  expect(verification.attestationInfo?.credentialID).toEqual(
    base64url.toBuffer('lGkWHPe88VpnNYgVBxzon_MRR9-gmgODveQ16uM_bPM'),
  );
});

test('should validate TPM RSA response (SHA1)', async () => {
  const expectedChallenge = 'f4e8d87b-d363-47cc-ab4d-1a84647bf245';
  const verification = await verifyAttestationResponse({
    credential: {
      id: 'oELnad0f6-g2BtzEn_78iLNoubarlq0xFtOtAMXnflU',
      rawId: 'oELnad0f6-g2BtzEn_78iLNoubarlq0xFtOtAMXnflU',
      response: {
        attestationObject:
          'o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQA7MkOLfnxF5Z0RsXHc0OoVV-wkR6gKW92FFuBU79qeu7bxzMONC0uJ1mLt4SmhKsKZss1UqEx37tjwhzRE3wgNFGEEwK274W6xDVsU2ZimAvW_hZZwQAK5I3b35oJcQQxoc2iTv6XHDfwmf1pDa3d35idsNrv_-wQttjapdycRmkt7POPFAVMvooIY1bW6xk4fNIdqhHN1X6E2eT9k7IHcnQfdpqo_PpxxHzH1sLm00D3GanqMQFO0RlfE6HUZmfrTh8WpnwPwRZ_AH7njRS_eNvFm_oPX-19YRgzY0GFJb_b7tsL_EejBbygnIh4SCXEj9XfV0mneXKZuh47HzC2sY3ZlcmMyLjBjeDVjglkEhzCCBIMwggNroAMCAQICDwQzi_r9IpiaTHT5hcpSFTANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELUZGOTkwMzM4RTE4NzA3OUE2Q0Q2QTAzQURDNTcyMzc0NDVGNkE0OUEwHhcNMTgwMjAxMDAwMDAwWhcNMjUwMTMxMjM1OTU5WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqFSXnyuWEwydvMZN8iP-HW-XnQ8thzSa0KbFr2JUdGN8ox4Re5VicuIW5uFn_0_l-lTvngIR5JTlyaSLr7VrXNqlv4fNax0ZBbaYqgXaBJMhXpBjVCvjSZuNvCxd-7vLbqXuCNdNPAkSU1RKXN4ATZJfOBeCLDBWh-puudODIGTaz6nG_q78Qh7oErN279BsP77DcfoR47Em1eZpWXe9ezyvXuV5bqS04CaG_AnN1KU3o5madqio3Xlf3OXTEEKhLNTEu4-Oay_sykWRd7iflPipE981PqXCw9bVJM089cg952Eyo8N94Uzjb6XT4zkRsBYonzoIywzqCYlvklAlQIDAQABo4IBtzCCAbMwDgYDVR0PAQH_BAQDAgeAMAwGA1UdEwEB_wQCMAAwewYDVR0gAQH_BHEwbzBtBgkrBgEEAYI3FR8wYDBeBggrBgEFBQcCAjBSHlAARgBBAEsARQAgAEYASQBEAE8AIABUAEMAUABBACAAVAByAHUAcwB0AGUAZAAgAFAAbABhAHQAZgBvAHIAbQAgAEkAZABlAG4AdABpAHQAeTAQBgNVHSUECTAHBgVngQUIAzBKBgNVHREBAf8EQDA-pDwwOjE4MA4GBWeBBQIDDAVpZDoxMzAQBgVngQUCAgwHTlBDVDZ4eDAUBgVngQUCAQwLaWQ6RkZGRkYxRDAwHwYDVR0jBBgwFoAUdOhwbuNi8U8_KoCvb3uGHTvHco0wHQYDVR0OBBYEFE9_Zz1qQuzOlnNmLOEjQnzvQoj5MHgGCCsGAQUFBwEBBGwwajBoBggrBgEFBQcwAoZcaHR0cHM6Ly9maWRvYWxsaWFuY2UuY28ubnovdHBtcGtpL05DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QS5jcnQwDQYJKoZIhvcNAQELBQADggEBAI-t9Opuc5rr7FrOUD0jJaXm-jg84L7QWeKoJ67znWGH09D0SBLsARPTAexUjDYQdoF7nWm4viw9NTXhUk3qLxd4G9602r8ht1FmgyqZz_jHLDnGJniXjJm5ILizCdwjlSDcN68lSkKcwAp5uScSorT9EDhB067Pexs4oJUo1-ZicdHyYsJu0i6wqhq2OVVufj2vifU82fw-xPzGkP4RXyWKWnxBfD2ofrLilL24GEIlrpB48y8EKeH8zsFGirsSM8wtT6pa0hBz2OBW4YWkGpOxNHIXTuafOS6ZLqeugg1P0KutUgGrdcQzZwcN6t9OwEV1imd3vmIgGD13qgCldN5ZBgUwggYBMIID6aADAgECAg8EV2dM14jMuwRaKXATKH8wDQYJKoZIhvcNAQELBQAwgb8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxNjA0BgNVBAMMLUZJRE8gRmFrZSBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxODExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzAeFw0xNzAyMDEwMDAwMDBaFw0zNTAxMzEyMzU5NTlaMEExPzA9BgNVBAMTNk5DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANc-c30RpQd-_LCoiLJbXz3t_vqciOIovwjez79_DtVgi8G9Ph-tPL-lC0ueFGBMSPcKd_RDdSFe2QCYQd9e0DtiFxra-uWGa0olI1hHI7bK2GzNAZSTKEbwgqpf8vXMQ-7SPajg6PfxSOLH_Nj2yd6tkNkUSdlGtWfY8XGB3n-q--nt3UHdUQWEtgUoTe5abBXsG7MQSuTNoad3v6vk-tLd0W44ivM6pbFqFUHchx8mGLApCpjlVXrfROaCoc9E91hG9B-WNvekJ0dM6kJ658Hy7yscQ6JdqIEolYojCtWaWNmwcfv--OE1Ax_4Ub24gl3hpB9EOcBCzpb4UFmLYUECAwEAAaOCAXUwggFxMAsGA1UdDwQEAwIBhjAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzAbBgNVHSUEFDASBgkrBgEEAYI3FSQGBWeBBQgDMBIGA1UdEwEB_wQIMAYBAf8CAQAwHQYDVR0OBBYEFHTocG7jYvFPPyqAr297hh07x3KNMB8GA1UdIwQYMBaAFEMRFpma7p1QN8JP_uJbFckJMz8yMGgGA1UdHwRhMF8wXaBboFmGV2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9jcmwvRklETyBGYWtlIFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE4LmNybDBvBggrBgEFBQcBAQRjMGEwXwYIKwYBBQUHMAKGU2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9GSURPIEZha2UgVFBNIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTguY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQBI6GeuxIkeKcmRmFQnkPnkvSybRIJEkzWKa2f00vdBygxtzpkXF2WMHbvuMU3_K3WMFzg2xkSPjM3x_-UxOWGYgVIq8fXUdy2NhmLz4tPI65_nQXpS22rzmXFzsj4x9yS0JF2NnW5xm-O8UdckFdwIZx4Ew_zA-rIF3hqbY4Ejz2AdsbvHJo-WTpu-wWDbBQyR19eqNyYZ6vf9K8DB2JZviIDXdOpkuOJLA40MKMlnhv5K4BZs7mDZIaPzNA_MrcH3_dYXq4tIoGu5Pr1ZNCQ--93XYG1eRbvCgSDYUCRza5AgBGCIhmx2-tqLYeCd9qdy4O9R9c9qRjEThbjnGStYZ0DuB6VCaH1WjiRqyq4VNi9cv15-RoC4zswWwuHee97AAJ_Tx29w6S4Kw9DQR6A0vtw_OHLuOkGH63ns0DACf_h1MvsAMnXXX0Q0P8IpNdBQGvLvrRtRdBNx06NHY1HGZOZ9PdJ6J4mnroB2ln3cMGZG9kyRv2vbwq6sCrYZVYjo3tf4MUtkEY4FijoYbMEDK7VlbTiDPnobhkxI1-bz5DTFnR3IfVybYAeGrBCKSg2UUTPvVgM3WZ-oGlP8W9dg1347hqgxP0vLgDM6cV7rhaFC_ZAf2Et9KLRZSj7lNpJWxHxPyz9mM4w3qFwdgWKwlXl3OQtJRT4Kbs6r3gzB5WdwdWJBcmVhWQE2AAEACwAGBHIAIJ3_y_NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi_rSKuABAAEAgAAAAAAAEAs5f8A9uD2ec_qaNha8KEFXXdd4KLfwpC_KeAfzbyQQuTsAGCg4pYov8I_tAgPDGp26UiJ8fU3Z8-rfdTobncFE9PlvwR0iyvzKhXI2Vq0eS2FZlac9RIB9w6zk62uAJaIBKtg9gmJLT6z3u46BPqE97wGFyvL80Ay0cmsSP2dakuCi5SwnWo1vDxqcNWEYzA8OrOvRmVPJl5IDTzAlIdU2dW5wryUzvX55i4w46nUBkVOG1qPLRYwi_INftlg_9p9PrcLep_lKMeVZ0dXUCRuGsDJWpwQpBhqTm91gQ0PCtdGCSdnrz4SShiWoQb7tg8ZquqSwgFwr9JmtxB4_j5g2hjZXJ0SW5mb1ih_1RDR4AXACIACxHmjtRNtTcuFCluL4Ssx4OYdRiBkh4w_CKgb4tzx5RTABS0TKJrlCTTWAOuZgxyOOh4sQ-ftQAAAAFHcBdIVWl7S8aFYKUBc375jTRWVfsAIgAL9vygl2NWFPZdCG3U1TrQ6RqfwNj7JxfCS5KpKXX44JEAIgAL4hZ6iGIhUFHeo5Tst6Kcwm-Nfh0I366P3MLYgbSPuhxoYXV0aERhdGFZAWc93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAABh8kS2flNkT9WfkMOWInMX2wAgoELnad0f6-g2BtzEn_78iLNoubarlq0xFtOtAMXnflWkAQMDOf_-IFkBALOX_APbg9nnP6mjYWvChBV13XeCi38KQvyngH828kELk7ABgoOKWKL_CP7QIDwxqdulIifH1N2fPq33U6G53BRPT5b8EdIsr8yoVyNlatHkthWZWnPUSAfcOs5OtrgCWiASrYPYJiS0-s97uOgT6hPe8Bhcry_NAMtHJrEj9nWpLgouUsJ1qNbw8anDVhGMwPDqzr0ZlTyZeSA08wJSHVNnVucK8lM71-eYuMOOp1AZFThtajy0WMIvyDX7ZYP_afT63C3qf5SjHlWdHV1AkbhrAyVqcEKQYak5vdYENDwrXRgknZ68-EkoYlqEG-7YPGarqksIBcK_SZrcQeP4-YMhQwEAAQ',
        clientDataJSON:
          'eyJvcmlnaW4iOiJodHRwczovL2Rldi5kb250bmVlZGEucHciLCJjaGFsbGVuZ2UiOiJmNGU4ZDg3Yi1kMzYzLTQ3Y2MtYWI0ZC0xYTg0NjQ3YmYyNDUiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
      },
      type: 'public-key',
      clientExtensionResults: {},
    },
    expectedChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.attestationInfo?.fmt).toEqual('tpm');
  expect(verification.attestationInfo?.counter).toEqual(97);
  expect(verification.attestationInfo?.credentialPublicKey).toEqual(
    base64url.toBuffer(
      'pAEDAzn__iBZAQCzl_wD24PZ5z-po2FrwoQVdd13got_CkL8p4B_NvJBC5OwAYKDilii_wj-0CA8ManbpSInx9Tdnz6t91OhudwUT0-W_BHSLK_MqFcjZWrR5LYVmVpz1EgH3DrOTra4AlogEq2D2CYktPrPe7joE-oT3vAYXK8vzQDLRyaxI_Z1qS4KLlLCdajW8PGpw1YRjMDw6s69GZU8mXkgNPMCUh1TZ1bnCvJTO9fnmLjDjqdQGRU4bWo8tFjCL8g1-2WD_2n0-twt6n-Uox5VnR1dQJG4awMlanBCkGGpOb3WBDQ8K10YJJ2evPhJKGJahBvu2Dxmq6pLCAXCv0ma3EHj-PmDIUMBAAE',
    ),
  );
  expect(verification.attestationInfo?.credentialID).toEqual(
    base64url.toBuffer('oELnad0f6-g2BtzEn_78iLNoubarlq0xFtOtAMXnflU'),
  );
});

test('should validate Android-Key response', async () => {
  const expectedChallenge = '14e0d1b6-9c36-4849-aeec-ea64676449ef';
  const verification = await verifyAttestationResponse({
    credential: {
      id: 'PPa1spYTB680cQq5q6qBtFuPLLdG1FQ73EastkT8n0o',
      rawId: 'PPa1spYTB680cQq5q6qBtFuPLLdG1FQ73EastkT8n0o',
      response: {
        attestationObject:
          'o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiBzpQmnQw6jn-V33XTmlvkw4wyUW-CbyYd5Bltvl_8oHwIgY05YGCJIawM1INNQg4cshJKi847UVUBURLNkTd-BC2hjeDVjglkDGjCCAxYwggK9oAMCAQICAQEwCgYIKoZIzj0EAwIwgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwIBcNNzAwMjAxMDAwMDAwWhgPMjA5OTAxMzEyMzU5NTlaMCkxJzAlBgNVBAMMHkZBS0UgQW5kcm9pZCBLZXlzdG9yZSBLZXkgRkFLRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEjCq7woGNN_42rbaqMgJvz0nuKTWNRrR29lMX3J239o6IcAXqPJPIjSrClHDAmbJv_EShYhYq0R9-G3k744n7ajggEWMIIBEjALBgNVHQ8EBAMCB4AwgeEGCisGAQQB1nkCAREEgdIwgc8CAQIKAQACAQEKAQAEIEwhPC-SlsMm-UdaXBdqAIDXqyRDtjXSeja589CMqyF2BAAwab-FPQgCBgFe0-PPoL-FRVkEVzBVMS8wLQQoY29tLmFuZHJvaWQua2V5c3RvcmUuYW5kcm9pZGtleXN0b3JlZGVtbwIBATEiBCB0z8tQdIj1KRCFkcelBZGfMncy-8HYA1Jq6pgABtLYmDAyoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBAr-FPgMCAQC_hT8CBQAwHwYDVR0jBBgwFoAUo9KqLO8NjPIkAtUctGC8v2pbJBQwCgYIKoZIzj0EAwIDRwAwRAIgHl4jYMq7nEV6pcuXJFNOsZHSX5Zn1UDy6RI9zsDR-C4CICNfJrQW1jyEuRUM1xR8VmKjkjIa2W22Z7NdyZz1CQq-WQMYMIIDFDCCArqgAwIBAgIBAjAKBggqhkjOPQQDAjCB3DE9MDsGA1UEAww0RkFLRSBBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTkwNDI1MDU0OTMyWhcNNDYwOTEwMDU0OTMyWjCB5DFFMEMGA1UEAww8RkFLRSBBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBGQUtFMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKtQYStiTRe7w7UbBEk7BUkLjB-LnbzzebLe3KB8UqHXtg3TIXXcK37dvCbbCNVfhvZxtpTcME2kooqMTgOm9cejYzBhMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgKEMB0GA1UdDgQWBBSj0qos7w2M8iQC1Ry0YLy_alskFDAfBgNVHSMEGDAWgBRSmhsy4FaqzVEP71-ANwaL8pEjHTAKBggqhkjOPQQDAgNIADBFAiEAsW8uQC-0es5tOY3w_T7IshPj3o__B5IQRsHq8IlZKH0CIG75Q6isJ4twXhaLE4b0TkuLadd7i4zarqZsoaSWXy75aGF1dGhEYXRhWKQ93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAABsVQ5LVKpHQJ-alRq3bBMBMQAgPPa1spYTB680cQq5q6qBtFuPLLdG1FQ73EastkT8n0qlAQIDJiABIVggSMKrvCgY03_jattqoyAm_PSe4pNY1GtHb2Uxfcnbf2giWCDohwBeo8k8iNKsKUcMCZsm_8RKFiFirRH34beTvjiftg',
        clientDataJSON:
          'eyJvcmlnaW4iOiJodHRwczovL2Rldi5kb250bmVlZGEucHciLCJjaGFsbGVuZ2UiOiIxNGUwZDFiNi05YzM2LTQ4NDktYWVlYy1lYTY0Njc2NDQ5ZWYiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
      },
      type: 'public-key',
      clientExtensionResults: {},
    },
    expectedChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.attestationInfo?.fmt).toEqual('android-key');
  expect(verification.attestationInfo?.counter).toEqual(108);
  expect(verification.attestationInfo?.credentialPublicKey).toEqual(
    base64url.toBuffer(
      'pQECAyYgASFYIEjCq7woGNN_42rbaqMgJvz0nuKTWNRrR29lMX3J239oIlgg6IcAXqPJPIjSrClHDAmbJv_EShYhYq0R9-G3k744n7Y',
    ),
  );
  expect(verification.attestationInfo?.credentialID).toEqual(
    base64url.toBuffer('PPa1spYTB680cQq5q6qBtFuPLLdG1FQ73EastkT8n0o'),
  );
});

test('should support multiple possible origins', async () => {
  const verification = await verifyAttestationResponse({
    credential: attestationNone,
    expectedChallenge: attestationNoneChallenge,
    expectedOrigin: ['https://dev.dontneeda.pw', 'https://different.address'],
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toBe(true);
});

test('should throw an error if origin not in list of expected origins', async () => {
  await expect(
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: ['https://different.address'],
      expectedRPID: 'dev.dontneeda.pw',
    }),
  ).rejects.toThrow(/unexpected attestation origin/i);
});

test('should support multiple possible RP IDs', async () => {
  const verification = await verifyAttestationResponse({
    credential: attestationNone,
    expectedChallenge: attestationNoneChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: ['dev.dontneeda.pw', 'simplewebauthn.dev'],
  });

  expect(verification.verified).toBe(true);
});

test('should throw an error if RP ID not in list of possible RP IDs', async () => {
  await expect(
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: ['simplewebauthn.dev'],
    }),
  ).rejects.toThrow(/unexpected rp id/i);
});

/**
 * Various Attestations Below
 */

const attestationFIDOU2F: AttestationCredentialJSON = {
  id: 'VHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUQ',
  rawId: 'VHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUQ',
  response: {
    attestationObject:
      'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgRYUftNUmhT0VWTZmIgDmrOoP26Pcre-kL3DLnCrXbegCIQCOu_x5gqp-Rej76zeBuXlk8e7J-9WM_i-wZmCIbIgCGmN4NWOBWQLBMIICvTCCAaWgAwIBAgIEKudiYzANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzE5ODA3MDc1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKgOGXmBD2Z4R_xCqJVRXhL8Jr45rHjsyFykhb1USGozZENOZ3cdovf5Ke8fj2rxi5tJGn_VnW4_6iQzKdIaeP6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQByV9A83MPhFWmEkNb4DvlbUwcjc9nmRzJjKxHc3HeK7GvVkm0H4XucVDB4jeMvTke0WHb_jFUiApvpOHh5VyMx5ydwFoKKcRs5x0_WwSWL0eTZ5WbVcHkDR9pSNcA_D_5AsUKOBcbpF5nkdVRxaQHuuIuwV4k1iK2IqtMNcU8vL6w21U261xCcWwJ6sMq4zzVO8QCKCQhsoIaWrwz828GDmPzfAjFsJiLJXuYivdHACkeJ5KHMt0mjVLpfJ2BCML7_rgbmvwL7wBW80VHfNdcKmKjkLcpEiPzwcQQhiN_qHV90t-p4iyr5xRSpurlP5zic2hlRkLKxMH2_kRjhqSn4aGF1dGhEYXRhWMQ93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAAAAAAAAAAAAAAAAAAAAAAAAAABAVHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUaUBAgMmIAEhWCDIkcsOaVKDIQYwq3EDQ-pST2kRwNH_l1nCgW-WcFpNXiJYIBSbummp-KO3qZeqmvZ_U_uirCDL2RNj3E5y4_KzefIr',
    clientDataJSON:
      'eyJjaGFsbGVuZ2UiOiJkRzkwWVd4c2VWVnVhWEYxWlZaaGJIVmxSWFpsY25sQmRIUmxjM1JoZEdsdmJnIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9',
  },
  clientExtensionResults: {},
  type: 'public-key',
};
const attestationFIDOU2FChallenge = base64url.encode('totallyUniqueValueEveryAttestation');

const attestationPacked: AttestationCredentialJSON = {
  id: 'bbb',
  rawId: 'bbb',
  response: {
    attestationObject:
      'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhANvrPZMUFrl_rvlgR' +
      'qz6lCPlF6B4y885FYUCCrhrzAYXAiAb4dQKXbP3IimsTTadkwXQlrRVdxzlbmPXt847-Oh6r2hhdXRoRGF0YVjhP' +
      'dxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KBFXsOO-a3OAAI1vMYKZIsLJfHwVQMAXQGE4WNXLCDWOCa2x' +
      '8hpqk5dZy_xdc4wBd4UgCJ4M_JAHI7oJgDDVb8WUcKqRB_mzRxwCL9vdTl-ZKPXg3_-Zrt1Adgb7EnK9ivqaTOKM' +
      'DqRrKsIObWYJaqpsSJtUKUBAgMmIAEhWCBKMVVaivqCBpqqAxMjuCo5jMeUdh3jDOC0EF4fLBNNTyJYILc7rqDDe' +
      'X1pwCLrl3ZX7IThrtZNwKQVLQyfHiorqP-n',
    clientDataJSON:
      'eyJjaGFsbGVuZ2UiOiJjelpRU1dKQ2JsQlFibkpIVGxOQ2VFNWtkRVJ5VkRkVmNsWlpT' +
      'a3M1U0UwIiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0' +
      'ZSJ9',
  },
  clientExtensionResults: {},
  type: 'public-key',
};
const attestationPackedChallenge = base64url.encode('s6PIbBnPPnrGNSBxNdtDrT7UrVYJK9HM');

const attestationPackedX5C: AttestationCredentialJSON = {
  // TODO: Grab these from another iPhone attestation
  id: 'aaa',
  rawId: 'aaa',
  response: {
    attestationObject:
      'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAIMt_hGMtdgpIVIwMOeKK' +
      'w0IkUUFkXSY8arKh3Q0c5QQAiB9Sv9JavAEmppeH_XkZjB7TFM3jfxsgl97iIkvuJOUImN4NWOBWQLBMIICvTCCAaWgA' +
      'wIBAgIEKudiYzANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwM' +
      'DYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1Ymljb' +
      'yBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpY' +
      'WwgNzE5ODA3MDc1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKgOGXmBD2Z4R_xCqJVRXhL8Jr45rHjsyFykhb1USG' +
      'ozZENOZ3cdovf5Ke8fj2rxi5tJGn_VnW4_6iQzKdIaeP6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4M' +
      'i4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBA' +
      'f8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQByV9A83MPhFWmEkNb4DvlbUwcjc9nmRzJjKxHc3HeK7GvVkm0H4XucVDB4j' +
      'eMvTke0WHb_jFUiApvpOHh5VyMx5ydwFoKKcRs5x0_WwSWL0eTZ5WbVcHkDR9pSNcA_D_5AsUKOBcbpF5nkdVRxaQHuu' +
      'IuwV4k1iK2IqtMNcU8vL6w21U261xCcWwJ6sMq4zzVO8QCKCQhsoIaWrwz828GDmPzfAjFsJiLJXuYivdHACkeJ5KHMt' +
      '0mjVLpfJ2BCML7_rgbmvwL7wBW80VHfNdcKmKjkLcpEiPzwcQQhiN_qHV90t-p4iyr5xRSpurlP5zic2hlRkLKxMH2_k' +
      'RjhqSn4aGF1dGhEYXRhWMQ93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAAAcbUS6m_bsLkm5MAyP6SDLc' +
      'wBA4rrvMciHCkdLQ2HghazIp1sMc8TmV8W8RgoX-x8tqV_1AmlqWACqUK8mBGLandr-htduQKPzgb2yWxOFV56TlqUBA' +
      'gMmIAEhWCBsJbGAjckW-AA_XMk8OnB-VUvrs35ZpjtVJXRhnvXiGiJYIL2ncyg_KesCi44GH8UcZXYwjBkVdGMjNd6LF' +
      'myiD6xf',
    clientDataJSON:
      'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZEc5MFlXeHNlVlZ1YVhG' +
      'MVpWWmhiSFZsUlhabGNubFVhVzFsIiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3In0=',
  },
  clientExtensionResults: {},
  type: 'public-key',
};
const attestationPackedX5CChallenge = base64url.encode('totallyUniqueValueEveryTime');

const attestationNone: AttestationCredentialJSON = {
  id: 'AdKXJEch1aV5Wo7bj7qLHskVY4OoNaj9qu8TPdJ7kSAgUeRxWNngXlcNIGt4gexZGKVGcqZpqqWordXb_he1izY',
  rawId: 'AdKXJEch1aV5Wo7bj7qLHskVY4OoNaj9qu8TPdJ7kSAgUeRxWNngXlcNIGt4gexZGKVGcqZpqqWordXb_he1izY',
  response: {
    attestationObject:
      'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFPdxHEOnAiLIp26idVjIguzn3I' +
      'pr_RlsKZWsa-5qK-KBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQHSlyRHIdWleVqO24-6ix7JFWODqDWo_arvEz3Se' +
      '5EgIFHkcVjZ4F5XDSBreIHsWRilRnKmaaqlqK3V2_4XtYs2pQECAyYgASFYID5PQTZQQg6haZFQWFzqfAOyQ_ENs' +
      'MH8xxQ4GRiNPsqrIlggU8IVUOV8qpgk_Jh-OTaLuZL52KdX1fTht07X4DiQPow',
    clientDataJSON:
      'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYUVWalkxQlhkWHBw' +
      'VURBd1NEQndOV2Q0YURKZmRUVmZVRU0wVG1WWloyUSIsIm9yaWdpbiI6Imh0dHBzOlwvXC9kZXYuZG9udG5lZWRh' +
      'LnB3IiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoib3JnLm1vemlsbGEuZmlyZWZveCJ9',
  },
  clientExtensionResults: {},
  type: 'public-key',
};
const attestationNoneChallenge = base64url.encode('hEccPWuziP00H0p5gxh2_u5_PC4NeYgd');
