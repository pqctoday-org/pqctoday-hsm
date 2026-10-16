# Terms of Service

**Effective Date:** March 22, 2026
**Last Updated:** October 15, 2026

## 1. About these Terms

These Terms of Service ("Terms") accompany SoftHSMv3 (the "Software"), available at [https://github.com/pqctoday/softhsmv3](https://github.com/pqctoday/softhsmv3) and its associated npm package (`@pqctoday/softhsm-wasm`). They are notices and disclaimers. Your rights to use, copy, modify and distribute the Software come from its licence (section 2), and these Terms add no conditions to it.

## 2. License

The code written for the Software by PQC Today, LLC is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0-only)**, with a commercial licence on request; the files taken from SoftHSM2 keep the **BSD 2-Clause License**, and vendored third-party code keeps its own licence. [COPYRIGHT.md](./COPYRIGHT.md) says which parts are under which licence; the texts are in [LICENSE](./LICENSE) and [LICENSES/](./LICENSES/). Nothing in these Terms restricts rights granted under those licences.

## 3. Purpose and Cryptographic Disclaimer

SoftHSMv3 is a **PQC-enabled HSM emulation library** forked from SoftHSM2 v2.7.0. It implements PKCS#11 v3.2 with ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) support. It is intended for **development, testing, education, and prototyping purposes**.

**Disclaimer:**

- The Software is not certified. It is not FIPS 140-3 validated and has no Common Criteria or equivalent certification.
- The Software is not a substitute for a certified hardware security module (HSM) and is not intended for production keys, production credentials, or financial transactions.
- The Software emulates PKCS#11 v3.2 operations in software (and WebAssembly) without the tamper resistance of a hardware HSM.

## 4. Export Compliance and Sanctions

### 4.1 Classification

The Software contains cryptographic functionality classified under **Export Control Classification Number (ECCN) 5D002** pursuant to the U.S. Export Administration Regulations (EAR). This includes but is not limited to: OpenSSL-backed implementations of ML-KEM, ML-DSA, SLH-DSA, AES, RSA, ECDSA, ECDH, and key derivation mechanisms.

### 4.2 License Exception

Distribution is authorized under **License Exception TSU (§740.13 EAR)** for publicly available encryption source code and **License Exception ENC (§740.17 EAR)** for mass-market encryption software.

### 4.3 Your responsibility for export and sanctions law

Users are responsible for complying with the export control and sanctions laws that apply to them. U.S. law, for example, restricts exports to countries and territories under comprehensive U.S. sanctions (such as Cuba, Iran, North Korea, Syria, and the Crimea, Donetsk and Luhansk regions of Ukraine) and to parties on the BIS Entity List, the Treasury Department's Specially Designated Nationals (SDN) List, or other restricted party lists. This section is a notice about the law, not a condition of the licence.

## 5. Notices on use

- Users are responsible for using the Software lawfully.
- The licence requires redistributions to keep the copyright and licence notices.
- The Software is not a certified or validated cryptographic module (FIPS 140-3, Common Criteria, or equivalent); a product built on it is certified only if it obtains its own certification.
- PQC Today, LLC does not endorse use of the Software to develop weapons, conduct surveillance, or violate human rights.

## 6. No Warranty

THE SOFTWARE IS PROVIDED "AS IS" AND WITHOUT WARRANTIES OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, OR NON-INFRINGEMENT. This is consistent with the AGPL-3.0 and the BSD 2-Clause License.

## 7. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE MAINTAINERS, CONTRIBUTORS, AND AFFILIATES OF SOFTHSMV3 SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS, DATA, OR GOODWILL, ARISING FROM YOUR USE OF OR INABILITY TO USE THE SOFTWARE.

## 8. Third-Party Components

The Software incorporates or depends on third-party components including:

- **SoftHSM2** (OpenDNSSEC project) — original upstream, BSD 2-Clause
- **OpenSSL** — Apache 2.0 License
- **OASIS PKCS#11 v3.2 headers** — OASIS IPR Policy

Each component is subject to its own license terms.

## 9. Intellectual Property

- The code written by PQC Today, LLC is licensed under AGPL-3.0-only; the SoftHSM2 files under BSD 2-Clause (see COPYRIGHT.md).
- PQC algorithm implementations (ML-KEM, ML-DSA, SLH-DSA) are based on NIST FIPS 203/204/205 standards, which are in the public domain.
- The PKCS#11 v3.2 specification is published by OASIS under its IPR Policy.

## 10. Modifications

These Terms may be updated at any time. Changes are indicated by updating the "Last Updated" date.

## 11. Governing Law

These Terms are governed by and construed in accordance with the laws of the State of Texas, United States, without regard to its conflict of law provisions.

## 12. Contact

For questions about these Terms, please open an issue on [GitHub](https://github.com/pqctoday/softhsmv3/issues) or contact the maintainers through the repository.

---

_SoftHSMv3 is an open-source, community-driven project. These Terms supplement — and do not replace — the rights and obligations under the BSD 2-Clause License._
