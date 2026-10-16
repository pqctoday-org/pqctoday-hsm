# Terms of Use

## 1. Educational and Experimental Purpose
SoftHSMv3 is an experimental, post-quantum cryptography (PQC) integration platform designed **exclusively for educational, testing, and research purposes.** 

This software is **not intended, tested, or certified for production environments**, high-availability operations, or the protection of sensitive commercial data.

## 2. No Warranty or Liability
This software is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.

## 3. Cryptographic State and Ephemerality
Please be advised that certain environments (such as the WASM memory model) are strictly ephemeral. Loss of stateful keys (e.g., XMSS or LMS variants) can result in catastrophic security failures if those keys are exported or reused across different sessions. SoftHSMv3 does not inherently provide durability guarantees in its default browser-based engine.

## 4. Certification Limitations
Unlike hardware security modules, SoftHSMv3 is a software abstraction layer. It **does not provide physical security guarantees**, side-channel resistance, or tamper-evident features. It is not a replacement for FIPS 140-2/3 Level 3+ HSMs in enterprise deployments.

These are notices and disclaimers; they add no conditions to the software licence in LICENSE. Users assume the risks of operating the software.
