# openpgp-pkcs11-tools

> **pqctoday fork note:** this crate is vendored from upstream
> [`heiko/openpgp-pkcs11`](https://codeberg.org/heiko/openpgp-pkcs11) — the
> content below is the **upstream** README and its examples (YubiKey,
> YubiHSM, generic SoftHSMv2, classical RSA/ECC keys only). It does not
> mention this fork's actual purpose: the `opgpkcs11` binary here also
> uploads/signs/decrypts with **post-quantum** composite ML-DSA/ML-KEM keys
> (plus standalone Ed448) against **softhsmv3**. See
> [`../README.md`](../README.md) for the fork-specific overview and the
> `openpgp/smoke-*` crates for real, HSM-verified PQC command examples.

[![crates.io openpgp-pkcs11-tools](https://img.shields.io/crates/v/openpgp-pkcs11-tools.svg)](https://crates.io/crates/openpgp-pkcs11-tools)
[![status-badge](https://ci.codeberg.org/api/badges/heiko/openpgp-pkcs11/status.svg)](https://ci.codeberg.org/heiko/openpgp-pkcs11)
[![Mastodon](https://img.shields.io/badge/mastodon-read-5da168.svg)](https://fosstodon.org/@hko)
[![Matrix: #openpgp-card:matrix.org](https://matrix.to/img/matrix-badge.svg)](https://matrix.to/#/#openpgp-card:matrix.org)

This crate implements `opgpkcs11`, an exploratory CLI tool that exposes the functionality in
[openpgp-pkcs11-sequoia](https://crates.io/crates/openpgp-pkcs11-sequoia)
to use PKCS #&#8203;11 devices in an OpenPGP context.

The tool can be used to upload OpenPGP component keys to PKCS #&#8203;11 devices,
and use these keys to perform OpenPGP signing and decryption operations.

This tool can also be used to migrate
[gnupg-pkcs11-scd](https://github.com/alonbl/gnupg-pkcs11-scd)-based setups
to Sequoia PGP.
In this use case, the OpenPGP public key (or OpenPGP certificate) is required
alongside the PKCS #&#8203;11 device (the OpenPGP certificate is necessary
to access OpenPGP metadata that is not available on the HSM).

## Signing via PKCS #&#8203;11

Once a signing subkey has been loaded onto an HSM, it can be used to sign as an
OpenPGP key (the tool produces a detached signature).

```shell
$ echo "hello world" | cargo run --bin opgpkcs11 -- sign --serial 16019180 --id 2
-----BEGIN PGP MESSAGE-----

wsAdBAATCgBvBYJj9RTACRDgxC4SrzU3rkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u
cy5zZXF1b2lhLXBncC5vcmcbgC3H5TAyHrskkS/Df1YhQm0hOxV2PR//4p0LHA7k
cRYhBNbjGCcsr64WE/F/t+DELhKvNTeuAABosAF/Yd26f75FMeP8uSVFR2+4J593
F+O5+U5kx1Fo1IXX6gNhrLuniEq7fDrbflFStbuCAX47Cd/+D/IlC6YSf//W9etl
sd4uMBq3AWNU3IwYJpm3/Zcx0L/2CTVa3hYa/jWmCm8=
=/R5+
-----END PGP MESSAGE-----
```

NOTE: On the YubiKey 4/5, `--id 2` corresponds to the PIV "Digital Signature" slot (PIV 9c).
Read more about ykcs11 Key Mapping
[here](https://developers.yubico.com/yubico-piv-tool/YKCS11/#_key_mapping).

(If the default path for the PKCS #&#8203;11 module `/usr/lib64/libykcs11.so` isn't correct on your
system, you need to provide a path with the parameter `--module`.)

After storing this detached signature in `/tmp/sig`, we can verify it with sq:

```shell
$ echo "hello world" | sq verify --signer-file /tmp/janus.pgp --detached /tmp/sig
Good signature from E0C42E12AF3537AE
1 good signature.
```

## Decryption via PKCS #&#8203;11

Analogous to signing (above), a PKCS #&#8203;11 device can be used to perform OpenPGP decryption operations:

Let's make an encrypted message:

```shell
$ echo "secret message!" | sq encrypt --recipient-file /tmp/janus.pgp > /tmp/secret.pgp
```

(If the default path for the PKCS #&#8203;11 module `/usr/lib64/libykcs11.so` isn't correct on your
system, you need to provide a path with the parameter `--module`.)

Now we can decrypt the message on the card:

```shell
$ cat /tmp/secret.pgp | cargo run --bin opgpkcs11 -- decrypt --serial 16019180 --id 3
secret message!
```

NOTE: On the YubiKey 4/5, `--id 3` corresponds to the PIV "KeyManagement" slot (PIV 9d).
Read more about ykcs11 Key Mapping
[here](https://developers.yubico.com/yubico-piv-tool/YKCS11/#_key_mapping)
(IDs 5-24 can be used to address "Retired Key Management" slots).

## Uploading to PKCS #&#8203;11

```
cargo run --bin opgpkcs11 -- upload --serial 1234 --id 2 --key /tmp/janus.rsa2 --fingerprint E35AE0F1494FBE1098014BD61E71CF45C4A31FEC
```

NOTE: uploading to YubiKey 4/5 via the ykcs11 driver currently doesn't work (due to limitations of the ykcs11 driver).
As an alternative, OpenPGP keys can be uploaded to these devices via the PIV interface, and then used for signing and
decryption via PKCS #&#8203;11.

# Hardware devices with PKCS #&#8203;11 support

Notes on some specific devices that can be accessed via PKCS #&#8203;11.

## YubiKey 4/5

https://developers.yubico.com/PIV/

- [YKCS11 module](https://developers.yubico.com/yubico-piv-tool/YKCS11/) (shows PIV to ykcs11 id mapping)

### Example setup using YubiKey PIV CLI tools

Reset PIV application on the card:

`$ ykman piv reset`

Generate a new key in slot '9d' ("Key Management") and export the public key into the file `public-9d.pem`:

`$ yubico-piv-tool -s 9d -a generate -A ECCP256 -o public-9d.pem`

(To inspect a public key ECC file: `openssl ec -pubin -in pubkey.pem -text`)


Generate a new key in slot '9a' ("PIV Authentication"), using RSA by default, and export the public key into the file `public-9a.pem`:

`$ yubico-piv-tool -s 9a -a generate -o public-9a.pem`


Dynamic library for PKCS #&#8203;11 access:

`$ export MODULE=/usr/lib64/libykcs11.so`

Inspect "objects" on the card:

`$ pkcs11-tool --module $MODULE -O`

### Supported functionality and limitations

The YubiKey PIV applet (which is optionally accessible via a PKCS #&#8203;11
interface) supports RSA 2048, NIST P-256 and NIST P-384.
Signing and decryption operations are supported with keys that use those
algorithms.

Upload to the card via the PKCS #&#8203;11 interface is not currently
supported, due to limitations of the `ykcs11` driver. However, keys can be
uploaded to the card using the PIV interface, and then used for cryptographic
operations via PKCS#&#8203;11.

### Notes

- [Retired PIV Slots Unavailable When Accessing via PKCS11](https://support.yubico.com/hc/en-us/articles/4585159896220-Troubleshooting-Retired-PIV-Slots-Unavailable-When-Accessing-via-PKCS11)

## YubiHSM 2

https://developers.yubico.com/YubiHSM2/Usage_Guides/YubiHSM_quick_start_tutorial.html

### USB access (udev)

Access to the USB device needs to be granted, e.g. with a udev rule like:

`/etc/udev/rules.d/10-yubihsm.rules`:

```
SUBSYSTEM=="usb", ATTRS{idVendor}=="1050", ATTRS{idProduct}=="0030", OWNER="username"
```

If necessary, reload the rules:

```
# udevadm control --reload-rules
```

NOTE: On my system, the YubiHSM2 didn't work when connected to USB3 ports.
If you have trouble, try different USB ports, and/or USB hubs.

### yubihsm-connector

"The Connector, yubihsm-connector, performs the communication between the YubiHSM 2 and applications that use it":

https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/

```
$ yubihsm-connector -d
```

Once the connector is running, access to the YubiHSM can be tested via:

```
$ yubihsm-shell
Using default connector URL: http://localhost:12345
yubihsm> connect
Session keepalive set up to run every 15 seconds
```

NOTE: During normal operation, on my system I see regular errors in `yubihsm-connector` output:
`handle_events: error: libusb: interrupted [code -10]`

### Logging in

- https://docs.yubico.com/software/yubihsm-2/component-reference/hsm2-ref-pkcs11.html#logging-in
- https://docs.yubico.com/hardware/yubikey/yk-5/tech-manual/yubihsm-auth.html

By default, logging in with `yubihsm-shell` works like:

```
yubihsm> session open 1 password
```

In `yubihsm-shell`, a KDF-scheme is used:

### List objects

```
yubihsm> connect
Session keepalive set up to run every 15 seconds
yubihsm> session open 1 password
Created session 0
yubihsm> list objects 0 0 asymmetric-key
Found 12 object(s)
id: 0x02f1, type: asymmetric-key, algo: rsa2048, sequence: 0 label:
[..]
id: 0xf6bc, type: asymmetric-key, algo: rsa2048, sequence: 0 label:
```

### Resetting a YubiHSM

```
yubihsm> connect
Session keepalive set up to run every 15 seconds
yubihsm> session open 1 password
Created session 0
yubihsm> reset 0
Device successfully reset
```

### Using YubiHSM2 via PKCS #&#8203;11

https://developers.yubico.com/yubihsm-shell/yubihsm-pkcs11.html

https://github.com/Yubico/yubihsm-shell/blob/master/lib/yubihsm.c#L579

Sources for the YubiHSM PKCS #&#8203;11 module:

https://github.com/Yubico/yubihsm-shell/tree/master/pkcs11

### Testing

`yubihsm_pkcs11.so` can use a configuration file.
Here we use a minimal file `/tmp/ykhsm.conf`:

```
connector=http://localhost:12345
```

Setup:
```
$ export MODULE="/usr/lib64/pkcs11/yubihsm_pkcs11.so"
$ export YUBIHSM_PKCS11_CONF=/tmp/ykhsm.conf
$ export SERIAL=`cargo run --bin opgpkcs11 -- --module $MODULE list`
```

Upload decryption subkey:

```
cargo run --bin opgpkcs11 -- --module $MODULE upload --serial $SERIAL --slot dec --pin 0001password --key /tmp/janus.rsa
```

Decrypt:

```
echo "hello world" | sq encrypt --recipient-file /tmp/janus.rsa  >/tmp/enc
cat /tmp/enc | cargo run --bin opgpkcs11 -- --module $MODULE decrypt --serial $SERIAL --pin 0001password
```

Sign:

```
echo "hello world" | cargo run --bin opgpkcs11 -- --module $MODULE sign --serial $SERIAL --pin 0001password
```

Inspect card state:

```
cargo run --bin opgpkcs11 -- --module $MODULE dump --serial $SERIAL --pin 0001password
```

### Supported functionality

All operations (key upload, signing, decryption) are supported for 
RSA 2048, RSA 3072, RSA 4096, NIST P-256, NIST P-384 and NIST P-521.

# Software Implementations of PKCS #&#8203;11

## SoftHSM2

https://github.com/opendnssec/SoftHSMv2

### Example setup/usage

(Paths for current Fedora, on different distributions exact paths will vary)

Make temporary storage path and configure SoftHSM to use it:

`$ export SOFTHSM2_CONF=$(mktemp) && DIR=$(mktemp --directory) && echo "directories.tokendir = $DIR" > $SOFTHSM2_CONF`

`$ export MODULE=/usr/lib64/softhsm/libsofthsm.so`

Initialize 'slot 0' on SoftHSM, set User PIN to `123456`, generate RSA key in slot 0:

```
$ pkcs11-tool --init-token --module $MODULE --slot-index 0 --label TestToken --so-pin 12345678
$ pkcs11-tool --init-pin --login --so-pin 12345678 --pin 123456 --slot-index 0 --module $MODULE
$ pkcs11-tool --module $MODULE --slot-index 0 --login --pin 123456 --keypairgen --key-type rsa:2048 --id 3
```

Inspect card (needs User PIN):

`$ pkcs11-tool --module $MODULE --test --pin 123456`

### Testing `opgpkcs11` with SoftHSM

"[SoftHSM](https://github.com/opendnssec/SoftHSMv2/) is an implementation of a cryptographic store accessible
through a PKCS #&#8203;11 interface."

#### Init (module path for Fedora, may differ on other systems):

```shell
export SOFTHSM2_CONF=$(mktemp) && DIR=$(mktemp --directory) && echo "directories.tokendir = $DIR" > $SOFTHSM2_CONF
export MODULE=/usr/lib64/softhsm/libsofthsm.so

pkcs11-tool --init-token --module $MODULE --slot-index 0 --label TestToken --so-pin 123456
pkcs11-tool --init-pin --login --so-pin 123456 --pin 123456 --slot-index 0 --module $MODULE
```

#### Generate OpenPGP key for testing

```shell
cargo run --bin janus_gen rsa2048 >/tmp/janus.rsa
```

#### Upload decryption subkey to SoftHSM

You can store the serial of the SoftHSM device in the environment variable `SERIAL` with:

```shell
export SERIAL=`cargo run --bin opgpkcs11 -- --module $MODULE list`
```

```shell
cargo run --bin opgpkcs11 -- --module $MODULE upload --serial $SERIAL --slot dec --key /tmp/janus.rsa
```

#### Encrypt to key, decrypt on card

```shell
echo "hello world" | sq encrypt --recipient-file /tmp/janus.rsa  >/tmp/enc.janus
```

```shell
cat /tmp/enc.janus | cargo run --bin opgpkcs11 -- --module $MODULE decrypt --serial $SERIAL
```

### Supported functionality

On this device, all operations (key upload, signing, decryption) are
supported for the following algorithms:
RSA 2048, RSA 3072, RSA 4096, NIST P-256, NIST P-384 and NIST P-521.

A CI test under `cli/ci/softhsm` tests the full set of operations for all
supported algorithms.
