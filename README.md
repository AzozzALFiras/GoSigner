# GoSigner

**A Go-native iOS code signing implementation for Apple Developer Program
members who re-sign their own applications outside a macOS environment.**

---

## ⚖️ Legal Notice — Read First

GoSigner is intended **exclusively** for use by individuals or entities that are
enrolled in the **Apple Developer Program** and that are signing iOS applications
using **their own valid Apple-issued signing certificates** and **their own
properly provisioned mobileprovision files**.

By using GoSigner you represent and warrant that:

1. You hold a current, valid Apple Developer Program membership.
2. The signing certificate (`*.p12`) in use was issued to you (or to the legal
   entity you are acting on behalf of) by Apple, and the private key is lawfully
   in your possession.
3. Every target device UDID is enrolled in the provisioning profile under your
   Apple developer account.
4. You are resigning applications that **you own, authored, or are otherwise
   authorized to distribute** under the Apple Developer Program License
   Agreement and all other applicable Apple terms.
5. You will **not** use GoSigner to circumvent Apple's technological protection
   measures, to resign or redistribute third-party applications without
   authorization, or to distribute pirated software.

GoSigner does **not** bypass any Apple verification, tamper with any Apple
server-side check, or disable any code-signing enforcement in the iOS runtime.
It simply produces a Mach-O code signature that is structurally conformant to
Apple's publicly documented format, signs it with the caller-supplied private
key, and repackages the IPA. Every cryptographic operation is performed on the
caller's own machine using the caller's own keys. The produced IPA is valid if
and only if the inputs (certificate, profile, UDID) are themselves valid — there
is no protection being circumvented.

**The authors and contributors of GoSigner accept no liability for misuse. Users
are solely responsible for ensuring that their use of this tool complies with
Apple's agreements and with any applicable law in their jurisdiction.**

---

## 📦 Overview

GoSigner reproduces, in pure Go, the signing step that Apple's `codesign(1)`
tool performs on macOS:

```
Unsigned IPA  ──►  GoSigner  ──►  Signed IPA (installable via itms-services)
                      ▲
                      │
                      ├── .p12              (signing identity — leaf cert + private key)
                      └── .mobileprovision  (Apple-issued provisioning profile)
```

The result is byte-compatible with what `codesign` emits on a Mac for the same
inputs, up to timestamp- and nonce-derived bytes (signing time, the CDHash that
depends on MinimumOSVersion bumps, and the RSA signature itself).

GoSigner targets three realistic workflows:

* **Developer on Linux / Windows** — A member of the Apple Developer Program who
  needs to resign their own IPA for internal QA or ad-hoc distribution without
  owning or renting a Mac build machine.
* **CI / automation** — Headless servers that issue signed builds for internal
  testers. The Mac-as-a-service cost is avoided; keys never leave the Linux CI.
* **In-house distribution** — Enterprise Program customers who distribute their
  own IPAs to their own devices and wish to do so from an existing Linux
  application server.

---

## 🧠 How Apple Code Signing Actually Works

The bulk of this document explains the on-disk format GoSigner emits. Every
field is sourced from Apple's own publicly released materials — there is no
reverse engineering of a proprietary binary anywhere in this project. Our
references:

* **Apple Open Source** — `Security.framework` and `libsecurity_codesigning`
  source releases at <https://opensource.apple.com/source/Security/> and
  <https://github.com/apple-oss-distributions/Security>. This is the canonical
  definition of every `CS_*` constant, `fade*` magic, and SuperBlob layout
  described below. Apple publishes it under the APSL license.
* **XNU** — the iOS kernel's code-signing enforcement (`bsd/kern/kern_cs.c`,
  `osfmk/kern/cs_blobs.h`) at
  <https://github.com/apple-oss-distributions/xnu>. This is where the iOS
  runtime actually validates a signature; our layout is driven by what XNU
  accepts.
* **IETF RFCs** — [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652)
  (Cryptographic Message Syntax), [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)
  (X.509), [RFC 3370](https://www.rfc-editor.org/rfc/rfc3370) (CMS algorithms),
  [RFC 5754](https://www.rfc-editor.org/rfc/rfc5754) (SHA-2 in CMS).
* **ITU-T X.690** — DER / BER encoding rules for ASN.1.
* **PKWARE APPNOTE.TXT** — the ZIP specification.
* **Apple's file-format headers** — `<mach-o/loader.h>`, `<mach-o/fat.h>`. These
  are part of the Xcode SDK and are redistributable documentation.

Everything below cites these sources; there is nothing described here that is
not already in Apple's open source tree.

---

## 🔬 The On-Disk Layout, Field by Field

### 1. The Mach-O Container

An iOS executable is a Mach-O (`feedfacf` — 64-bit little-endian, magic
`0xFEEDFACF`). A universal / fat binary starts with `0xCAFEBABE` and contains
multiple slice offsets; GoSigner signs every arm64 slice (CPU type `0x0100000C`).

A Mach-O file is a header followed by *load commands*. The two load commands
GoSigner mutates are:

| Constant | Value | Purpose |
|---|---|---|
| `LC_SEGMENT_64` | `0x19` | Memory segment. `__LINKEDIT.filesize` must cover the appended signature. |
| `LC_CODE_SIGNATURE` | `0x1D` | 16-byte command that points at the code signature blob (`dataoff`, `datasize`). |

A typical `LC_CODE_SIGNATURE` command bytes (before endian flip) are
`1D 00 00 00 10 00 00 00 40 7C 41 00 47 99 00 00`, meaning `cmd=0x1D`,
`cmdsize=0x10`, `dataoff=0x00417C40`, `datasize=0x00009947`.

The code signature lives at the **end of `__LINKEDIT`** — the same file range
that `dataoff..dataoff+datasize` describes. GoSigner rewrites
`__LINKEDIT.filesize` and `LC_CODE_SIGNATURE.datasize` in a three-pass approach
(discover → layout → sign) so that page-0's hash covers the final header
layout, not a stale one.

### 2. The SuperBlob

Magic `0xFADE0CC0`. This is the top-level container of the code signature.
Apple's definition ([libsecurity_codesigning/lib/CSCommon.h](https://opensource.apple.com/source/Security/)):

```
SuperBlob  ::=  magic   (4 bytes, big-endian)  = 0xFADE0CC0
                length  (4 bytes, big-endian)  total byte length incl. this header
                count   (4 bytes, big-endian)  number of slots that follow
                index[] ( count × { slotType:4, offset:4 } )
                blobs   ( actual blob bytes at the offsets above )
```

All integers in the SuperBlob are **big-endian**. The offsets in the index are
measured from the start of the SuperBlob, not from the file.

A typical main-binary SuperBlob has five slots:

| Slot Type | Hex | Contains |
|---|---|---|
| `CSSLOT_CODEDIRECTORY` | `0x00000000` | CodeDirectory (SHA-256) |
| `CSSLOT_REQUIREMENTS` | `0x00000002` | Requirements set (`0xFADE0C01`) |
| `CSSLOT_ENTITLEMENTS` | `0x00000005` | XML entitlements blob (`0xFADE7171`) |
| `CSSLOT_DER_ENTITLEMENTS` | `0x00000007` | DER-encoded entitlements blob (`0xFADE7172`) |
| `CSSLOT_CMS_SIGNATURE` | `0x00010000` | CMS SignedData wrapper (`0xFADE0B01`) |

Frameworks (`.framework/<Binary>`) and loose dylibs use only four: slot `0x7` is
**omitted** — the framework carries no DER entitlements.

### 3. The CodeDirectory (`0xFADE0C02`)

This is the heart of the signature. It is hashed; the hash ends up as the
`messageDigest` attribute of the CMS signer info. GoSigner emits CodeDirectory
**version `0x20400`**, which is defined as:

| Field | Offset | Size | Notes |
|---|---|---|---|
| `magic` | `0x00` | 4 | `0xFADE0C02` |
| `length` | `0x04` | 4 | Total bytes of this CD (big-endian) |
| `version` | `0x08` | 4 | `0x00020400` |
| `flags` | `0x0C` | 4 | Typically `0x00000000` for distribution |
| `hashOffset` | `0x10` | 4 | Offset from CD start to the first page-hash |
| `identOffset` | `0x14` | 4 | Offset from CD start to the NUL-terminated identifier |
| `nSpecialSlots` | `0x18` | 4 | `7` for main/appex, `5` for frameworks |
| `nCodeSlots` | `0x1C` | 4 | `ceil(codeLimit / pageSize)` |
| `codeLimit` | `0x20` | 4 | Everything before the signature blob must be hashed; equals `LC_CODE_SIGNATURE.dataoff` |
| `hashSize` | `0x24` | 1 | `0x20` (SHA-256) |
| `hashType` | `0x25` | 1 | `0x02` (SHA-256, `CS_HASHTYPE_SHA256`) |
| `platform` | `0x26` | 1 | `0x00` |
| `pageSize` | `0x27` | 1 | `0x0C` → `1 << 12` = 4096 bytes |
| `spare2` | `0x28` | 4 | `0x00000000` |
| `scatterOffset` | `0x2C` | 4 | `0x00000000` |
| `teamOffset` | `0x30` | 4 | Offset to NUL-terminated team identifier |
| `spare3` | `0x34` | 4 | `0x00000000` |
| `codeLimit64` | `0x38` | 8 | `0x0000000000000000` (codeLimit < 4 GiB) |
| `execSegBase` | `0x40` | 8 | File offset of the `__TEXT` segment (always `0x0`) |
| `execSegLimit` | `0x48` | 8 | `__TEXT` vmsize, e.g. `0x000000000031C000` |
| `execSegFlags` | `0x50` | 8 | `0x1` for main/appex, `0x0` for frameworks. See below. |

Immediately after the header come, in order:

1. `identifier` string (NUL-terminated UTF-8)
2. `team` string (NUL-terminated UTF-8)
3. The **special slot hashes**, laid out in reverse index order — i.e. the very
   first `hashSize` bytes are slot `-nSpecialSlots`, the next are
   `-(nSpecialSlots-1)`, etc. The byte at `hashOffset - hashSize` is slot `-1`.
4. The **page hashes** — `nCodeSlots` × `hashSize` bytes starting at
   `hashOffset`. Each hash is `SHA-256(page[i])`, where `page[i]` is a slice of
   `pageSize` bytes from the file (the last page may be shorter, capped at
   `codeLimit`).

#### `execSegFlags`

This 64-bit field is the single biggest source of silent-reject behavior on
iOS 26. The bits that matter:

| Name | Value | When to set |
|---|---|---|
| `CS_EXECSEG_MAIN_BINARY` | `0x0000000000000001` | **Always** set on the main Mach-O of any bundle (the app's binary *and* every `.appex`'s binary). Never set on frameworks / dylibs. |
| `CS_EXECSEG_ALLOW_UNSIGNED` | `0x0000000000000010` | Only set when the entitlements grant `get-task-allow = true` (Developer-signed debug builds). Setting it on an Ad-Hoc / Distribution signature where `get-task-allow = false` causes iOS 26 to refuse installation. |

Everything else (`CS_EXECSEG_DEBUGGER`, `CS_EXECSEG_JIT`, …) stays `0` for a
normal iOS app.

#### Special Slots

The seven negative-indexed hashes that sit immediately before `hashOffset`
cover the resources of the bundle:

| Index | Name | Hashes |
|---|---|---|
| `-1` | `CSSLOT_INFOSLOT` | `SHA-256(Info.plist file bytes)` |
| `-2` | `CSSLOT_REQUIREMENTS` | `SHA-256(Requirements blob — the entire 0xFADE0C01 blob including its 8-byte header)` |
| `-3` | `CSSLOT_RESOURCEDIR` | `SHA-256(_CodeSignature/CodeResources file bytes)` |
| `-4` | `CSSLOT_APPLICATION` | unused — written as 32 zero bytes |
| `-5` | `CSSLOT_ENTITLEMENTS` | `SHA-256(Entitlements blob — the entire 0xFADE7171 blob)` |
| `-6` | reserved | zero |
| `-7` | `CSSLOT_DER_ENTITLEMENTS` | `SHA-256(DER entitlements blob — the entire 0xFADE7172 blob)` |

Any slot whose hash is all-zeros is skipped by iOS at validation time. Slots
`-4` and `-6` are always zero in the GoSigner output.

Sub-bundles (frameworks, dylibs) set `nSpecialSlots = 5` and do not emit a `-7`
slot at all.

### 4. Requirements Blob (`0xFADE0C01`)

The designated-requirement expression, byte-identical to what Apple's
`codesign` emits for an iOS Distribution-signed app:

```
identifier "com.example.app"           and
anchor apple generic                   and
certificate leaf[subject.CN] = "iPhone Distribution: …"   and
certificate 1[field.1.2.840.113635.100.6.2.1]  /* exists */
```

The blob wraps a requirements-set (`0xFADE0C01`, count = 1, type `3` which is
`kSecDesignatedRequirementType`), which wraps a single requirement
(`0xFADE0C00`, expression kind `1`). The expression uses the opcode language
from `libsecurity_codesigning/lib/requirement.h`:

| Opcode | Hex | Meaning |
|---|---|---|
| `opIdent` | `0x00000002` | `identifier "…"` |
| `opAnd` | `0x00000006` | logical AND |
| `opCertField` | `0x0000000B` | `certificate N[<field name>] <match>` |
| `opCertGeneric` | `0x0000000E` | `certificate N[field.<OID>] <match>` |
| `opAppleGenericAnchor` | `0x0000000F` | `anchor apple generic` |

Strings are length-prefixed (`uint32_be` length, followed by the raw bytes,
padded with `0x00` to a 4-byte boundary). The length is the byte count of the
string itself — no trailing NUL is counted.

OIDs inside `opCertGeneric` are written as their **DER content octets**, not as
ASCII dotted-decimal. The Apple WWDR OID `1.2.840.113635.100.6.2.1` is the ten
bytes `0x2A 0x86 0x48 0x86 0xF7 0x63 0x64 0x06 0x02 0x01`.

### 5. XML Entitlements (`0xFADE7171`)

The entitlements blob is an 8-byte header (`magic || length`) followed by the
**raw bytes of a UTF-8 XML plist**. GoSigner emits the exact plist the
provisioning profile embeds, i.e.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "…">
<plist version="1.0">
<dict>
  <key>application-identifier</key><string>TEAMID.com.example.app</string>
  <key>com.apple.developer.team-identifier</key><string>TEAMID</string>
  <key>get-task-allow</key><false/>
  <key>keychain-access-groups</key><array>…</array>
</dict>
</plist>
```

For sub-bundles that are **not** main binaries (frameworks and loose dylibs),
this blob is replaced with an empty-dictionary plist:

```xml
<plist version="1.0"><dict/></plist>
```

Embedding the host app's entitlements into a framework is rejected by iOS 26 —
a framework is a library and cannot legally claim application-level
entitlements.

### 6. DER Entitlements (`0xFADE7172`)

This is where the strict serialization rules matter. iOS re-parses this blob
with a DER reader that is stricter than most public ASN.1 libraries.

Logical layout (ASN.1 abstract):

```
Entitlements  ::=  SET OF Entitlement
Entitlement   ::=  SEQUENCE { key UTF8String, value Value }
Value         ::=  UTF8String | BOOLEAN | INTEGER | SEQUENCE OF Value
```

Concrete DER rules that Apple's parser enforces:

1. **Strings are `UTF8STRING`** (universal tag `0x0C`). Generic Go / OpenSSL
   libraries that emit `PRINTABLESTRING` (`0x13`) for ASCII-clean strings will
   be rejected by iOS on Ad-Hoc / Developer profiles.
2. **Array values are `SEQUENCE OF`** (tag `0x30`), *not* `SET OF` (tag `0x31`).
   This is true for the outer wrapper of, e.g., `keychain-access-groups`.
3. **Outer collection is `SET OF SEQUENCE`** (tag `0x31`). Entries inside are
   emitted in **ascending alphabetical order of their key string** — Apple's
   parser accepts that ordering and expects it even though strict DER
   canonical SET-OF would sort by encoded bytes.
4. **BOOLEAN TRUE is `0x01`** (BER-compatible), not `0xFF` (strict DER).
   BOOLEAN FALSE is `0x00`.
5. **Length encoding** follows standard DER: short-form `< 0x80`, long-form
   `0x81..0x84` for lengths up to ~4 GiB.

Example entry for `application-identifier`:

```
30 3B                                    SEQUENCE, length 0x3B
   0C 16  61 70 70 6C 69 63 …            UTF8STRING "application-identifier"
   0C 21  54 45 41 4D 49 44 2E …         UTF8STRING "TEAMID.com.example.app"
```

### 7. CMS SignedData (`0xFADE0B01`)

A detached CMS SignedData as defined in RFC 5652, wrapped in an 8-byte blob
header (`0xFADE0B01` + length). The signed content is the CodeDirectory bytes;
the `messageDigest` attribute repeats `SHA-256(CodeDirectory)`. The signer is
the leaf of the supplied `.p12` (typically `iPhone Distribution: <Name>` issued
by Apple WWDR G3). Certificates embedded in the SignedData:

1. Apple WWDR CA G3
2. Apple Root CA
3. The leaf (signer)

Notes that mattered for iOS 26 compatibility:

* **`digestAlgorithms`** (both the outer SET and each signerInfo's
  `digestAlgorithm`) must be `SEQUENCE { OID(sha256) }` **with no `NULL`
  parameter** (RFC 5754). Encoded bytes:
  `30 0B 06 09 60 86 48 01 65 03 04 02 01`.
* **`signatureAlgorithm`** is `rsaEncryption` (`1.2.840.113549.1.1.1`), with a
  `NULL` parameter — *not* `sha256WithRSAEncryption`. The actual digest comes
  from `digestAlgorithm`.
* **`signedAttrs`** contains **exactly three** attributes:
  `contentType  (1.2.840.113549.1.9.3)`,
  `signingTime  (1.2.840.113549.1.9.5)`,
  `messageDigest (1.2.840.113549.1.9.4)`.
  The Apple-specific attributes `1.2.840.113635.100.9.1` (CDHashes plist) and
  `1.2.840.113635.100.9.2` (CDHashes2) that some older macOS codesign releases
  emitted are **not** added — iOS 26 silently refuses Ad-Hoc / Developer
  installs that carry them.
* The three attributes are serialized in DER canonical SET-OF order (ascending
  by encoded bytes) before being hashed. Go's `encoding/asn1` already produces
  them in the correct order for these specific OIDs; if you reimplement this,
  verify.

### 8. `_CodeSignature/CodeResources`

An XML plist that mirrors `codesign`'s resource envelope. Four top-level keys:

| Key | Purpose |
|---|---|
| `files` | v1 dict: `relative/path` → base64 SHA-1 hash bytes. Legacy. |
| `files2` | v2 dict: `relative/path` → `{hash, hash2, optional}`. Modern validation. |
| `rules` | v1 regex matcher. Just the Apple defaults. |
| `rules2` | v2 regex matcher with weights. Must match Apple's defaults, including the omit rules for `^(.*/)?\.DS_Store$` and for `^Info\.plist$`. |

Critical rules the tool applies:

* The bundle's own main executable is **excluded** from `files2` — it is
  covered by its own embedded Mach-O signature, not by CodeResources.
* `.DS_Store` files are omitted via the canonical weight-2000 rule in
  `rules2`.
* `files` (v1) and `files2` (v2) are populated **independently**: `Info.plist`
  is in `files` but omitted from `files2` because the default `rules2` sets
  `^Info\.plist$` to `omit`. Treating them as the same list produces an
  empty-looking v1 for frameworks, which breaks their own CD special slot
  `-3`.
* For framework / appex sub-bundles, a separate CodeResources is generated
  **before** the sub-bundle's Mach-O is signed — its hash feeds slot `-3` of
  the sub-bundle's CD.

### 9. IPA (ZIP) Packaging

The outer IPA is a PKZIP archive. Two attributes that iOS actually honors when
unpacking:

* **External attributes (Unix mode)** — the 16 bits at `external_attr >> 16`.
  A value of `0o644` strips the execute bit on the app's main binary, which
  causes iOS 26 to fail the install check on Ad-Hoc profiles. GoSigner emits
  every file with `0o755`.
* **Last-modified date (DOS-format time + date)** — at local-header offsets
  `0x0A..0x0D`. Both halves must be a valid DOS date (month 1–12, day 1–31).
  The default Go value of `0x0000` decodes to month 0 / day 0, which some ZIP
  consumers reject. GoSigner sets `Modified = time.Now()`.

---

## 🛠 Project Layout

```
GoSigner/
├── cli/                      CLI entry point
├── ipa/
│   ├── archive/              ZIP writer (mode 0755, valid DOS dates)
│   ├── pipeline/             Resign pipeline (extract → modify → sign → repack)
│   └── ...
├── plist/
│   ├── coderesources/        _CodeSignature/CodeResources generator
│   └── infoplist/            Info.plist reader + compatibility modifier
├── codesign/
│   ├── types/                CS_MAGIC_* / CS_SLOT_* constants
│   ├── blobs/                SuperBlob, CodeDirectory, Requirements, Entitlements
│   ├── hashing/              Page hashing + special-slot hashing
│   ├── cms/                  CMS SignedData builder
│   └── signer/               Orchestrator: reads Mach-O, builds all blobs, appends
├── provision/
│   ├── embed/                Reads the .mobileprovision, extracts entitlements
│   └── entitlements/         DER encoder (UTF8STRING, BER BOOLEAN, SEQUENCE OF)
├── certificate/
│   ├── chain/                Apple WWDR + Root anchors as PEM constants
│   └── ...                   .p12 loader
├── engine/                   JSON-driven orchestration (multi-app)
└── main.go
```

---

## 📥 Usage

GoSigner exposes two orthogonal front-ends:

| Mode | Invocation | Best for |
|---|---|---|
| **JSON mode** | `./gosigner --data='{ … }'` | Automation / CI / back-end services — multi-app batch, HTTP-sourced IPAs, OTA `itms-services://` plist generation. |
| **CLI mode** | `./gosigner sign [flags]` | Interactive single-file signing, scripts, day-to-day developer use. |

Both modes drive the same signing core. JSON mode is the recommended integration
surface for server-side workflows because a single invocation can sign many IPAs
concurrently, download remote IPAs with automatic retry / resume, and emit the
OTA install plist in one step.

---

### 🅐 JSON mode — `--data`

Run one invocation with the full pipeline (download → modify → sign → repackage
→ emit install plist) described by a JSON document passed as a single CLI
argument.

#### 1. Full field reference

```jsonc
{
  "apps": [
    {
      // ─── Required ────────────────────────────────────────────────────────
      "ipa":            "./in.ipa",             // local path OR full https:// URL
      "cert":           "./identity.p12",       // full path to the .p12 bundle

      // ─── Signing identity ────────────────────────────────────────────────
      "cert_password":  "optional-p12-pass",    // empty / absent if the .p12 has no password
      "profile":        "./dev.mobileprovision", // full path to the Apple-issued profile
      "remove_profile": false,                   // true → strip embedded.mobileprovision after signing
                                                 //         (typically only useful for adhoc / simulator)

      // ─── App-level overrides ─────────────────────────────────────────────
      "bundle_id":      "",                      // e.g. "com.your.bundleid" — empty = keep original
      "name":           "",                      // e.g. "Internal Build"    — empty = keep original

      // ─── Dylib / bundle injection ────────────────────────────────────────
      //
      // One entry per "feature" to inject. Each entry always has a `full_dylib`;
      // `full_bundle` is optional and is used when the dylib has an accompanying
      // .bundle directory of Objective-C class dumps, NIBs, assets, etc.
      //
      // Typical tweak / hook / telemetry SDKs ship as a pair: mychanges.dylib
      // + mychanges.bundle/.
      "dylibs": [
        {
          "full_dylib":  "/path/to/Plugin.dylib",
          "full_bundle": "/path/to/Plugin.bundle"   // can be "" or absent → no bundle
        },
        {
          "full_dylib":  "/path/to/standalone.dylib"
          // full_bundle omitted → inject only the dylib
        }
      ],

      // ─── Output paths (local filesystem) ─────────────────────────────────
      "output":        "/var/www/cdn/signature/ipa/",   // where the .ipa lands
      "plist_output":  "/var/www/cdn/signature/plist/",  // where the install .plist lands
                                                         // (ignored if create_plist=false)

      // ─── Public URLs — used only for the install plist / itms-services:// ─
      "ipa_base_url":    "https://cdn.example.com/signature/ipa/",
      "plist_base_url":  "https://cdn.example.com/signature/plist/",
      "url_icon":        "https://cdn.example.com/icons/myapp-512.png",

      "create_plist":    true                           // emit the OTA install plist
    }
  ]
}
```

Every string field defaults to empty, every bool defaults to `false`. You can
omit any field that doesn't apply.

#### 2. JSON result (stdout)

```jsonc
{
  "success": true,
  "results": [
    {
      "success":      true,
      "ipa":          "./in.ipa",
      "output_ipa":   "/var/www/cdn/signature/ipa/f0f70d67…e77.ipa",
      "output_plist": "/var/www/cdn/signature/plist/f0f70d67…e77.plist",
      "plist_url":    "https://cdn.example.com/signature/plist/f0f70d67…e77.plist",
      "name":         "MyApp",
      "bundle_id":    "com.example.myapp",
      "duration":     "569ms"
    }
  ]
}
```

The OTA install URL that goes into a web page or a push notification is:

```
itms-services://?action=download-manifest&url={plist_url}
```

Place that URL behind Safari on the target iPhone / iPad and iOS will fetch the
plist, fetch the IPA it names, and install it.

---

### 🅑 Example recipes

Every example below is a one-shot invocation. All string paths can be absolute
or relative to the current working directory. All IPA inputs can be either a
local file path **or** a `https://…` URL — GoSigner detects URLs by prefix and
streams the body into a temp file with up to three resume-capable retries
before handing off to the signer.

---

#### Recipe 1 — minimal, local IPA, no plist

```bash
./gosigner --data='{
  "apps": [{
    "ipa":     "./MyApp.ipa",
    "cert":    "./identity.p12",
    "profile": "./dev.mobileprovision",
    "output":  "./signed/"
  }]
}'
```

Output: `./signed/<32-hex-random>.ipa`.

---

#### Recipe 2 — remote IPA over HTTPS (auto-download)

```bash
./gosigner --data='{
  "apps": [{
    "ipa":     "https://releases.example.com/builds/nightly-2026-04-17.ipa",
    "cert":    "./identity.p12",
    "cert_password": "hunter2",
    "profile": "./dev.mobileprovision",
    "output":  "/var/www/cdn/signature/ipa/"
  }]
}'
```

GoSigner will:

1. Create a temp file under the system temp dir (e.g. `/tmp/gosigner_dl_<hex>.ipa`).
2. Fetch the URL with `Accept: */*`, forced `HTTP/1.1`, a 30-minute total
   budget, and a 30-second connect budget.
3. On any non-fatal error, retry up to **3 times** with exponential-ish
   back-off (`2s`, `4s`).
4. Validate the first four bytes are the ZIP local-file-header magic `50 4B 03
   04` (`PK..`); non-ZIP responses are rejected as failed downloads.
5. Hand the local copy off to the signer. The temp file is deleted on success
   or on any terminal error.

---

#### Recipe 3 — full OTA pipeline (what `SignatureApiService.php` wires up)

```bash
./gosigner --data='{
  "apps": [{
    "ipa":            "https://releases.example.com/builds/v4.7.ipa",
    "cert":           "/srv/certs/team.p12",
    "cert_password":  "",
    "profile":        "/srv/profiles/dev-iphone17.mobileprovision",
    "output":         "/var/www/cdn/signature/ipa/",
    "plist_output":   "/var/www/cdn/signature/plist/",
    "ipa_base_url":   "https://cdn.example.com/signature/ipa/",
    "plist_base_url": "https://cdn.example.com/signature/plist/",
    "url_icon":       "https://cdn.example.com/icons/myapp-512.png",
    "create_plist":   true
  }]
}'
```

The stdout JSON will contain `plist_url`. Put

```
itms-services://?action=download-manifest&url={plist_url}
```

behind an `<a href="…">` on a landing page served over HTTPS (iOS refuses plain
HTTP for `itms-services://`). The target device taps the link → iOS downloads
the plist → iOS downloads the IPA named in the plist → iOS validates the
signature against the embedded provisioning profile → if the UDID is in the
profile, the app installs.

The generated plist is in the canonical OTA form Apple documents for
enterprise / ad-hoc distribution:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>items</key>
    <array>
      <dict>
        <key>assets</key>
        <array>
          <dict>
            <key>kind</key><string>software-package</string>
            <key>url</key><string>https://cdn.example.com/signature/ipa/<hex>.ipa</string>
          </dict>
          <dict>
            <key>kind</key><string>display-image</string>
            <key>needs-shine</key><true/>
            <key>url</key><string>https://cdn.example.com/icons/myapp-512.png</string>
          </dict>
          <dict>
            <key>kind</key><string>full-size-image</string>
            <key>needs-shine</key><true/>
            <key>url</key><string>https://cdn.example.com/icons/myapp-512.png</string>
          </dict>
        </array>
        <key>metadata</key>
        <dict>
          <key>bundle-identifier</key><string>com.example.myapp</string>
          <key>bundle-version</key><string>4.7</string>
          <key>kind</key><string>software</string>
          <key>title</key><string>MyApp</string>
        </dict>
      </dict>
    </array>
  </dict>
</plist>
```

> **Web server note** — nginx / Apache must serve
> `.plist` with `Content-Type: text/xml` (or `application/xml`) and
> `.mobileprovision` with `Content-Type: application/x-apple-aspen-mobileprovision`.
> Without those two MIME types the download starts but iOS silently discards
> the response.

---

#### Recipe 4 — bundle-id rename and display-name rewrite

When the provisioning profile is bound to a specific `application-identifier`
(typical for Developer / Ad-Hoc profiles) the IPA's `CFBundleIdentifier` must
match the profile's app-id exactly.

```bash
./gosigner --data='{
  "apps": [{
    "ipa":       "./MyApp.ipa",
    "cert":      "./identity.p12",
    "profile":   "./dev.mobileprovision",
    "output":    "./signed/",
    "bundle_id": "377GFQUWV6.com.example.specific",
    "name":      "Internal QA"
  }]
}'
```

GoSigner rewrites every `CFBundleIdentifier` in the main `Info.plist`, in the
entitlements blob (`application-identifier`), and in the embedded designated
requirement (`identifier "…"`) so the whole chain stays consistent.

---

#### Recipe 5 — inject a single dylib

```bash
./gosigner --data='{
  "apps": [{
    "ipa":     "./MyApp.ipa",
    "cert":    "./identity.p12",
    "profile": "./dev.mobileprovision",
    "output":  "./signed/",
    "dylibs": [
      { "full_dylib": "/srv/plugins/AnalyticsShim.dylib" }
    ]
  }]
}'
```

Under the hood GoSigner:

1. Copies `AnalyticsShim.dylib` into `Payload/<App>.app/Frameworks/`.
2. Inserts an `LC_LOAD_DYLIB` (`cmd = 0x0C`) load command into the main
   executable pointing at `@executable_path/Frameworks/AnalyticsShim.dylib`
   (or `LC_LOAD_WEAK_DYLIB` / `cmd = 0x18` if you also pass `"weak": true` in
   the equivalent CLI mode — not exposed through JSON).
3. Signs the injected dylib with the supplied `.p12`, emitting an empty
   `<dict/>` entitlements blob (dylibs aren't allowed to claim app-level
   entitlements).
4. Re-hashes page-0 of the main executable (the LC changes went there) and
   regenerates the CodeDirectory.

---

#### Recipe 6 — inject a dylib **with its companion `.bundle`**

Many tweak SDKs are shipped as a pair: a single `Foo.dylib` plus a `Foo.bundle/`
directory of localized strings, NIBs, class-dump JSONs, textures, etc. The
dylib at runtime does
`[NSBundle bundleWithURL:[mainBundle URLForResource:@"Foo" withExtension:@"bundle"]]`
and expects the `.bundle` to live alongside it. GoSigner copies both, signs
the dylib, hashes the bundle into the main app's `CodeResources`, and
re-embeds.

```bash
./gosigner --data='{
  "apps": [{
    "ipa":     "./MyApp.ipa",
    "cert":    "./identity.p12",
    "profile": "./dev.mobileprovision",
    "output":  "./signed/",
    "dylibs": [
      {
        "full_dylib":  "/srv/plugins/DebugOverlay.dylib",
        "full_bundle": "/srv/plugins/DebugOverlay.bundle"
      },
      {
        "full_dylib":  "/srv/plugins/TelemetryCore.dylib",
        "full_bundle": "/srv/plugins/TelemetryCore.bundle"
      },
      {
        "full_dylib":  "/srv/plugins/StandaloneShim.dylib"
      }
    ]
  }]
}'
```

Layout inside the signed IPA becomes:

```
Payload/MyApp.app/
├── MyApp                          (re-signed, with three new LC_LOAD_DYLIB entries)
├── Info.plist
├── Frameworks/
│   ├── DebugOverlay.dylib         (signed, empty entitlements)
│   ├── DebugOverlay.bundle/       (resources — listed in the app's CodeResources)
│   ├── TelemetryCore.dylib        (signed)
│   ├── TelemetryCore.bundle/
│   └── StandaloneShim.dylib       (signed)
├── _CodeSignature/CodeResources   (lists every file above, with SHA-1 and SHA-256 hashes)
└── embedded.mobileprovision
```

---

#### Recipe 7 — multi-app batch (one invocation, many IPAs)

```bash
./gosigner --data='{
  "apps": [
    {
      "ipa":          "https://releases.example.com/AppA.ipa",
      "cert":         "./identity.p12",
      "profile":      "./AppA.mobileprovision",
      "output":       "./signed/",
      "bundle_id":    "com.example.AppA",
      "create_plist": true,
      "plist_output": "./plists/",
      "ipa_base_url": "https://cdn.example.com/signature/ipa/",
      "plist_base_url":"https://cdn.example.com/signature/plist/",
      "url_icon":     "https://cdn.example.com/icons/appA.png"
    },
    {
      "ipa":          "https://releases.example.com/AppB.ipa",
      "cert":         "./identity.p12",
      "profile":      "./AppB.mobileprovision",
      "output":       "./signed/",
      "bundle_id":    "com.example.AppB",
      "create_plist": true,
      "plist_output": "./plists/",
      "ipa_base_url": "https://cdn.example.com/signature/ipa/",
      "plist_base_url":"https://cdn.example.com/signature/plist/",
      "url_icon":     "https://cdn.example.com/icons/appB.png"
    }
  ]
}'
```

Apps inside the same invocation sign **concurrently** (one goroutine per app);
shared inputs like `./identity.p12` are safe to reuse because the loader is
read-only. The response's `results` array preserves the input order regardless
of which app finished first.

---

#### Recipe 8 — using a `file://`-style input from a local fileserver

If the IPA is already sitting on the same machine, give its absolute path —
no URL parsing happens for non-`http(s)` strings:

```bash
./gosigner --data='{
  "apps": [{
    "ipa":     "/data/artifacts/nightly/2026-04-17/MyApp.ipa",
    "cert":    "/etc/signing/identity.p12",
    "profile": "/etc/signing/dev.mobileprovision",
    "output":  "/srv/dist/signed/"
  }]
}'
```

---

### 🅒 CLI mode — `gosigner sign [flags]`

The traditional subcommand interface, exposed through cobra. Mirrors the JSON
mode feature-for-feature (except for plist generation and multi-app batching —
those are JSON-only for now).

```text
Usage:
  gosigner sign [flags]

Flags:
  -i, --input           string   Input IPA (required)            — local path only
  -o, --output          string   Output IPA (required)
  -c, --cert            string   Signing certificate (.p12)
  -p, --cert-password   string   Certificate password
  -m, --profile         string   Provisioning profile (.mobileprovision)
  -e, --entitlements    string   Custom entitlements .plist file (overrides profile)
  -b, --bundle-id       string   Override CFBundleIdentifier
  -n, --bundle-name     string   Override CFBundleDisplayName
  -r, --bundle-version  string   Override CFBundleVersion / ShortVersionString
  -M, --min-version     string   Override MinimumOSVersion (e.g. "12.0")
  -l, --inject-dylib    string   Inject a dylib (repeatable: -l a.dylib -l b.dylib)
  -w, --weak                      Use LC_LOAD_WEAK_DYLIB for injections
  -D, --remove-dylib    string   Strip an LC_LOAD_DYLIB by name (repeatable)
  -E, --strip-extensions         Delete PlugIns/*.appex
  -W, --strip-watch               Delete Watch/ sub-bundle
      --strip-profile             Remove embedded.mobileprovision after signing
  -S, --enable-docs              Turn on UIFileSharingEnabled + UISupportsDocumentBrowser
  -a, --adhoc                     Ad-hoc sign (no .p12, no profile)
  -z, --zip-level       int       ZIP compression level 0..9 (default 6; 0 = store)
  -f, --force                     Re-sign even if the cache says inputs are unchanged
  -h, --help                      Show help
```

#### CLI examples

```bash
# Basic developer sign
./gosigner sign \
  -i MyApp.ipa -o MyApp.signed.ipa \
  -c identity.p12 -p hunter2 \
  -m dev.mobileprovision

# With bundle-id and name override
./gosigner sign \
  -i MyApp.ipa -o MyApp.signed.ipa \
  -c identity.p12 -m dev.mobileprovision \
  -b com.example.staging \
  -n "Staging Build"

# Multiple dylib injections + weak binding + high compression
./gosigner sign \
  -i MyApp.ipa -o MyApp.signed.ipa \
  -c identity.p12 -m dev.mobileprovision \
  -l /tweaks/Hook.dylib \
  -l /tweaks/Analytics.dylib \
  --weak \
  -z 9

# Strip watch app + appex extensions + force re-sign
./gosigner sign \
  -i MyApp.ipa -o MyApp.signed.ipa \
  -c identity.p12 -m dev.mobileprovision \
  -E -W -f

# Ad-hoc sign for simulator builds / local testing (no real identity needed)
./gosigner sign -i MyApp.ipa -o MyApp.adhoc.ipa --adhoc

# Bump MinimumOSVersion and enable document browser
./gosigner sign \
  -i MyApp.ipa -o MyApp.signed.ipa \
  -c identity.p12 -m dev.mobileprovision \
  -M 14.0 --enable-docs
```

---

### 🅓 Supporting subcommands

| Command | What it does |
|---|---|
| `gosigner info -i <ipa> -c <p12> -m <profile>` | Prints certificate subject / issuer / expiry, profile UUID / devices / entitlements, and the IPA's bundle-id / version / executable without signing anything. |
| `gosigner verify -i <signed.ipa>` | Walks every Mach-O inside the IPA, re-computes page hashes and special slots, verifies each CMS signer info against the embedded cert. Purely offline — no network, no Apple call. |
| `gosigner version` | Prints the build version + Git SHA (if compiled with `-ldflags`). |

---

### 🅔 Exit codes and error output

| Exit | Meaning |
|---|---|
| `0` | All apps signed successfully. Full JSON response on stdout (JSON mode) / full summary on stdout (CLI mode). |
| `1` | At least one app failed, or the input JSON itself was malformed. Per-app `error` field in the JSON response explains which one(s). |

In JSON mode every failure still produces a well-formed JSON response — stderr
is only used for internal `log.Printf` progress, never for the machine-readable
result. Failure payload shape:

```json
{
  "success": false,
  "results": [
    {
      "success": false,
      "ipa":     "./MyApp.ipa",
      "error":   "load certificate: pkcs12: decryption password incorrect"
    }
  ],
  "errors": ["one or more apps failed"]
}
```

---

### 🅕 Environment requirements

* **OS**: Linux x86_64 / arm64, macOS, Windows — anywhere a Go 1.25+ static
  binary runs.
* **Runtime deps**: none. GoSigner is a single statically-linked binary.
* **Disk**: roughly `3 × IPA size` free in `$TMPDIR` during signing (unzip +
  work dir + repackage). GoSigner checks `disk_free_space` upfront and refuses
  to start if the budget is insufficient.
* **Network**: only used when an `ipa` field is an `http(s)://` URL.
  `.p12` / `.mobileprovision` are always read from local disk; no key material
  ever leaves the host.
* **Clock**: signed CMS attributes embed the wall-clock time (`signingTime`).
  A badly skewed clock (> 5 years off) can cause iOS to reject the signature
  as "from the future" — make sure NTP is running.

---

### 🅖 Exit-free side-effects

* Temp directories under `$TMPDIR` are named `/tmp/gosigner-<random>` (unpack
  workspace) and `/tmp/gosigner_dl_<hex>.ipa` (URL downloads). Both are
  deleted on success and on panic. A crashed process may leave them behind —
  they are safe to `rm -rf` once you confirm no other GoSigner process is
  running.
* Output IPA names are random 32-character hex by default; the returned
  JSON's `output_ipa` field is the authoritative full path. Reserve a caller
  mechanism to rename if you need a stable filename.

---

## 🔎 Verifying the Output

A resigned IPA is self-verifiable on any Linux machine with Python 3 and
`openssl`:

1. Page-0 hash of every Mach-O must equal
   `SHA-256(file[0 : min(pageSize, codeLimit)])`.
2. Every special slot hash must equal `SHA-256` of the corresponding file /
   blob bytes.
3. The SignerInfo's signature must verify against the leaf cert's RSA public
   key, using the DER-re-encoded `signedAttrs` (outer tag swapped from
   `[0] IMPLICIT` `0xA0` to `SET` `0x31`) as the signed message.
4. CMS `messageDigest` equals `SHA-256(CodeDirectory bytes)`.

GoSigner's test suite and the bundled `verify_hashes.py` helper perform
exactly these checks.

---

## 📜 License

```
MIT License

Copyright (c) 2026 GoSigner contributors

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The MIT License governs *GoSigner's own source code*. It does **not** grant any
rights in Apple's trademarks, nor does it modify the terms of the Apple
Developer Program License Agreement under which the user operates their signing
certificate. Every user remains bound by their own agreement with Apple.

### Third-party Components and Attribution

GoSigner's layout implementation is informed by public information released by
Apple under the **Apple Public Source License (APSL)**: specifically, portions
of [Security](https://github.com/apple-oss-distributions/Security) and
[xnu](https://github.com/apple-oss-distributions/xnu). No APSL-licensed source
code is copied into this repository; only constant values (magic numbers, slot
indices, opcode identifiers) that are documented in those sources are
referenced. Such identifiers are interface constants, not expressive code, and
their use here is a compatibility requirement, not a copying of Apple's
implementation.

The bundled Apple root / intermediate CA certificates that GoSigner embeds into
the CMS envelope are the same certificates Apple publishes on
<https://www.apple.com/certificateauthority/>. They are redistributed in their
original DER form with no modification.

---

## 🚫 What GoSigner Is Not

* It is **not** a tool for installing unsigned, pirated, or third-party
  applications onto devices that their authors have not authorized.
* It **cannot** bypass Apple's device-provisioning gate: a target UDID must be
  present in the supplied profile's `ProvisionedDevices`, or the profile must
  be an Enterprise wildcard profile.
* It does **not** generate, renew, or manipulate Apple-issued certificates.
  Users bring their own `.p12`.
* It does **not** communicate with Apple servers or with any other remote
  service during signing.

If any of those properties are important to your workflow, GoSigner is not the
right tool and you should use Apple's first-party `codesign(1)` on macOS
instead.

---

## 🧾 Acknowledgements

Thanks to the Apple Security framework maintainers for keeping the
code-signing format publicly documented, and to the IETF / ITU-T committees
whose RFCs made a conformant re-implementation possible.
