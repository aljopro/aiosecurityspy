# Disclosure Register

AD-13 (widened 2026-08-29) states: *anything that is PII, a secret, or a password is redacted or encrypted*. The rule is the category, not a list of field names. Where a value genuinely cannot be withheld without making a shareable artifact (diagnostics dump, debug log, public issue) useless, the deliberate exposure is documented here — the field, the artifact, why withholding it was not possible, and the reduced form used.

An undocumented deliberate exposure is a defect regardless of how defensible it would have been.

## Fields deliberately disclosed

None at the library layer.

The library's `anonymize()` is the only path a diagnostics dump or shareable log may take through a `aiosecurityspy`-owned payload. Every value the walk encounters is either:

- matched by `CREDENTIAL_KEYS` or the `*Pass` convention → replaced with `REDACTED`,
- matched by `IDENTIFYING_KEYS` → replaced with `REDACTED`,
- or a scalar / structure the consumer (the integration) chose to include deliberately.

The library itself never publishes a deliberately-disclosed field. This register therefore documents **what is *not* redacted by default** and why — so a future reviewer who adds a field to a known-safe category can see the line.

### Camera number (`number`)

- **Where it appears:** every `Camera`, `CameraStatus`, `CameraView`, capture history entry, capture preview URL, arming write.
- **Why disclosed:** the entire purpose of a diagnostics dump is to identify *which* camera is misbehaving. Replacing the number with a hash or a placeholder breaks the cross-reference between entries — the dump becomes a bag of unrelated events.
- **Reduced form:** the integer as published. No truncation; a partial number cannot be cross-referenced.

### Camera display name (`name`)

- **Where it appears:** `Camera`, `CameraView`, settings payloads.
- **Why disclosed:** the user named the camera; the name is what they refer to in automations and dashboards. Replacing it with a placeholder breaks the dump's correspondence with the user's HA install.
- **Reduced form:** the string as published. `anonymize()` does *not* hash names, and the library has no basis for hashing them — the consumer (the integration) can opt to do so.

### Server version, port, server-software identifiers

- **Where it appears:** `ServerInfo.version`, `ServerInfo.bonjour_name`, `ServerInfo.uuid`, `Camera.number`, port numbers on connection failure messages.
- **Why disclosed:** without these the dump cannot tell which SecuritySpy version is failing, on what network, or which server in a multi-server HA install. The `uuid` is per-server and serves as the stable identity (AD-5); replacing it would break every cross-reference.
- **Reduced form:** as published. The `uuid` is a SecuritySpy-server-generated UUID, not a user-supplied identifier — it identifies the *server*, not the user, and is the documented stable key.

### Error state (camera error code and description)

- **Where it appears:** `CameraStatus.error`, `CameraStatus.error_description`, `Camera.last_error`, `Camera.last_error_description`.
- **Why disclosed:** the *whole point* of a camera health sensor is to surface the error code and description to the user. A dump that redacted these would defeat the diagnostic purpose.
- **Reduced form:** as published. The error description is server-supplied free text and does not carry credentials.

### Configuration flags (brightness, sensitivity, mode toggles)

- **Where it appears:** `CameraSettings` (the curated, credential-free model).
- **Why disclosed:** the field is the value the user asked the camera to apply. Replacing it would defeat the diagnostic purpose; the camera name *and* the applied brightness together tell the maintainer which camera to look at and what to expect.
- **Reduced form:** as published.

### Mode strings (`C` / `M` / `A`)

- **Where it appears:** `CaptureModes`, `mode_string`, capture-mode selectors on writes.
- **Why disclosed:** these are fixed single letters from research §5.1, not user-supplied. They cannot carry PII or a credential.

## What is *not* in this register

- The full library `Settings` payload (e.g. `++settings-cameras`): the library drops this at decode and never stores it; what reaches the consumer is the curated `CameraSettings` model whose disclosure story is above.
- The model `repr()`: documented as carrying only the camera number (research §8.3 — the settings page contains credentials, the library's models deliberately do not).
- The `REDACTED` marker itself: the substitution sentinel is not PII.

## How to add to this register

A change that introduces a new field the walk leaves untouched must either:

1. add the field to `CREDENTIAL_KEYS` or `IDENTIFYING_KEYS` in `const.py` (the change is then mechanical and this register is unchanged), or
2. justify the deliberate disclosure in this register in the same commit.

There is no third option: a new field the walk passes through and this register does not name is an undocumented exposure, which AD-13 names as a defect.
