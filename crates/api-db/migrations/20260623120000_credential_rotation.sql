-- Credential rotation bookkeeping.
--
-- Two tables track the rotation of device credentials that NICo is
-- authoritative for (BMC root, host/DPU UEFI, switch NVOS, and the SuperNIC
-- lockdown IKM). The site-wide table records the current rotation target per
-- credential type; the per-device table records each device's convergence
-- toward that target. Secret material itself lives in Vault, never here.

-- Credential type shared by both rotation tables.
CREATE TYPE credential_rotation_type AS ENUM
    ('bmc', 'host_uefi', 'dpu_uefi', 'nvos', 'lockdown_ikm');

-- One row per credential type: the site-wide rotation target / intent.
CREATE TABLE sitewide_credential_rotation (
    credential_type credential_rotation_type PRIMARY KEY,
    target_version  integer     NOT NULL,
    started_at      timestamptz NOT NULL DEFAULT now(),
    -- Free-form initiator/reason metadata; must never contain secrets.
    request_meta    jsonb       NOT NULL DEFAULT '{}'::jsonb
);

-- One row per (device_mac, credential_type): per-device convergence state.
--
-- No foreign key: device_mac is a logical key (it mirrors the Vault per-device
-- path) shared across machines, switches, power shelves, and SuperNICs, which
-- live in separate tables with heterogeneous primary keys.
CREATE TABLE device_credential_rotation (
    device_mac                 macaddr                  NOT NULL,
    credential_type            credential_rotation_type NOT NULL,
    -- Version currently live on the hardware (the convergence marker). NULL
    -- means "not yet established" (e.g. an unlocked card for lockdown_ikm).
    current_version            integer,
    -- Non-NULL while a rotation is mid-flight on this device; doubles as the
    -- crash-safety marker and pins that version against sweep.
    rotating_to_version        integer,
    rotate_attempts            integer       NOT NULL DEFAULT 0,
    rotate_last_attempt_at     timestamptz,
    -- Redacted last-error string for observability; never contains secrets.
    rotate_last_error_redacted text,
    rotate_quarantined_until   timestamptz,
    PRIMARY KEY (device_mac, credential_type)
);

-- Hot path: "which devices for this credential type still need rotation"
-- (current_version < target) and completion counting.
CREATE INDEX device_credential_rotation_type_version_idx
    ON device_credential_rotation (credential_type, current_version);

-- In-flight rows scanned during crash recovery and sweep pinning.
CREATE INDEX device_credential_rotation_in_flight_idx
    ON device_credential_rotation (credential_type)
    WHERE rotating_to_version IS NOT NULL;

-- Quarantined rows scanned by the backoff sweep.
CREATE INDEX device_credential_rotation_quarantined_idx
    ON device_credential_rotation (credential_type)
    WHERE rotate_quarantined_until IS NOT NULL;
