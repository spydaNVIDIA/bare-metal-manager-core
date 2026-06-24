//! Runtime writer for the credential-rotation bookkeeping tables.
//!
//! `device_credential_rotation` records, per device and credential type, the
//! version of the site-wide credential currently applied on the hardware -- the
//! convergence marker the rotation engine drives toward
//! `sitewide_credential_rotation.target_version`.
//!
//! Already-ingested devices are populated once by the
//! `*_credential_rotation_backfill` data migration. This module records the
//! same fact at runtime, at the moment NICo actually sets a credential on a
//! device (factory -> site-wide at ingestion), so the table does not go stale
//! as new sites and new hardware are adopted. The migration handles "before the
//! upgrade"; these hooks handle "ever after".
//!
//! Ingestion hooks wired today (calling [`record_device_converged`]) record the
//! fact at the moment NICo writes the credential, not when the device row is
//! later persisted:
//!
//! * `bmc` -- at `site-explorer` `BmcEndpointExplorer::set_bmc_root_credentials`,
//!   the single point where every host, DPU, switch, and power-shelf BMC is
//!   moved onto (or confirmed on) the site-wide root and its per-device Vault
//!   secret is written.
//! * `host_uefi` -- when the host UEFI password is set on the device
//!   (`api-core` `set_host_uefi_password` and the machine-controller UEFI-setup
//!   state, alongside stamping `machines.bios_password_set_time`).
//! * `dpu_uefi` -- when the DPU UEFI password is set on the device, at the
//!   machine-controller `DpuInitState::WaitingForPlatformConfiguration` state
//!   right after `uefi_setup(dpu = true)` succeeds (keyed by the DPU BMC MAC,
//!   mirroring the backfill).
//! * `lockdown_ikm` -- when a SuperNIC card is confirmed locked, at the
//!   dpa-manager `handle_locking` state (`card_state.lockmode == Locked`), keyed
//!   by the card (NIC) MAC. Recorded at the current site-wide target, which today
//!   is `CURRENT_LOCKDOWN_IKM_VERSION` (0) -- the same version the lock key is
//!   derived from. The rotation engine will own advancing that version.
//!
//! Deferred to the work that owns those write paths:
//!
//! * `nvos` -- the hook is wired in the switch controller at
//!   `configuring::handle_rotate_os_password` (the `RotateOsPassword` state) but
//!   gated off, because NICo only copies the operator-provided NVOS credential
//!   into Vault today; it does not change the switch password (REQ-6,
//!   set-NVOS-from-factory, is not implemented). The gate flips on with REQ-6.

use mac_address::MacAddress;
use sqlx::PgConnection;

use crate::DatabaseError;

/// Mirrors the `credential_rotation_type` Postgres enum
/// (`20260623120000_credential_rotation.sql`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "credential_rotation_type", rename_all = "snake_case")]
pub enum CredentialRotationType {
    Bmc,
    HostUefi,
    DpuUefi,
    Nvos,
    LockdownIkm,
}

/// Records that `device_mac` now carries the current site-wide `credential_type`
/// credential, i.e. it has converged to the active `target_version`.
///
/// Call this right after NICo sets the credential on the device (the factory ->
/// site-wide step at ingestion). The recorded `current_version` is the
/// credential type's current site-wide `target_version` (0 before any rotation
/// has occurred), so a device ingested during or after a rotation is recorded
/// at the version it actually received rather than a stale 0.
///
/// Idempotent: an existing row (re-ingestion, retry, or the backfill migration)
/// is left untouched, so this never clobbers a version the rotation engine is
/// tracking -- the engine owns all subsequent version transitions.
pub async fn record_device_converged(
    conn: &mut PgConnection,
    device_mac: MacAddress,
    credential_type: CredentialRotationType,
) -> Result<(), DatabaseError> {
    let query = "INSERT INTO device_credential_rotation \
                     (device_mac, credential_type, current_version) \
                 SELECT $1, $2, COALESCE( \
                     (SELECT target_version FROM sitewide_credential_rotation \
                      WHERE credential_type = $2), 0) \
                 ON CONFLICT (device_mac, credential_type) DO NOTHING";
    sqlx::query(query)
        .bind(device_mac)
        .bind(credential_type)
        .execute(conn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

#[cfg(test)]
mod tests {
    use mac_address::MacAddress;
    use sqlx::PgPool;

    use super::{CredentialRotationType, record_device_converged};

    // current_version for a (mac, type) row, or None if no row exists.
    async fn version_of(pool: &PgPool, mac: &str, credential_type: &str) -> Option<i32> {
        let row: Option<Option<i32>> = sqlx::query_scalar(
            "SELECT current_version FROM device_credential_rotation \
             WHERE device_mac = $1::macaddr \
               AND credential_type = $2::credential_rotation_type",
        )
        .bind(mac)
        .bind(credential_type)
        .fetch_optional(pool)
        .await
        .unwrap();
        row.flatten()
    }

    #[crate::sqlx_test]
    async fn records_current_target_and_is_idempotent(pool: PgPool) {
        let mac1: MacAddress = "02:00:00:00:00:01".parse().unwrap();
        let mac2: MacAddress = "02:00:00:00:00:02".parse().unwrap();
        let mut conn = pool.acquire().await.unwrap();

        // The backfill migration seeds the bmc site-wide target at version 0, so
        // a device recorded now converges at 0.
        record_device_converged(&mut conn, mac1, CredentialRotationType::Bmc)
            .await
            .unwrap();
        assert_eq!(version_of(&pool, "02:00:00:00:00:01", "bmc").await, Some(0));

        // Bump the site-wide target. An already-recorded device must NOT be
        // clobbered -- the engine owns version transitions, not this hook.
        sqlx::query(
            "UPDATE sitewide_credential_rotation SET target_version = 3 \
             WHERE credential_type = 'bmc'",
        )
        .execute(&pool)
        .await
        .unwrap();
        record_device_converged(&mut conn, mac1, CredentialRotationType::Bmc)
            .await
            .unwrap();
        assert_eq!(
            version_of(&pool, "02:00:00:00:00:01", "bmc").await,
            Some(0),
            "existing row must be preserved on re-ingestion"
        );

        // A device first seen after the bump records the current target (3).
        record_device_converged(&mut conn, mac2, CredentialRotationType::Bmc)
            .await
            .unwrap();
        assert_eq!(
            version_of(&pool, "02:00:00:00:00:02", "bmc").await,
            Some(3),
            "a newly ingested device records the current site-wide target"
        );

        // nvos has no site-wide target row (deliberately not backfilled); the
        // COALESCE in the writer defaults current_version to 0 rather than failing.
        record_device_converged(&mut conn, mac1, CredentialRotationType::Nvos)
            .await
            .unwrap();
        assert_eq!(
            version_of(&pool, "02:00:00:00:00:01", "nvos").await,
            Some(0)
        );
    }
}
