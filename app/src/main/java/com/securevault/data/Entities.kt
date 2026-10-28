package com.securevault.data

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/** Table `users` (report 8.2). The PIN itself is never stored, only a salted slow hash. */
@Entity(tableName = "users")
class UserEntity(
    @PrimaryKey val id: Int = 1,
    @ColumnInfo(name = "pin_salt") val pinSalt: ByteArray,
    @ColumnInfo(name = "pin_hash") val pinHash: ByteArray,
    @ColumnInfo(name = "failed_attempts") val failedAttempts: Int = 0,
    @ColumnInfo(name = "locked_until") val lockedUntil: Long = 0L,
)

/**
 * Table `vault_items`. Every sensitive column holds ciphertext. Each blob is `IV(12) || ct || tag`,
 * so the per-operation IV travels with the ciphertext (the report's `iv` column is folded in).
 */
@Entity(tableName = "vault_items")
class VaultItem(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val type: String,
    @ColumnInfo(name = "title_enc") val titleEnc: ByteArray,
    @ColumnInfo(name = "body_enc") val bodyEnc: ByteArray,
    @ColumnInfo(name = "created_at") val createdAt: Long,
    @ColumnInfo(name = "updated_at") val updatedAt: Long,
)

/** Table `file_meta`. The file on disk is encrypted and has a random name; its real name is in title_enc. */
@Entity(tableName = "file_meta")
class FileMeta(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(name = "item_id") val itemId: Long,
    @ColumnInfo(name = "random_name") val randomName: String,
    val size: Long,
)

/** Table `audit_log`. Event types only, never sensitive content. */
@Entity(tableName = "audit_log")
class AuditEntry(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(name = "event_type") val eventType: String,
    val timestamp: Long,
    @ColumnInfo(name = "prev_hash") val prevHash: String,
    val hash: String,
)
