package com.securevault.data

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Update

// All DAO calls are blocking; callers run them on Dispatchers.IO (Room rejects main-thread queries).

@Dao
interface UserDao {
    @Query("SELECT * FROM users WHERE id = 1")
    fun get(): UserEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun upsert(user: UserEntity)

    @Query("UPDATE users SET failed_attempts = :failed, locked_until = :lockedUntil WHERE id = 1")
    fun setAttempts(failed: Int, lockedUntil: Long)

    @Query("DELETE FROM users")
    fun clear()
}

@Dao
interface ItemDao {
    @Query("SELECT * FROM vault_items ORDER BY updated_at DESC")
    fun all(): List<VaultItem>

    @Query("SELECT * FROM vault_items WHERE id = :id")
    fun byId(id: Long): VaultItem?

    @Insert
    fun insert(item: VaultItem): Long

    @Update
    fun update(item: VaultItem)

    @Query("DELETE FROM vault_items WHERE id = :id")
    fun delete(id: Long)

    @Query("DELETE FROM vault_items")
    fun clear()
}

@Dao
interface FileDao {
    @Insert
    fun insert(meta: FileMeta): Long

    @Query("SELECT * FROM file_meta WHERE item_id = :itemId")
    fun byItem(itemId: Long): FileMeta?

    @Query("DELETE FROM file_meta WHERE item_id = :itemId")
    fun deleteByItem(itemId: Long)

    @Query("DELETE FROM file_meta")
    fun clear()
}

@Dao
interface AuditDao {
    @Insert
    fun insert(entry: AuditEntry): Long

    @Query("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
    fun lastHash(): String?

    @Query("SELECT * FROM audit_log ORDER BY id ASC")
    fun all(): List<AuditEntry>
}

@Database(
    entities = [UserEntity::class, VaultItem::class, FileMeta::class, AuditEntry::class],
    version = 1,
    exportSchema = false,
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun users(): UserDao
    abstract fun items(): ItemDao
    abstract fun files(): FileDao
    abstract fun audit(): AuditDao

    companion object {
        fun build(context: Context): AppDatabase =
            Room.databaseBuilder(context, AppDatabase::class.java, "vault.db").build()
    }
}
