package com.securevault.security

enum class Role { OWNER, VIEW_ONLY }
enum class Action { READ, WRITE }

/** In-memory unlock state. Nothing here is persisted. */
object Session {
    @Volatile var unlocked: Boolean = false
        private set
    @Volatile var role: Role = Role.OWNER
        private set

    /** True while the app deliberately opens system UI (picker, chooser, credential screen) so it is not auto-locked. */
    @Volatile var suppressLock: Boolean = false

    private val listeners = java.util.concurrent.CopyOnWriteArraySet<() -> Unit>()

    fun addLockListener(l: () -> Unit) { listeners.add(l) }
    fun removeLockListener(l: () -> Unit) { listeners.remove(l) }

    fun unlock(role: Role) {
        this.role = role
        unlocked = true
    }

    fun lock() {
        val was = unlocked
        unlocked = false
        role = Role.OWNER
        if (was) listeners.forEach { it() }
    }
}

/** Module 3: checked before every read or write of vault data. */
object AccessController {
    fun isAllowed(unlocked: Boolean, role: Role, action: Action): Boolean = when {
        !unlocked -> false
        action == Action.READ -> true
        else -> role == Role.OWNER
    }

    fun check(action: Action) {
        if (!isAllowed(Session.unlocked, Session.role, action)) {
            throw SecurityException(
                if (!Session.unlocked) "Vault is locked" else "Vault is read-only on this device state",
            )
        }
    }
}
