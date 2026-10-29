package dev.dfte.app

import androidx.compose.runtime.mutableStateListOf

sealed interface Screen {
    data object Home : Screen
    data object Receive : Screen

    /** Owns [picked] until it is sent (then the engine owns it) or abandoned. */
    data class SendTo(val picked: Picked) : Screen
    data class Transfer(val id: String) : Screen
}

/**
 * A plain back stack held by the Application, so it survives rotation without a
 * navigation library (ui-spec: light on resources).
 */
class Nav {
    val stack = mutableStateListOf<Screen>(Screen.Home)
    val top: Screen get() = stack.last()

    fun push(s: Screen) {
        stack.add(s)
    }

    /** Returns false at the root so the system can close the app. */
    fun pop(): Boolean {
        if (stack.size <= 1) return false
        val gone = stack.removeAt(stack.lastIndex)
        if (gone is Screen.SendTo) gone.picked.close()
        return true
    }

    /** Swaps the top screen without releasing what it owned (a SendTo hands its files to the engine). */
    fun replaceTop(s: Screen) {
        stack[stack.lastIndex] = s
    }

    fun home() {
        while (stack.size > 1) pop()
    }
}
