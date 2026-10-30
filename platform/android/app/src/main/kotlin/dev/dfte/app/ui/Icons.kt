// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

package dev.dfte.app.ui

import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.unit.dp
import androidx.compose.ui.graphics.Color

/** The spec's single stroke icon set (1.75 px, rounded), same path data as ui-spec.html. */
object Icons {
    private fun icon(name: String, vararg paths: String): ImageVector = ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f).apply {
        for (d in paths) {
            addPath(PathParser().parsePathString(d).toNodes(), stroke = SolidColor(Color.Black), strokeLineWidth = 1.75f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round)
        }
    }.build()

    val Up = icon("up", "M12 19V5M6 11l6-6 6 6")
    val Down = icon("down", "M12 5v14M6 13l6 6 6-6")
    val File = icon("file", "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z", "M14 3v5h5")
    val Folder = icon("folder", "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z")
    val Phone = icon("phone", "M9 3h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z", "M11 18h2")
    val Laptop = icon("laptop", "M5.5 5h13A1.5 1.5 0 0 1 20 6.5v8a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 14.5v-8A1.5 1.5 0 0 1 5.5 5z", "M2 19h20")
    val Shield = icon("shield", "M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z", "M9 12l2 2 4-4")
    val Close = icon("x", "M6 6l12 12M18 6L6 18")
    val Back = icon("back", "M15 6l-6 6 6 6")
    val Check = icon("check", "M5 12l5 5 9-10")
    val Pause = icon("pause", "M9 6v12M15 6v12")
    val Play = icon("play", "M8 5.5v13l10-6.5z")
    val Link = icon("link", "M10 14a4 4 0 0 0 5.66 0l3-3a4 4 0 0 0-5.66-5.66l-1 1", "M14 10a4 4 0 0 0-5.66 0l-3 3a4 4 0 0 0 5.66 5.66l1-1")
    val Wifi = icon("wifi", "M2.5 9a14 14 0 0 1 19 0", "M6 12.5a9 9 0 0 1 12 0", "M9.5 16a4 4 0 0 1 5 0", "M12 19.5v.01")
    val Alert = icon("alert", "M12 8v5M12 16.5v.01", "M21 12a9 9 0 1 1-18 0a9 9 0 1 1 18 0z")
}
