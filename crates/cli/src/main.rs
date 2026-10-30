// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

fn main() {
    // `run` returns only the exit code; it never returns while transfer threads
    // (e.g. a pending terminal prompt) could keep the process alive.
    std::process::exit(dfte_cli::app::main_entry());
}
