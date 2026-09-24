// SPDX-License-Identifier: GPL-3.0-only
//! The installer for the made-up test product, `super-test`: what the
//! end-to-end test runs, and the shape of every product's installer.

use super_engine_installer::Installer;
use super_engine_protocol::test_product::TEST;

static INSTALLER: Installer = Installer {
    product: &TEST,
    user_agent: "super-test/0.0.0",
    wrapper_usage: "Used by the tests.",
    after_install: None,
};

fn main() -> std::process::ExitCode {
    super_engine_installer::main(&INSTALLER)
}
