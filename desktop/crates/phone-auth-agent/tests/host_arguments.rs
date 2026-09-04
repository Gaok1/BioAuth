//! What the native-messaging host does with the arguments it is launched with.
//!
//! Two properties, and the second matters more than it looks. Browsers pass
//! arguments of their own -- Chrome hands the calling extension's origin,
//! Firefox adds the manifest path and the extension id -- so an unrecognised
//! argument is the ordinary case. A host that rejected one would refuse every
//! launch a browser makes, and a browser reports that as nothing at all.

use std::process::{Command, Stdio};

const HOST: &str = env!("CARGO_BIN_EXE_phone-auth-webauthn-host");

#[test]
fn the_host_says_which_build_it_is() {
    let output = Command::new(HOST)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .expect("the host runs");

    assert!(output.status.success(), "{:?}", output.status);
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(said.contains("phone-auth-webauthn-host"), "{said}");
    assert!(said.contains(env!("CARGO_PKG_VERSION")), "{said}");
}

/// The installers do not ask this question -- they launch the host the way a
/// browser does, with nothing on stdin -- but the same property is what makes
/// that probe safe: whatever the launcher passes, the host runs and stops.
#[test]
fn an_argument_a_browser_passes_is_not_a_usage_error() {
    for argument in [
        "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
        "--parent-window=0",
        "/etc/opt/chrome/native-messaging-hosts/com.bioauth.webauthn.json",
        "webauthn@bioauth.local",
    ] {
        let output = Command::new(HOST)
            .arg(argument)
            // Closed rather than left open: with nothing to read the host
            // finishes its loop and exits, which is how this test asks
            // "were you refused?" without holding a conversation.
            .stdin(Stdio::null())
            .output()
            .expect("the host runs");

        assert!(output.status.success(), "{argument}: {:?}", output.status);
    }
}
