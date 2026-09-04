//! Browser native-messaging bridge to the authenticated PhoneAuth agent IPC.

use std::io::{self, Read, Write};

use phone_auth_agent::service::origin_host;
use phone_auth_agent::{AgentClient, Paths};
use serde_json::{json, Value};

const MAX_MESSAGE: usize = 128 * 1024;

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // The browser restarts the host on the next request, so the exit
            // status is what a person debugging this has to go on.
            eprintln!("phone-auth-webauthn-host: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    loop {
        let Some(message) = read_message(&mut input)? else {
            return Ok(());
        };
        let reply = handle(message);
        write_message(&mut output, &reply)?;
    }
}

/// The origin of a `vault-fill` request, or None when it is not one to act on.
///
/// The rule is the agent's, imported rather than restated. This binary is a
/// second gate on the same request, and a gate that disagrees with the one
/// behind it silently refuses what the agent would have allowed -- which is
/// what a copy of the rule here did the moment the extension learned to fill
/// on localhost: the agent took the loopback origin, this file still tested
/// for `https://`, and the feature was dead before it reached the socket.
fn fill_origin(message: &Value) -> Option<&str> {
    message
        .get("origin")
        .and_then(Value::as_str)
        .filter(|origin| origin.len() <= 255 && origin_host(origin).is_some())
}

fn handle(message: Value) -> Value {
    let operation = message.get("operation").and_then(Value::as_str);
    let request_id = message.get("requestId").and_then(Value::as_str);
    if operation == Some("cancel") {
        let Some(request_id) = request_id.filter(|value| !value.is_empty() && value.len() <= 64)
        else {
            return json!({"ok": false, "error": "invalid browser cancellation"});
        };
        let mut client = match AgentClient::connect(&Paths::resolve(None)) {
            Ok(client) => client,
            Err(error) => return json!({"ok": false, "error": error.to_string()}),
        };
        return match client.call("webauthn.cancel", json!({"requestId": request_id})) {
            Ok(value) => json!({"ok": true, "response": value}),
            Err(error) => json!({"ok": false, "error": error.to_string()}),
        };
    }
    // Password autofill. Kept as its own arm rather than folded into the
    // passkey path below, because what crosses here is different in kind: a
    // passkey assertion is a signature the page cannot reuse, and this is a
    // password the page keeps. `VLT-09` accepts that the browser receives the
    // plaintext — it is what autofill is — and the narrowness is the mitigation:
    // one origin in, at most one secret out, and the phone approves it with
    // the full context sheet before anything is released.
    if operation == Some("vault-fill") {
        let Some(origin) = fill_origin(&message) else {
            return json!({"ok": false, "error": "invalid browser origin"});
        };
        let mut client = match AgentClient::connect(&Paths::resolve(None)) {
            Ok(client) => client,
            Err(error) => return json!({"ok": false, "error": error.to_string()}),
        };
        return match client.call("vault.fill", json!({"origin": origin})) {
            Ok(value) => json!({
                "ok": true,
                "password": value.get("password"),
                "username": value.get("username"),
            }),
            // Deliberately the agent's message and nothing more. Whether the
            // vault is locked, empty, or simply has nothing for this site are
            // one answer, or any page that can raise a fill learns what the
            // vault holds by asking.
            Err(error) => json!({"ok": false, "error": error.to_string()}),
        };
    }

    // An operation this build does not know is told apart from a request it
    // does know and cannot read. They are different problems with different
    // answers, and they used to share one sentence.
    //
    // The extension is loaded from the repository and changes the moment it is
    // rebuilt; this binary is a copy an installer made, and changes only when
    // it is reinstalled. So the two do drift apart, and "invalid browser
    // request" is what that drift looked like -- a sentence with nothing in it
    // about the cause or the fix.
    // A message with no operation at all is malformed, not old: nothing was
    // asked for, so there is nothing this build could be missing.
    if let Some(unknown) = operation.filter(|name| !matches!(*name, "create" | "get")) {
        return json!({
            "ok": false,
            "error": format!(
                "PhoneAuth host {} does not know the operation {}; reinstall the native host",
                env!("CARGO_PKG_VERSION"),
                name_of(Some(unknown)),
            ),
        });
    }
    let origin = message.get("origin").and_then(Value::as_str);
    let options = message.get("options").filter(|value| value.is_object());
    if operation.is_none() || request_id.is_none() || origin.is_none() || options.is_none() {
        return json!({"ok": false, "error": "invalid browser request"});
    }
    let mut client = match AgentClient::connect(&Paths::resolve(None)) {
        Ok(client) => client,
        Err(error) => return json!({"ok": false, "error": error.to_string()}),
    };
    match client.call(
        "webauthn.perform",
        json!({
            "operation": operation,
            "requestId": request_id,
            "origin": origin,
            "options": options,
        }),
    ) {
        Ok(value) => json!({"ok": true, "response": value.get("response")}),
        Err(error) => json!({"ok": false, "error": error.to_string()}),
    }
}

/// An operation name as it is safe to repeat back.
///
/// It arrives from the browser and is quoted into a sentence that ends up in a
/// badge tooltip and in whatever reads this host's output. Anything that is not
/// a plain name is not worth repeating, so what survives is a short run of the
/// characters an operation can actually contain.
fn name_of(operation: Option<&str>) -> String {
    let name: String = operation
        .unwrap_or_default()
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_')
        })
        .take(32)
        .collect();
    if name.is_empty() {
        "(none)".into()
    } else {
        format!("`{name}`")
    }
}

fn read_message(reader: &mut impl Read) -> Result<Option<Value>, String> {
    let mut length = [0u8; 4];
    let mut read = 0;
    while read < length.len() {
        match reader.read(&mut length[read..]) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => return Err("truncated native-messaging length".into()),
            Ok(count) => read += count,
            Err(error) => return Err(error.to_string()),
        }
    }
    let length = u32::from_ne_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Err("invalid native-messaging length".into());
    }
    let mut bytes = vec![0u8; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn write_message(writer: &mut impl Write, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_MESSAGE {
        return Err("native-messaging response is too large".into());
    }
    writer
        .write_all(&(bytes.len() as u32).to_ne_bytes())
        .and_then(|_| writer.write_all(&bytes))
        .and_then(|_| writer.flush())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_message_round_trips() {
        let mut bytes = Vec::new();
        write_message(&mut bytes, &json!({"hello": "world"})).unwrap();
        assert_eq!(
            read_message(&mut bytes.as_slice()).unwrap(),
            Some(json!({"hello": "world"}))
        );
    }

    /// The gate this binary puts in front of `vault.fill`, which has to agree
    /// with the agent's or it refuses requests the agent would have served.
    #[test]
    fn a_fill_origin_is_what_the_agent_would_accept() {
        for origin in [
            "https://bank.example",
            "https://bank.example:8443/login",
            "http://localhost:3000",
            "http://127.0.0.1:8080/",
            "http://app.localhost",
        ] {
            assert_eq!(
                fill_origin(&json!({ "origin": origin })),
                Some(origin),
                "{origin}"
            );
        }

        for origin in [
            "http://bank.example",
            "http://localhost.evil.example",
            "file:///etc/passwd",
            "bank.example",
            "",
        ] {
            assert_eq!(fill_origin(&json!({ "origin": origin })), None, "{origin}");
        }

        assert_eq!(fill_origin(&json!({})), None);
        let long = format!("https://{}.example", "a".repeat(250));
        assert_eq!(fill_origin(&json!({ "origin": long })), None);
    }

    /// Version skew has its own answer now. The extension updates when the
    /// repository is rebuilt and this binary updates when it is reinstalled, so
    /// an extension that knows an operation this build does not is the ordinary
    /// way the two come apart -- and the reply has to say which half is behind.
    #[test]
    fn an_operation_this_build_does_not_know_names_the_host_and_the_fix() {
        let reply = handle(json!({"operation": "vault-store", "requestId": "abc"}));
        let error = reply["error"].as_str().unwrap();

        assert_eq!(reply["ok"], json!(false));
        assert!(error.contains(env!("CARGO_PKG_VERSION")), "{error}");
        assert!(error.contains("`vault-store`"), "{error}");
        assert!(error.contains("reinstall"), "{error}");
    }

    /// The other half of the split: an operation this build does know, in a
    /// message it cannot read, is not a version problem and must not send
    /// somebody reinstalling.
    #[test]
    fn a_known_operation_with_a_broken_body_is_not_reported_as_version_skew() {
        let reply = handle(json!({"operation": "get", "requestId": "abc"}));

        assert_eq!(reply["ok"], json!(false));
        assert_eq!(reply["error"], json!("invalid browser request"));
    }

    /// The name is quoted into a sentence that leaves this process, so what can
    /// be quoted is a short plain name and nothing else.
    #[test]
    fn an_operation_name_is_trimmed_before_it_is_repeated() {
        assert_eq!(name_of(Some("vault-fill")), "`vault-fill`");
        assert_eq!(name_of(None), "(none)");
        assert_eq!(name_of(Some("  ")), "(none)");
        assert_eq!(
            name_of(Some(
                "a
b <script>"
            )),
            "`abscript`"
        );
        assert_eq!(
            name_of(Some(&"x".repeat(64))),
            format!("`{}`", "x".repeat(32))
        );
    }

    /// A message with no operation asked for nothing, so nothing is missing
    /// from this build and the reply must not send anybody reinstalling.
    #[test]
    fn a_message_with_no_operation_is_malformed_rather_than_old() {
        let reply = handle(json!({"requestId": "abc"}));

        assert_eq!(reply["ok"], json!(false));
        assert_eq!(reply["error"], json!("invalid browser request"));
    }

    #[test]
    fn oversized_message_is_rejected_before_allocation() {
        let bytes = ((MAX_MESSAGE as u32) + 1).to_ne_bytes();
        assert!(read_message(&mut bytes.as_slice()).is_err());
    }
}
