//! Browser native-messaging bridge to the authenticated PhoneAuth agent IPC.

use std::io::{self, Read, Write};

use phone_auth_agent::{AgentClient, Paths};
use serde_json::{json, Value};

const MAX_MESSAGE: usize = 128 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("phone-auth-webauthn-host: {error}");
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

fn handle(message: Value) -> Value {
    let operation = message.get("operation").and_then(Value::as_str);
    let origin = message.get("origin").and_then(Value::as_str);
    let options = message.get("options").filter(|value| value.is_object());
    if !matches!(operation, Some("create" | "get")) || origin.is_none() || options.is_none() {
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
            "origin": origin,
            "options": options,
        }),
    ) {
        Ok(value) => json!({"ok": true, "response": value.get("response")}),
        Err(error) => json!({"ok": false, "error": error.to_string()}),
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

    #[test]
    fn oversized_message_is_rejected_before_allocation() {
        let bytes = ((MAX_MESSAGE as u32) + 1).to_ne_bytes();
        assert!(read_message(&mut bytes.as_slice()).is_err());
    }
}
