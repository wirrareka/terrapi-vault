//! Encrypted recovery control journal, independent of application schemas and transport.
//! Policy integrations must establish authority continuity, fencing and member evidence.
#![forbid(unsafe_code)]
pub mod decision;
pub mod grant;
pub mod model;
pub mod transition;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
