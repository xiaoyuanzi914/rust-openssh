mod auth_krb5;

use log::{info, LevelFilter};
use simple_logger::SimpleLogger;  // Ensure this import is here
use auth_krb5::AuthCtxt;  // Import AuthCtxt from auth_krb5.rs


fn main() {
    // Initialize logger
    SimpleLogger::new().with_level(LevelFilter::Info).init().unwrap();

    // Create AuthCtxt and test Kerberos authentication
    let mut authctxt = AuthCtxt {
        krb5_ctx: None,
        krb5_user: None,
        krb5_fwd_ccache: None,
        krb5_ticket_file: None,
        krb5_ccname: None,
        pw_name: "user".to_string(),
        valid: false,
    };

    let password = "password";
    match authctxt.auth_krb5_password(password) {
        1 => info!("Authentication successful"),
        0 => info!("Authentication failed"),
        _ => info!("Error occurred"),
    }
}

