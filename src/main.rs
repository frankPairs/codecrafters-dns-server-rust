mod error;
mod message;
mod server;

use std::env;

use crate::server::DnsServer;

const RESOLVER_ARG_NAME: &str = "--resolver";

fn main() {
    let server = DnsServer::bind("127.0.0.1:2053").unwrap();
    let mut cli_args = env::args();

    let resolver_addr = cli_args
        .nth(1)
        .and_then(|arg_name| {
            if arg_name == RESOLVER_ARG_NAME {
                Some(arg_name)
            } else {
                None
            }
        })
        .and_then(|_| cli_args.next());

    server.listen(resolver_addr.as_deref()).unwrap();
}
