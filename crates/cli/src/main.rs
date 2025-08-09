use log::info;

mod init_logging;

fn main() {
    init_logging::init_logging();
    info!("Hello, world!");
}
