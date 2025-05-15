use tracing::Level;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_tracing(level: Level) {
    // Build a filter that allows logs at and above the specified level
    let filter = EnvFilter::from_default_env()
        .add_directive(
            format!("{}={}", env!("CARGO_PKG_NAME"), level.as_str())
                .parse()
                .unwrap(),
        )
        .add_directive("tokio=warn".parse().unwrap())
        .add_directive("runtime=warn".parse().unwrap());

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_file(false)
        .with_line_number(false)
        .with_ansi(true)
        .compact()
        .init();

    tracing::info!("Tracing initialized with level: {:?}", level);
}
