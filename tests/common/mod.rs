use std::sync::Once;
use log::LevelFilter;

static INIT: Once = Once::new();

pub fn setup() {
    INIT.call_once(|| {
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .try_init();
    });
}