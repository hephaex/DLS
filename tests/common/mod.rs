use log::LevelFilter;
use std::sync::Once;

static INIT: Once = Once::new();

pub fn setup() {
    INIT.call_once(|| {
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .try_init();
    });
}
