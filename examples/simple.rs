use dls_server::hello;

fn main() {
    println!("{}", hello());
    
    #[cfg(target_os = "freebsd")]
    println!("Running on FreeBSD");
    
    #[cfg(target_os = "macos")]
    println!("Running on macOS");
    
    #[cfg(not(any(target_os = "freebsd", target_os = "macos")))]
    println!("Running on other OS");
    
    println!("Target OS: {}", std::env::consts::OS);
    println!("Target Arch: {}", std::env::consts::ARCH);
    println!("Target Family: {}", std::env::consts::FAMILY);
}