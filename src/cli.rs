use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server {
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        bind: String,
    },
    Client {
        #[arg(short, long)]
        server: String,
    },
    Image {
        #[command(subcommand)]
        action: ImageCommands,
    },
}

#[derive(Subcommand)]
enum ImageCommands {
    List,
    Create {
        name: String,
        size: String,
    },
    Delete {
        name: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Server { bind } => {
            println!("Starting server on {}", bind);
        }
        Commands::Client { server } => {
            println!("Connecting to server at {}", server);
        }
        Commands::Image { action } => match action {
            ImageCommands::List => {
                println!("Listing images...");
            }
            ImageCommands::Create { name, size } => {
                println!("Creating image {} with size {}", name, size);
            }
            ImageCommands::Delete { name } => {
                println!("Deleting image {}", name);
            }
        },
    }

    Ok(())
}