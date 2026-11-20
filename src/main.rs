use std::{env, error::Error, fs::File, io::Read, process::ExitCode};

use pp2::{Block, Cluster, Limits, LocalityPolicy, Program};

mod app_cli;
mod demo;
mod native_cli;
mod peer_cli;

const USAGE: &str = "Usage: pp2 app <command>\n       pp2 peer <command>\n       pp2 demo [sandbox|placement|locality|gossip|gc]\n       pp2 eval <AEB1-program-file>";

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => demo::run(None)?,
        [flag] if flag == "--help" || flag == "-h" => println!("{USAGE}"),
        [command, parent] if command == "__worker" => {
            pp2::peer::worker_main(parent.to_str().ok_or(USAGE)?.parse()?)?;
        }
        [command, rest @ ..] if command == "app" => app_cli::run(rest)?,
        [command, rest @ ..] if command == "peer" => peer_cli::run(rest)?,
        [command] if command == "demo" => demo::run(None)?,
        [command, scenario] if command == "demo" => {
            let scenario = scenario.to_str().ok_or(USAGE)?;
            demo::run(Some(scenario))?;
        }
        [command, path] if command == "eval" => {
            let mut bytes = Vec::new();
            File::open(path)?
                .take(Block::MAX_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            let program = Program::from_bytes(&bytes)?;
            let mut cluster = Cluster::new();
            let node = cluster.add_node()?;
            let hash = cluster.put(node, &Block::Program(program))?;
            let report = cluster.run(
                node,
                hash,
                &[],
                Limits::default(),
                LocalityPolicy::default(),
            )?;
            println!("{:?}", report.value);
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
