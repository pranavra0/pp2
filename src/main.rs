use std::{env, error::Error, fs::File, io::Read, process::ExitCode};

use pp2::{Block, Cluster, Limits, LocalityPolicy, Program};

mod app_cli;
mod demo;
mod native_cli;
mod peer_cli;
mod project_cli;
mod replica_cli;

const USAGE: &str = "pp2 — Write programs, not servers.

  pp2 new DIRECTORY                   Create a document search project
  pp2 install PROJECT                 Review and install from source
  pp2 grant NAME DIRECTORY [HOLDER]   Connect a directory locally or issue a peer grant
  pp2 run [LINE]                      Open the app or send one line
  pp2 update PROJECT                  Review changes and keep installation state
  pp2 list                            List installed applications
  pp2 status                          Inspect the selected app and its grants

Across machines
  pp2 publish                         Publish selected app code and print PACKAGE@PEER
  pp2 install --from PACKAGE@PEER      Fetch and review a published app
  pp2 update --from PACKAGE@PEER       Review a published update
  pp2 identity                        Print this machine's peer ID
  pp2 host [BIND]                     Serve resources (default: an available TCP port)
  pp2 connect NAME GRANT_FILE         Attach a grant from the resource owner
  pp2 revoke GRANT_ID                 Withdraw a grant issued here

Set PP2_HOME to select a workspace (default: ~/.pp2).
Set PP2_APP to an installation ID when more than one app is installed.

Administration and runtime tools
  pp2 app --help       Package and deployment operations
  pp2 peer --help      Storage, networking and authority
  pp2 demo             Run a runtime demonstration
  pp2 eval FILE        Evaluate a binary program";

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => println!("{USAGE}"),
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
        _ => project_cli::run(&args)?,
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
