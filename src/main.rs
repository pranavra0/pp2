use pp2::{
    Hash,
    peer::{Options, Peer, PeerError, Result, serve_rendezvous, worker_main},
};
use std::{
    env,
    net::TcpListener,
    path::{Path, PathBuf},
};

const USAGE: &str = "usage: pp2 init | serve ADDRESS | rendezvous ADDRESS | create RESOURCE JSON | pack FILE | grant RESOURCE HOLDER PROGRAM read|write | revoke CAPABILITY | eval FILE_OR_HASH [OPTIONS_JSON] | pin FILE_OR_HASH [OPTIONS_JSON]";

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
fn run() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let home = env::var_os("PP2_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| ".pp2".into());
    match *args.as_slice() {
        ["__worker", parent] => {
            return worker_main(
                parent
                    .parse()
                    .map_err(|_| PeerError::Invalid("invalid parent"))?,
            );
        }
        ["init"] => {
            println!("{}", Peer::init(&home)?);
            return Ok(());
        }
        ["rendezvous", addr] => {
            let listener = TcpListener::bind(addr)?;
            println!("{}", listener.local_addr()?);
            return serve_rendezvous(listener, true);
        }
        [] | ["--help"] => {
            println!("{USAGE}");
            return Ok(());
        }
        _ => {}
    }
    let peer = Peer::open(&home, &env::current_exe()?)?;
    match *args.as_slice() {
        ["serve", addr] => {
            let listener = TcpListener::bind(addr)?;
            println!("{}@{}", peer.id(), listener.local_addr()?);
            peer.serve(listener)?
        }
        ["create", name, state] => peer.create(name, serde_json::from_str(state)?)?,
        ["pack", file] => println!("{}", peer.pack(Path::new(file))?),
        ["grant", name, holder, program, mode @ ("read" | "write")] => println!(
            "{}",
            peer.grant(name, holder.parse()?, program.parse()?, mode == "write")?
        ),
        ["revoke", cap] => peer.revoke(cap)?,
        [cmd @ ("eval" | "pin"), program, ref rest @ ..] if rest.len() <= 1 => {
            let options: Options = serde_json::from_str(rest.first().copied().unwrap_or("{}"))?;
            let hash = match program.parse::<Hash>() {
                Ok(hash) => hash,
                Err(_) => peer.pack(Path::new(program))?,
            };
            let result = peer.evaluate(hash, options)?;
            if cmd == "pin" {
                println!("{}", serde_json::to_string(&peer.pin(result)?)?)
            } else {
                println!("{result}")
            }
        }
        _ => return Err(PeerError::Invalid(USAGE)),
    }
    Ok(())
}
