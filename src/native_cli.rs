use std::{
    fs::{self, File},
    io::{self, BufRead, Read, Write},
    net::TcpListener,
    path::Path,
};

use crate::{
    app_cli::{credentials, network, node_init, read_document},
    peer_cli::access,
};
use pp2::{
    Hash,
    peer::{Access, Binding, Client, NativeInstallation, NativePackage, PeerStore, Server},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) const USAGE: &str = "Usage: pp2 app native <command>
  identity HOME
  pack MANIFEST_JSON PACKAGE_FILE
  host HOME [BIND]
  share-directory HOME REFERENCE DIRECTORY HOLDER_ID PROGRAM reader|writer
  install HOME PACKAGE [SOURCE_ID[@ADDRESS] ...] [--yes]
  update HOME APPLICATION PACKAGE [SOURCE_ID[@ADDRESS] ...] [--yes]
  grant HOME APPLICATION NAME GRANT_JSON
  disconnect HOME APPLICATION NAME
  list HOME
  status HOME APPLICATION
  run HOME APPLICATION [LINE] [--metrics]
  remove HOME APPLICATION";

pub(crate) fn run(args: &[&str]) -> Result<()> {
    match args {
        [] | ["--help" | "-h"] => println!("{USAGE}"),
        ["identity", home] => {
            println!("{}", network(workspace(home)?)?.id());
        }
        ["pack", manifest, output] => {
            let manifest: NativePackage = read_document(File::open(manifest)?)?;
            let bytes = manifest.to_bytes()?;
            fs::write(output, &bytes)?;
            println!("{}", Hash::digest(&bytes));
        }
        ["host", home, bind @ ..] if bind.len() <= 1 => {
            let listener = TcpListener::bind(bind.first().copied().unwrap_or("0.0.0.0:0"))?;
            let server = server(workspace(home)?)?;
            println!("listening on {}", listener.local_addr()?);
            server.serve(listener)?;
        }
        [
            "share-directory",
            home,
            reference,
            directory,
            holder,
            program,
            level,
        ] => {
            let binding = directory_grant(
                workspace(home)?,
                reference,
                Path::new(directory),
                holder.parse()?,
                program.parse()?,
                access(level)?,
            )?;
            println!("{}", serde_json::to_string_pretty(&binding)?);
        }
        ["install", home, package, sources @ ..] | ["update", home, _, package, sources @ ..] => {
            let home = workspace(home)?;
            let mut store = open(home)?;
            let previous = if args[0] == "update" {
                Some(store.native_installation(args[2].parse()?)?)
            } else {
                None
            };
            let (manifest, yes) = fetch(home, &mut store, package.parse()?, sources)?;
            apply_package(&mut store, &manifest, package, previous.as_ref(), yes)?;
        }
        ["grant", home, id, name, file] => {
            bind(
                home,
                id.parse()?,
                name,
                Some(read_document(File::open(file)?)?),
            )?;
        }
        ["disconnect", home, id, name] => bind(home, id.parse()?, name, None)?,
        ["list", home] => {
            let store = open(workspace(home)?)?;
            for id in store.native_installations()? {
                let app = store.native_installation(id)?;
                println!("{id}  {}", visible(&app.manifest.name));
            }
        }
        ["status", home, id] => {
            let app = open(workspace(home)?)?.native_installation(id.parse()?)?;
            println!("{}  {}", app.id, visible(&app.manifest.name));
            println!("Package {}", app.package);
            for (name, request) in &app.manifest.bindings {
                if let Some(binding) = app.bindings.get(name) {
                    println!("{name}  {:?}  {}", binding.access, binding.peer);
                } else {
                    println!("{name}  {:?}  awaiting grant", request.access);
                }
            }
        }
        ["run", home, id, input @ ..] => {
            let (metrics, input) = match input.split_last() {
                Some((&"--metrics", before)) => (true, before),
                _ => (false, input),
            };
            if input.len() > 1 {
                return Err(USAGE.into());
            }
            shell(
                &server(workspace(home)?)?,
                id.parse()?,
                input.first().copied(),
                metrics,
            )?;
        }
        ["remove", home, id] => open(workspace(home)?)?.remove_native(id.parse()?)?,
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

pub(crate) fn workspace(home: &str) -> Result<&Path> {
    let path = Path::new(home);
    if !path.exists() {
        node_init(path)?;
    }
    Ok(path)
}

pub(crate) fn open(home: &Path) -> Result<PeerStore> {
    Ok(PeerStore::open(home.join("peer.db"))?)
}

pub(crate) fn server(home: &Path) -> Result<Server> {
    Ok(Server::new_discovered(
        home.join("peer.db"),
        std::env::current_exe()?,
        &credentials(home),
        network(home)?,
    )?)
}

fn fetch(
    home: &Path,
    store: &mut PeerStore,
    package: Hash,
    sources: &[&str],
) -> Result<(NativePackage, bool)> {
    let (sources, yes) = match sources.split_last() {
        Some((&"--yes", before)) => (before, true),
        _ => (sources, false),
    };
    let network = network(home)?;
    let clients = sources
        .iter()
        .map(|source| -> Result<Client> {
            let (id, address) = match source.split_once('@') {
                Some((id, address)) => (id, Some(address.parse()?)),
                None => (*source, None),
            };
            Ok(Client::for_peer(&network, id.parse()?, address))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((NativePackage::fetch(store, &clients, package)?, yes))
}

pub(crate) fn apply_package(
    store: &mut PeerStore,
    manifest: &NativePackage,
    package: &str,
    previous: Option<&NativeInstallation>,
    yes: bool,
) -> Result<()> {
    approve(manifest, package, previous.map(|app| &app.manifest), yes)?;
    let id = if let Some(app) = previous {
        store.update_native(app.id, app.package, manifest)?;
        app.id
    } else {
        store.install_native(manifest)?
    };
    println!("{id}");
    Ok(())
}

fn approve(
    manifest: &NativePackage,
    package: &str,
    previous: Option<&NativePackage>,
    yes: bool,
) -> Result<()> {
    eprintln!("{}  {package}", visible(&manifest.name));
    eprintln!("  Terminal input and text output while running");
    eprintln!("  Read and write its private application state");
    eprintln!(
        "  Invocation budget of {} ms, {} calls and depth {}",
        manifest.budget.timeout_ms, manifest.budget.calls, manifest.budget.depth
    );
    for (name, request) in &manifest.bindings {
        let status = if previous.and_then(|old| old.bindings.get(name)) == Some(request) {
            "existing request"
        } else {
            "requires a separate grant"
        };
        eprintln!(
            "  {name}  {:?}  {}  ({status})",
            request.access,
            visible(&request.description)
        );
        eprintln!("    Program {}", request.program);
    }
    if !yes {
        eprint!("Approve this package? [y/N] ");
        io::stderr().flush()?;
        if read_line(&mut io::stdin().lock())?
            .is_none_or(|answer| !matches!(answer.trim(), "y" | "Y" | "yes"))
        {
            return Err("package approval declined".into());
        }
    }
    Ok(())
}

fn bind(home: &str, id: Hash, name: &str, binding: Option<Binding>) -> Result<()> {
    let mut store = open(workspace(home)?)?;
    let app = store.native_installation(id)?;
    if let Some(grant) = &binding {
        eprintln!(
            "Connecting {name} to {:?} grant from {}",
            grant.access, grant.peer
        );
    }
    Ok(store.bind_native(id, app.package, name, binding)?)
}

#[cfg(target_os = "linux")]
pub(crate) fn directory_grant(
    home: &Path,
    reference: &str,
    directory: &Path,
    holder: Hash,
    program: Hash,
    access: Access,
) -> Result<Binding> {
    let peer = network(home)?.id();
    let resource = pp2::peer::Directory::resource(directory)?;
    let grant = open(home)?.share_host_resource(reference, resource, holder, program, access)?;
    eprintln!("Directory grant {grant}");
    Ok(Binding {
        peer,
        grant,
        program,
        access,
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn directory_grant(
    _: &Path,
    _: &str,
    _: &Path,
    _: Hash,
    _: Hash,
    _: Access,
) -> Result<Binding> {
    Err("directory grants require Linux".into())
}

pub(crate) fn shell(server: &Server, id: Hash, first: Option<&str>, metrics: bool) -> Result<()> {
    let event = |line: &str| -> Result<()> {
        let (result, report) = server.run_native(id, line)?;
        for line in result.lines {
            println!("{}", visible(&line));
        }
        if metrics {
            eprintln!("{}", serde_json::to_string(&report)?);
        }
        Ok(())
    };
    if let Some(line) = first {
        return event(line);
    }
    let input = io::stdin();
    let interactive = io::IsTerminal::is_terminal(&input);
    let mut input = input.lock();
    loop {
        if interactive {
            print!("> ");
            io::stdout().flush()?;
        }
        let Some(line) = read_line(&mut input)? else {
            break;
        };
        if line == ".quit" {
            break;
        }
        if let Err(error) = event(&line) {
            eprintln!("{}", visible(&error.to_string()));
        }
    }
    Ok(())
}

fn visible(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() || matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            result.extend(ch.escape_default());
        } else {
            result.push(ch);
        }
    }
    result
}

fn read_line(reader: &mut impl BufRead) -> Result<Option<String>> {
    let mut line = String::new();
    if reader.take(4098).read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let line = line.strip_suffix('\n').unwrap_or(&line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.len() > 4096 {
        return Err("terminal event exceeds 4096 bytes".into());
    }
    Ok(Some(line.to_owned()))
}
