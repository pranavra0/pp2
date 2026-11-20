use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};

use pp2::{
    Data, Hash,
    peer::{
        Access, Binding, Client, EvaluationMode, GraphBudget, NativePackage, PeerStore,
        RequestedBinding, data_from_json, data_to_json, package_source,
    },
};
use serde::Deserialize;

use crate::{
    app_cli::{ModuleSpec, network, package, read_document},
    native_cli,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    name: String,
    entry: String,
    #[serde(default)]
    modules: BTreeMap<String, ModuleSpec>,
    budget: GraphBudget,
    bindings: BTreeMap<String, Request>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    description: String,
    program: String,
    access: Access,
}

fn build(directory: &Path, store: &mut PeerStore) -> Result<(NativePackage, Hash)> {
    let path = directory.join("pp2.json");
    let file = fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let project: Project = read_document(file)?;
    let mut compiled = BTreeMap::new();
    let mut compile = |name: &str| {
        if project.modules.is_empty() {
            import_source(store, &directory.join(name))
        } else {
            package(
                name,
                &project.modules,
                directory,
                &mut BTreeSet::new(),
                &mut compiled,
            )
        }
    };
    let entry = compile(&project.entry)?;
    let mut bindings = BTreeMap::new();
    for (name, request) in project.bindings {
        bindings.insert(
            name,
            RequestedBinding {
                program: compile(&request.program)?,
                description: request.description,
                access: request.access,
            },
        );
    }
    let manifest = NativePackage {
        name: project.name,
        entry,
        budget: project.budget,
        bindings,
    };
    let hash = Hash::digest(&manifest.to_bytes()?);
    for (_, (hash, bytes)) in compiled {
        store.import(hash, &bytes)?;
    }
    Ok((manifest, hash))
}

fn selected(store: &PeerStore) -> Result<Hash> {
    if let Some(id) = env::var_os("PP2_APP") {
        return Ok(id.to_str().ok_or("invalid PP2_APP")?.parse()?);
    }
    match store.native_installations()?.as_slice() {
        [id] => Ok(*id),
        [] => Err("No apps installed. Run pp2 install PROJECT.".into()),
        _ => Err("Choose an installation from pp2 list and set PP2_APP to its ID.".into()),
    }
}

fn import_source(store: &mut PeerStore, source: &Path) -> Result<Hash> {
    let blocks = package_source(source)?;
    let entry = blocks
        .last()
        .ok_or("Expected an executable entry module.")?
        .0;
    for (hash, bytes) in blocks {
        store.import(hash, &bytes)?;
    }
    Ok(entry)
}

fn evaluate(
    home: &Path,
    source: &str,
    input: Option<&str>,
    target: Option<(Binding, EvaluationMode)>,
) -> Result<()> {
    let input = match input {
        Some(input) => data_from_json(serde_json::from_str(input)?)?,
        None => Data::Nil,
    };
    let mut store = native_cli::open(home)?;
    let program = match (source, &target, source.parse::<Hash>()) {
        ("-", Some((binding, _)), _) => binding.program,
        (_, _, Ok(hash)) => hash,
        _ => import_source(&mut store, Path::new(source))?,
    };
    let result = if let Some((binding, mode)) = target {
        if binding.program != program {
            return Err("The grant pins a different program hash.".into());
        }
        native_cli::server(home)?.evaluate_bound(&binding, mode, &input)?
    } else {
        if source.parse::<Hash>().is_ok() {
            Client::fetch_discovered_program(&mut store, &network(home)?, program)?;
        }
        native_cli::server(home)?.evaluate_program(program, &input)?
    };
    println!("{}", data_to_json(&result.value)?);
    Ok(())
}

fn starter(dir: &Path) -> Result<()> {
    fs::create_dir(dir).map_err(|e| format!("Create {}: {e}", dir.display()))?;
    macro_rules! template {
        ($name:literal) => {
            (
                $name,
                include_str!(concat!("../examples/native-documents/", $name)),
            )
        };
    }
    let files = [
        template!("pp2.json"),
        template!("app.mjs"),
        template!("index.ts"),
        template!("directory.d.ts"),
        template!("tsconfig.json"),
        ("package.json", include_str!("../package.json")),
        ("package-lock.json", include_str!("../package-lock.json")),
    ];
    for (name, contents) in files {
        fs::write(dir.join(name), contents)?;
    }
    println!(
        "Created {}. Edit index.ts and run pp2 install with the project directory.",
        dir.display()
    );
    Ok(())
}

pub(crate) fn run(args: &[std::ffi::OsString]) -> Result<()> {
    let args = args
        .iter()
        .map(|s| s.to_str().ok_or("Expected UTF-8 arguments"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if let [command, "--help" | "-h"] = args.as_slice() {
        let prefix = format!("pp2 {command} ");
        let lines: Vec<_> = crate::USAGE
            .lines()
            .map(str::trim_start)
            .filter(|line| line.starts_with(&prefix))
            .collect();
        if !lines.is_empty() {
            println!("{}", lines.join("\n"));
            return Ok(());
        }
    }
    if let ["new", dir] = args.as_slice() {
        return starter(Path::new(dir));
    }
    let home = env::var_os("PP2_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|dir| PathBuf::from(dir).join(".pp2")))
        .ok_or("Set PP2_HOME to a private workspace directory.")?;
    let home = home.to_str().ok_or("Expected a UTF-8 workspace path")?;
    match args.as_slice() {
        ["pack", source, flags @ ..] if matches!(flags, [] | ["--publish"]) => {
            let mut store = native_cli::open(native_cli::workspace(home)?)?;
            let program = import_source(&mut store, Path::new(source))?;
            if !flags.is_empty() {
                store.publish_graph(program)?;
            }
            println!("{program}");
        }
        [
            "eval",
            mode @ ("--at" | "--replica"),
            grant,
            source,
            input @ ..,
        ] if input.len() <= 1 => {
            let mode = if *mode == "--replica" {
                EvaluationMode::ReadReplica
            } else {
                EvaluationMode::Read
            };
            evaluate(
                native_cli::workspace(home)?,
                source,
                input.first().copied(),
                Some((read_document(fs::File::open(grant)?)?, mode)),
            )?;
        }
        ["eval", source, input @ ..] if input.len() <= 1 => {
            evaluate(
                native_cli::workspace(home)?,
                source,
                input.first().copied(),
                None,
            )?;
        }
        [command @ ("install" | "update"), "--from", release] => {
            let (package, source) = release
                .split_once('@')
                .ok_or("Use the PACKAGE@PEER printed by pp2 publish.")?;
            package.parse::<Hash>()?;
            source
                .split_once('@')
                .map_or(source, |(id, _)| id)
                .parse::<Hash>()
                .map_err(|_| "Expected the peer identity printed by pp2 publish.")?;
            let mut args = vec![*command, home];
            let id;
            if *command == "update" {
                id = selected(&native_cli::open(native_cli::workspace(home)?)?)?.to_string();
                args.push(&id);
            }
            args.extend([package, source]);
            native_cli::run(&args)?;
        }
        ["publish"] => {
            let home = native_cli::workspace(home)?;
            let mut store = native_cli::open(home)?;
            let app = store.native_installation(selected(&store)?)?;
            let mut blocks = BTreeSet::new();
            for program in app.manifest.programs() {
                blocks.extend(Client::fetch_program(&mut store, &[], program)?);
            }
            let publisher = network(home)?.id();
            blocks.insert(app.package);
            store.publish_all(&blocks.into_iter().collect::<Vec<_>>())?;
            println!("{}@{publisher}", app.package);
        }
        ["install" | "update", directory] => {
            let mut store = native_cli::open(native_cli::workspace(home)?)?;
            let previous = if args[0] == "update" {
                Some(store.native_installation(selected(&store)?)?)
            } else {
                None
            };
            let (manifest, hash) = build(Path::new(directory), &mut store)?;
            native_cli::apply_package(
                &mut store,
                &manifest,
                &hash.to_string(),
                previous.as_ref(),
                false,
            )?;
        }
        [command @ ("list" | "identity")] => native_cli::run(&[command, home])?,
        ["host", bind @ ..] if bind.len() <= 1 => {
            native_cli::run(&[&["host", home][..], bind].concat())?
        }
        ["revoke", grant] => {
            if !native_cli::open(native_cli::workspace(home)?)?.revoke(grant.parse()?)? {
                return Err("Grant is unknown or already revoked.".into());
            }
        }
        ["grant", name, directory, holder @ ..] if holder.len() <= 1 => {
            let home = native_cli::workspace(home)?;
            let mut store = native_cli::open(home)?;
            let app = store.native_installation(selected(&store)?)?;
            let request = app
                .manifest
                .bindings
                .get(*name)
                .ok_or("Unknown resource name. Run pp2 status to see the requests.")?;
            let recipient = match holder {
                [id] => id.parse()?,
                _ => network(home)?.id(),
            };
            let path = Path::new(directory);
            let absolute = std::path::absolute(path)?;
            let reference = Hash::digest(&serde_json::to_vec(&(
                app.id,
                name,
                request.program,
                absolute,
            ))?)
            .to_string();
            let binding = native_cli::directory_grant(
                home,
                &reference,
                path,
                recipient,
                request.program,
                request.access,
            )?;
            if holder.is_empty() {
                if let Err(error) =
                    store.bind_native(app.id, app.package, name, Some(binding.clone()))
                {
                    store.revoke(binding.grant)?;
                    return Err(error.into());
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&binding)?);
            }
        }
        ["run", input @ ..] if input.len() <= 1 => {
            let home = native_cli::workspace(home)?;
            let id = selected(&native_cli::open(home)?)?;
            native_cli::shell(
                &native_cli::server(home)?,
                id,
                input.first().copied(),
                false,
            )?;
        }
        ["status"] | ["connect", _, _] => {
            let id = selected(&native_cli::open(native_cli::workspace(home)?)?)?.to_string();
            let command = if args[0] == "connect" {
                "grant"
            } else {
                args[0]
            };
            native_cli::run(&[&[command, home, &id][..], &args[1..]].concat())?;
        }
        _ => {
            return Err(
                format!("Unknown command or incorrect arguments.\n{}", crate::USAGE).into(),
            );
        }
    }
    Ok(())
}
