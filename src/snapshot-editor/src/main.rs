// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};

mod edit_memory;
mod info;
mod utils;

use edit_memory::{EditMemoryError, EditMemorySubCommand, edit_memory_command};
use info::{InfoVmStateError, InfoVmStateSubCommand, info_vmstate_command};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum SnapEditorError {
    /// Error during editing memory file: {0}
    EditMemory(#[from] EditMemoryError),
    /// Error during getting info from a vmstate file: {0}
    InfoVmState(#[from] InfoVmStateError),
}

#[derive(Debug, Parser)]
#[command(version = format!("v{}", env!("CARGO_PKG_VERSION")))]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(subcommand)]
    EditMemory(EditMemorySubCommand),
    #[command(subcommand)]
    InfoVmstate(InfoVmStateSubCommand),
}

fn main_exec() -> Result<(), SnapEditorError> {
    let cli = Cli::parse();

    match cli.command {
        Command::EditMemory(command) => edit_memory_command(command)?,
        Command::InfoVmstate(command) => info_vmstate_command(command)?,
    }

    Ok(())
}

fn main() -> Result<(), SnapEditorError> {
    let result = main_exec();
    if let Err(e) = result {
        eprintln!("{}", e);
        Err(e)
    } else {
        Ok(())
    }
}
