// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Subcommand;
use vmm::persist::MicrovmState;
use vmm::snapshot::Snapshot;

use crate::utils::*;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum InfoVmStateError {
    /// {0}
    Utils(#[from] UtilsError),
}

#[derive(Debug, Subcommand)]
pub enum InfoVmStateSubCommand {
    /// Print snapshot version.
    Version {
        /// Path to the vmstate file.
        #[arg(short, long)]
        vmstate_path: PathBuf,
    },
    /// Print info about vcpu states.
    VcpuStates {
        /// Path to the vmstate file.
        #[arg(short, long)]
        vmstate_path: PathBuf,
    },
    MsrState {
        #[arg(short, long)]
        vmstate_path: PathBuf,
    },
    /// Print readable MicroVM state.
    VmState {
        /// Path to the vmstate file.
        #[arg(short, long)]
        vmstate_path: PathBuf,
    },
}

pub fn info_vmstate_command(command: InfoVmStateSubCommand) -> Result<(), InfoVmStateError> {
    match command {
        InfoVmStateSubCommand::Version { vmstate_path } => info(&vmstate_path, info_version)?,
        InfoVmStateSubCommand::VcpuStates { vmstate_path } => {
            info(&vmstate_path, info_vcpu_states)?
        }
        InfoVmStateSubCommand::MsrState { vmstate_path } => {
            info(&vmstate_path, msr_state)?
        }
        InfoVmStateSubCommand::VmState { vmstate_path } => info(&vmstate_path, info_vmstate)?,
    }
    Ok(())
}

fn info(
    vmstate_path: &PathBuf,
    f: impl Fn(&Snapshot<MicrovmState>) -> Result<(), InfoVmStateError>,
) -> Result<(), InfoVmStateError> {
    let snapshot = open_vmstate(vmstate_path)?;
    f(&snapshot)?;
    Ok(())
}

fn info_version(snapshot: &Snapshot<MicrovmState>) -> Result<(), InfoVmStateError> {
    println!("v{}", snapshot.version());
    Ok(())
}

fn info_vcpu_states(snapshot: &Snapshot<MicrovmState>) -> Result<(), InfoVmStateError> {
    for (i, state) in snapshot.data.vcpu_states.iter().enumerate() {
        println!("vcpu {i}:");
        println!("{state:#?}");
    }
    Ok(())
}

// 我自己加的查询 snapshot 中的 msr 信息
fn msr_state(snapshot: &Snapshot<MicrovmState>) -> Result<(), InfoVmStateError> {
    for (i, state) in snapshot.data.vcpu_states.iter().enumerate() {
        println!("vcpu {i}:");

        // 额外结构化打印真正的 MSR entry
        println!("saved_msrs:");

        for (chunk_index, chunk) in state.saved_msrs.iter().enumerate() {
            let entries = chunk.as_slice();

            println!("  chunk {chunk_index}:");
            println!("    count: {}", entries.len());

            for (entry_index, entry) in entries.iter().enumerate() {
                println!("    entry {entry_index}:");
                println!("      index: {:#x}", entry.index);
                println!("      data:  {:#x}", entry.data);
            }
        }

        println!();
    }
    Ok(())
}

fn info_vmstate(snapshot: &Snapshot<MicrovmState>) -> Result<(), InfoVmStateError> {
    println!("{:#?}", snapshot.data);
    Ok(())
}
