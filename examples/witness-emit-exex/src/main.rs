//! `reth-witness-emit-node` — a reth node binary with an ExEx installed that
//! emits per-block witness bundles to a local directory.
//!
//! All standard reth flags work as-is; we add:
//!
//! ```text
//! --witness-emit-dir <PATH>      where to write per-block .witness.zst files
//! --witness-stats <PATH>         optional JSONL stats file
//! ```
//!
//! Run on a fresh datadir + ports — do NOT point at a prod reth datadir.

use clap::Parser;
use reth_ethereum::{
    cli::{chainspec::EthereumChainSpecParser, interface::Cli},
    node::EthereumNode,
};
use std::path::PathBuf;

mod bundle;
mod exex;

/// Extra CLI flags layered on top of the standard reth node flags.
#[derive(Debug, Parser)]
pub struct WitnessEmitArgs {
    /// Directory to write per-block `<num>-<hash>.witness.zst` files.
    #[arg(long = "witness-emit-dir", env = "WITNESS_EMIT_DIR")]
    pub emit_dir: PathBuf,
    /// Optional JSONL stats file (one line per emitted block). Defaults to no
    /// file — stats still go to stdout via `tracing::info!`.
    #[arg(long = "witness-stats", env = "WITNESS_STATS")]
    pub stats: Option<PathBuf>,
}

fn main() -> eyre::Result<()> {
    Cli::<EthereumChainSpecParser, WitnessEmitArgs>::parse().run(
        async move |builder, args: WitnessEmitArgs| {
            let emit_dir = args.emit_dir.clone();
            let stats = args.stats.clone();
            // `launch_with_debug_capabilities` is identical to `.launch()` for
            // mainnet/holesky/sepolia, but ALSO wires the local miner for
            // `--dev` mode (auto-mining + LocalPayloadAttributesBuilder).
            // Without it, --dev silently produces no blocks.
            let handle = builder
                .node(EthereumNode::default())
                .install_exex("witness-emit", async move |ctx| {
                    let exex = exex::WitnessEmitExEx::new(ctx, emit_dir, stats);
                    Ok(exex.run())
                })
                .launch_with_debug_capabilities()
                .await?;

            handle.wait_for_node_exit().await
        },
    )
}
