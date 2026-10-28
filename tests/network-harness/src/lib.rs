//! Network test harness (manual §31): runs the real `engine-bench` sender and
//! receiver in two network namespaces joined by a veth pair, with `tc netem`
//! loss/latency/reorder/duplication/rate profiles on the link, and checks that
//! every transfer completes with a matching BLAKE3 and a sane report.

pub mod proc;
pub mod profile;
pub mod report;
pub mod results;
pub mod runner;
pub mod topology;
