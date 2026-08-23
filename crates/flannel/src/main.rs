//! flannel CNI plugin binary (drop-in for the flannel-io/cni-plugin `flannel`
//! meta-plugin). Speaks the CNI exec protocol; all logic in `flannel-cni`.

fn main() {
    std::process::exit(flannel_cni::skel::run());
}
