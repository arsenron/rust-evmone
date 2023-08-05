use std::env;
use std::path::PathBuf;

fn main() {
    let out_path = if let Ok(p) = env::var("LINK_PATH") {
        PathBuf::from(p)
    } else {
        PathBuf::from(env::var("OUT_DIR").unwrap())
    };
    let binding_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    std::fs::create_dir_all(out_path.join("evmone")).unwrap();

    let dst = cmake::Config::new("evmone")
        .profile("Release")
        .always_configure(true)
        .out_dir(out_path.join("evmone"))
        .build_target("evmone")
        .build();

    println!("cargo:rustc-link-search={}/build/lib", dst.display());
    println!("cargo:rustc-link-lib=evmone");

    let bindings = bindgen::Builder::default()
        .header("evmone.h")
        .clang_arg("-Ievmone/include")
        .clang_arg("-Ievmone/evmc/include")
        .blocklist_type(".*")
        .allowlist_function("evmc_create_evmone")
        .raw_line("use evmc_sys::evmc_vm;")
        .generate()
        .unwrap();

    bindings
        .write_to_file(binding_path.join("bindings.rs"))
        .unwrap();
}
