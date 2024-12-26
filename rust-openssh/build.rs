fn main() {
    // 告诉 Rust 编译器链接 `libaudit` 库
    println!("cargo:rustc-link-lib=audit");
}
