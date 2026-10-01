fn main() {
    let root = std::env::args().nth(1).unwrap();
    let out = std::env::args().nth(2).unwrap();
    for (name, server) in [("link", false), ("local", true)] {
        let dir = format!("{out}/{name}");
        std::fs::create_dir_all(&dir).unwrap();
        tonic_prost_build::configure()
            .build_server(server)
            .build_client(true)
            .build_transport(false)
            .out_dir(&dir)
            .compile_protos(&[format!("{root}/spec/proto/moochy/v1/{name}.proto")], &[format!("{root}/spec/proto")])
            .unwrap();
    }
}
