fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/wirespider.proto").unwrap();
    Ok(())
}