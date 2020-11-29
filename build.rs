fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().build_server(false).compile(
        &[
            "vendor/terraform-plugin-go/tfprotov5/internal/tfplugin5/tfplugin5.proto",
            "vendor/go-plugin/internal/plugin/grpc_controller.proto",
        ],
        &["."],
    )?;
    Ok(())
}
