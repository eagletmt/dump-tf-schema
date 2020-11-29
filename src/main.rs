#[derive(structopt::StructOpt)]
struct Opt {
    #[structopt(short, long)]
    namespace: String,
    #[structopt(short, long)]
    type_: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    use structopt::StructOpt as _;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let opt = Opt::from_args();

    let temp_path = dump_tf_schema::discover_provider(&opt.namespace, &opt.type_).await?;
    let provider_schema = dump_tf_schema::get_provider_schema(&temp_path).await?;
    println!("{}", serde_json::to_string_pretty(&provider_schema)?);
    Ok(())
}
