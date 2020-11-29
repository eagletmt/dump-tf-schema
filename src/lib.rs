mod proto {
    tonic::include_proto!("tfplugin5");
    tonic::include_proto!("plugin");
}

// https://github.com/hashicorp/terraform-plugin-sdk/blob/v2.3.0/plugin/serve.go#L19-L24
const MAGIC_COOKIE_KEY: &str = "TF_PLUGIN_MAGIC_COOKIE";
const MAGIC_COOKIE_VALUE: &str = "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2";
const PLUGIN_PROTOCOL_VERSION: &str = "5";

#[derive(Debug, serde::Serialize)]
pub struct ProviderSchema {
    pub resource_schemas: std::collections::HashMap<String, BlockSchema>,
}

#[derive(Debug, serde::Serialize)]
pub struct BlockSchema {
    pub attributes: std::collections::HashMap<String, TerraformType>,
    pub blocks: std::collections::HashMap<String, NestedBlock>,
}

#[derive(Debug, serde::Serialize)]
pub struct NestedBlock {
    pub block: BlockSchema,
    pub min_items: i64,
    pub max_items: i64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum TerraformType {
    String,
    Number,
    Bool,
    List(Box<TerraformType>),
    Set(Box<TerraformType>),
    Tuple(Vec<TerraformType>),
    Map(Box<TerraformType>),
    Object(std::collections::HashMap<String, TerraformType>),
}

impl TerraformType {
    fn from_serialized(serialized: &serde_json::Value) -> Result<Self, anyhow::Error> {
        if let Some(s) = serialized.as_str() {
            match s {
                "string" => Ok(Self::String),
                "number" => Ok(Self::Number),
                "bool" => Ok(Self::Bool),
                _ => Err(anyhow::anyhow!(
                    "Unknown primitive type {}: expected string, number or bool",
                    s
                )),
            }
        } else if let Some(v) = serialized.as_array() {
            let container = v[0].as_str().unwrap();
            let element = &v[1];
            match container {
                "list" => Ok(Self::List(Box::new(Self::from_serialized(element)?))),
                "set" => Ok(Self::Set(Box::new(Self::from_serialized(element)?))),
                "tuple" => {
                    let ary = element.as_array().unwrap();
                    let mut elems = Vec::with_capacity(ary.len());
                    for e in ary {
                        elems.push(Self::from_serialized(e)?);
                    }
                    Ok(Self::Tuple(elems))
                }
                "map" => Ok(Self::Map(Box::new(Self::from_serialized(element)?))),
                "object" => {
                    let m = element.as_object().unwrap();
                    let mut o = std::collections::HashMap::with_capacity(m.len());
                    for (k, v) in m.iter() {
                        o.insert(k.to_owned(), Self::from_serialized(v)?);
                    }
                    Ok(Self::Object(o))
                }
                _ => Err(anyhow::anyhow!(
                    "Unknown container type {}: expected list, set, tuple, map or object",
                    container
                )),
            }
        } else {
            Err(anyhow::anyhow!("Unexpected JSON value: {}", serialized))
        }
    }
}

impl std::fmt::Display for TerraformType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Self::String => write!(f, "string"),
            Self::Number => write!(f, "number"),
            Self::Bool => write!(f, "bool"),
            Self::List(e) => write!(f, "list({})", e),
            Self::Set(e) => write!(f, "set({})", e),
            Self::Tuple(es) => {
                write!(f, "tuple(")?;
                let mut first = true;
                for e in es {
                    if !first {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", e)?;
                    first = false;
                }
                write!(f, ")")
            }
            Self::Map(e) => write!(f, "map({})", e),
            Self::Object(o) => {
                write!(f, "object({{")?;
                let mut first = true;
                for (k, v) in o.iter() {
                    if !first {
                        write!(f, ", ")?;
                    }
                    write!(f, " {} = {}", k, v)?;
                    first = false;
                }
                write!(f, " }})")
            }
        }
    }
}

pub async fn get_provider_schema<P>(plugin_path: P) -> Result<ProviderSchema, anyhow::Error>
where
    P: AsRef<std::ffi::OsStr>,
{
    let mut child = tokio::process::Command::new(plugin_path)
        .env(MAGIC_COOKIE_KEY, MAGIC_COOKIE_VALUE)
        .env("PLUGIN_PROTOCOL_VERSIONS", PLUGIN_PROTOCOL_VERSION)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let mut reader = tokio::io::BufReader::new(child.stdout.unwrap());
    let mut buf = String::new();
    use tokio::io::AsyncBufReadExt as _;
    reader.read_line(&mut buf).await?;
    child.stdout = Some(reader.into_inner());
    let parts: Vec<_> = buf.trim_end().split('|').collect();

    let core_protocol_version = parts[0];
    if core_protocol_version != "1" {
        return Err(anyhow::anyhow!(
            "Unknown core protocol version: {}",
            core_protocol_version
        ));
    }
    let app_protocol_version = parts[1];
    if app_protocol_version != PLUGIN_PROTOCOL_VERSION {
        return Err(anyhow::anyhow!(
            "Unsupported app protocol version: {}",
            app_protocol_version
        ));
    }
    let network_type = parts[2];
    if network_type != "unix" {
        return Err(anyhow::anyhow!(
            "Unsupported network type: {}",
            network_type
        ));
    }
    let network_addr = parts[3].to_owned();
    let protocol = parts[4];
    if protocol != "grpc" {
        return Err(anyhow::anyhow!("Unsupported protocol: {}", protocol));
    }

    let channel = tonic::transport::Channel::from_static("http://[::]:50051")
        .connect_with_connector(tower::service_fn(move |_| {
            let path = network_addr.clone();
            tokio::net::UnixStream::connect(path)
        }))
        .await?;
    let mut provider_client = crate::proto::provider_client::ProviderClient::new(channel.clone());
    let resp = provider_client
        .get_schema(crate::proto::get_provider_schema::Request {})
        .await?
        .into_inner();

    let mut controller_client =
        crate::proto::grpc_controller_client::GrpcControllerClient::new(channel);
    let _ = controller_client.shutdown(crate::proto::Empty {}).await;
    child.await?;

    let mut resource_schemas = std::collections::HashMap::new();
    for (resource_name, schema) in resp.resource_schemas {
        if let Some(block) = schema.block {
            resource_schemas.insert(resource_name, build_block_schema(&block)?);
        }
    }

    Ok(ProviderSchema { resource_schemas })
}

fn build_block_schema(block: &crate::proto::schema::Block) -> Result<BlockSchema, anyhow::Error> {
    let mut attributes = std::collections::HashMap::new();
    for attr in &block.attributes {
        attributes.insert(
            attr.name.to_owned(),
            TerraformType::from_serialized(&serde_json::from_slice(&attr.r#type)?)?,
        );
    }
    let mut blocks = std::collections::HashMap::new();
    for nested_block in &block.block_types {
        if let Some(b) = &nested_block.block {
            blocks.insert(
                nested_block.type_name.to_owned(),
                NestedBlock {
                    block: build_block_schema(b)?,
                    min_items: nested_block.min_items,
                    max_items: nested_block.max_items,
                },
            );
        }
    }
    Ok(BlockSchema { attributes, blocks })
}

const REGISTRY_URL: &str = "https://registry.terraform.io";

#[derive(Debug, serde::Deserialize)]
struct DiscoveryResponse {
    #[serde(rename = "providers.v1")]
    providers_v1: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProviderVersionsResponse {
    versions: Vec<ProviderVersion>,
}

#[derive(Debug, serde::Deserialize)]
struct ProviderVersion {
    version: String,
    protocols: Vec<String>,
    platforms: Vec<ProviderPlatform>,
}

#[derive(Debug, serde::Deserialize)]
struct ProviderPlatform {
    os: String,
    arch: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProviderPackageResponse {
    download_url: String,
    shasum: String,
}

pub async fn discover_provider(
    namespace: &str,
    type_: &str,
) -> Result<tempfile::TempPath, anyhow::Error> {
    let client = reqwest::Client::new();
    let discovery_response: DiscoveryResponse = client
        .get(&format!("{}/.well-known/terraform.json", REGISTRY_URL))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let versions_response: ProviderVersionsResponse = client
        .get(&format!(
            "{}{}/{}/{}/versions",
            REGISTRY_URL, discovery_response.providers_v1, namespace, type_
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let version = &versions_response.versions.last().unwrap().version;

    let os = match std::env::consts::OS {
        "macos" => "darwin",
        os => os,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        arch => arch,
    };
    let package_response: ProviderPackageResponse = client
        .get(&format!(
            "{}{}/{}/{}/{}/download/{}/{}",
            REGISTRY_URL, discovery_response.providers_v1, namespace, type_, version, os, arch
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut resp = client
        .get(&package_response.download_url)
        .send()
        .await?
        .error_for_status()?;
    let zip_file = tempfile::Builder::new()
        .prefix("dump-tf-schema-")
        .suffix(".zip")
        .tempfile()?;
    log::info!(
        "Downloading {} to {}",
        package_response.download_url,
        zip_file.path().display()
    );
    let mut writer = std::io::BufWriter::new(zip_file);
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    while let Some(chunk) = resp.chunk().await? {
        use std::io::Write as _;
        hasher.update(&chunk);
        writer.write_all(&chunk)?;
    }
    let hexdigest = format!("{:x}", hasher.finalize());
    if hexdigest != package_response.shasum {
        return Err(anyhow::anyhow!(
            "shasum mismatch: got={} expected={}",
            hexdigest,
            package_response.shasum
        ));
    }
    let zip_file = writer.into_inner()?;
    let mut zip_archive = zip::ZipArchive::new(zip_file)?;
    let mut file_names = Vec::new();
    for name in zip_archive.file_names() {
        file_names.push(name.to_owned());
    }
    let prefix = format!("terraform-provider-{}", type_);
    let file_name = file_names.iter().find(|name| name.starts_with(&prefix));
    if file_name.is_none() {
        return Err(anyhow::anyhow!(
            "No plugin binary in zip archive: {:?}",
            file_names
        ));
    }
    let mut file = zip_archive.by_name(file_name.unwrap())?;
    let mut plugin_file = tempfile::Builder::new()
        .prefix("dump-tf-schema-")
        .tempfile()?;
    log::info!(
        "Unarchiving {} to {}",
        file.name(),
        plugin_file.path().display()
    );
    std::io::copy(&mut file, &mut plugin_file)?;
    use std::os::unix::fs::PermissionsExt as _;
    let path = plugin_file.into_temp_path();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o744))?;
    Ok(path)
}
