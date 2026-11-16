// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Namespace-scoped Helm hook for NICo's environment/default configuration mode.
//! The mounted-TOML integration remains in scripts/integrate_external_nico.py.

use std::error::Error;
use std::time::{Duration, Instant};

use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const ENABLED: &str = "CARBIDE_HEALTH__SINKS__OTLP__ENABLED";
const TARGETS: &str = "CARBIDE_HEALTH__SINKS__OTLP__TARGETS";
const LABEL: &str = "fleet-intelligence.nvidia.com/otel-source";
const STATE: &str = "state.json";
const SERVICE_ACCOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

#[derive(Debug, clap::Args)]
pub struct Arguments {
    #[arg(long)]
    config: String,
    #[arg(long)]
    restore: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    namespace: String,
    deployment: String,
    container: String,
    expected_image: String,
    endpoint: String,
    release: String,
    backup_secret: String,
    enabled: bool,
    timeout_seconds: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Backup {
    deployment_uid: String,
    container: String,
    release: String,
    original_env: Vec<Value>,
    original_label: Option<Value>,
    applied_env: Vec<Value>,
    #[serde(default)]
    previous_applied_env: Option<Vec<Value>>,
    active: bool,
}

fn error(message: &str) -> Box<dyn Error> {
    std::io::Error::other(message).into()
}

fn validate_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 253
        || !value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-.".contains(&c))
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
    {
        return Err(error(
            "invalid Kubernetes resource name in integration configuration",
        ));
    }
    Ok(())
}

impl Config {
    fn validate(&self) -> Result<()> {
        for name in [
            &self.namespace,
            &self.deployment,
            &self.container,
            &self.backup_secret,
            &self.release,
        ] {
            validate_name(name)?;
        }
        if self.release.len() > 63
            || self.expected_image.is_empty()
            || !(1..=600).contains(&self.timeout_seconds)
        {
            return Err(error(
                "invalid image, release label, or timeout in integration configuration",
            ));
        }
        // Existing backend URL validation rejects credentials, queries and fragments.
        backend_client::BackendUrl::parse(&self.endpoint)
            .map_err(|_| error("invalid FI OTLP endpoint"))?;
        Ok(())
    }

    fn deployment_path(&self) -> String {
        format!(
            "/apis/apps/v1/namespaces/{}/deployments/{}",
            self.namespace, self.deployment
        )
    }

    fn backup_path(&self) -> String {
        format!(
            "/api/v1/namespaces/{}/secrets/{}",
            self.namespace, self.backup_secret
        )
    }
}

struct Api {
    client: reqwest::Client,
    origin: String,
    token: String,
}

impl Api {
    fn in_cluster() -> Result<Self> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")?;
        let host = match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
            Ok(ip) => ip.to_string(),
            Err(_) => return Err(error("Kubernetes service host must be an IP address")),
        };
        let port: u16 = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
            .unwrap_or_else(|_| "443".into())
            .parse()?;
        let ca = std::fs::read(format!("{SERVICE_ACCOUNT}/ca.crt"))?;
        let token = std::fs::read_to_string(format!("{SERVICE_ACCOUNT}/token"))?
            .trim()
            .to_owned();
        let client = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
            .build()?;
        Ok(Self {
            client,
            origin: format!("https://{host}:{port}"),
            token,
        })
    }

    async fn request(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.origin))
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/merge-patch+json")
                .json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| error("Kubernetes API request failed"))?;
        let status = response.status();
        if !status.is_success() {
            // API error bodies can contain object contents, so never export them.
            return Err(error(if status == StatusCode::CONFLICT {
                "Kubernetes resource changed concurrently; retry the Helm operation"
            } else {
                "Kubernetes API rejected the integration request; check namespace RBAC and resource names"
            }));
        }
        response
            .json()
            .await
            .map_err(|_| error("invalid Kubernetes API response"))
    }
}

fn selected_container<'a>(deployment: &'a Value, name: &str) -> Result<&'a Value> {
    let containers = deployment
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array)
        .ok_or_else(|| error("NICo Deployment has no containers"))?;
    let matches: Vec<_> = containers.iter().filter(|c| c["name"] == name).collect();
    if matches.len() != 1 {
        return Err(error("expected exactly one selected NICo container"));
    }
    Ok(matches[0])
}

fn managed_env(container: &Value) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    if let Some(env) = container.get("env") {
        for variable in env
            .as_array()
            .ok_or_else(|| error("NICo env is not an array"))?
        {
            if [ENABLED, TARGETS]
                .iter()
                .any(|name| variable["name"] == *name)
            {
                if result
                    .iter()
                    .any(|item: &Value| item["name"] == variable["name"])
                {
                    return Err(error("duplicate NICo OTLP environment variable"));
                }
                if variable.get("valueFrom").is_some() || variable["value"].as_str().is_none() {
                    return Err(error(
                        "OTLP variables using valueFrom require integration through their configuration source",
                    ));
                }
                result.push(variable.clone());
            }
        }
    }
    result.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(result)
}

fn source_is_environment(container: &Value) -> Result<()> {
    if container
        .get("envFrom")
        .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
    {
        return Err(error(
            "envFrom is ambiguous; integrate through the original NICo configuration source",
        ));
    }
    for field in ["command", "args"] {
        if container[field].as_array().is_some_and(|args| {
            args.iter()
                .any(|v| v.as_str().is_some_and(|s| s.contains(".toml")))
        }) {
            return Err(error(
                "mounted TOML requires the documented TOML integration procedure",
            ));
        }
    }
    if container["env"].as_array().is_some_and(|env| {
        env.iter().any(|e| {
            let name = e["name"].as_str().unwrap_or_default();
            name.starts_with("NICO_HEALTH__SINKS")
                || name == "CARBIDE_HEALTH__SINKS"
                || name == "CARBIDE_HEALTH__SINKS__OTLP"
                || name.starts_with("CARBIDE_HEALTH__SINKS__OTLP__TARGETS__")
        })
    }) {
        return Err(error(
            "overlapping NICo OTLP environment settings require explicit source integration",
        ));
    }
    Ok(())
}

fn desired_env(original: &[Value], endpoint: &str) -> Result<Vec<Value>> {
    let current = original
        .iter()
        .find(|v| v["name"] == TARGETS)
        .and_then(|v| v["value"].as_str())
        .unwrap_or("[]");
    let parsed: toml::Table = format!("targets = {current}")
        .parse()
        .map_err(|_| error("existing NICo OTLP target list is not a valid TOML array"))?;
    let mut targets = parsed["targets"]
        .as_array()
        .ok_or_else(|| error("existing NICo OTLP targets must be an array"))?
        .clone();
    if targets.iter().any(|v| {
        v.as_table().is_none() || v.get("endpoint").and_then(toml::Value::as_str).is_none()
    }) {
        return Err(error(
            "each existing OTLP target must be a table with an endpoint",
        ));
    }
    let matches: Vec<_> = targets
        .iter()
        .enumerate()
        .filter(|(_, v)| v["endpoint"].as_str() == Some(endpoint))
        .map(|(i, _)| i)
        .collect();
    if matches.len() > 1 {
        return Err(error(
            "FI OTLP endpoint occurs more than once in the original target list",
        ));
    }
    let target: toml::Table = format!("endpoint = {}\nbatch_size = 512\nflush_interval = \"2s\"\ninclude_diagnostics = true\ninclude_alert_details = true\n", json!(endpoint)).parse()?;
    if let Some(index) = matches.first() {
        targets[*index]
            .as_table_mut()
            .expect("validated table")
            .extend(target);
    } else {
        targets.push(toml::Value::Table(target));
    }
    Ok(vec![
        json!({"name": ENABLED, "value": "true"}),
        json!({"name": TARGETS, "value": toml::Value::Array(targets).to_string()}),
    ])
}

fn current_label(deployment: &Value) -> Option<Value> {
    deployment
        .pointer("/spec/template/metadata/labels")
        .and_then(|v| v.get(LABEL))
        .cloned()
}

fn validate_backup(backup: &Backup, deployment: &Value, config: &Config) -> Result<()> {
    if deployment.pointer("/metadata/uid").and_then(Value::as_str) != Some(&backup.deployment_uid)
        || backup.container != config.container
        || backup.release != config.release
    {
        return Err(error(
            "NICo backup belongs to a different workload or release",
        ));
    }
    Ok(())
}

fn template_patch(
    deployment: &Value,
    config: &Config,
    env: &[Value],
    label: Option<&Value>,
) -> Result<Value> {
    let mut containers = deployment
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array)
        .ok_or_else(|| error("NICo containers are missing"))?
        .clone();
    let container = containers
        .iter_mut()
        .find(|c| c["name"] == config.container)
        .ok_or_else(|| error("NICo container is missing"))?;
    let mut variables = container["env"].as_array().cloned().unwrap_or_default();
    variables.retain(|e| ![ENABLED, TARGETS].iter().any(|name| e["name"] == *name));
    variables.extend_from_slice(env);
    container["env"] = json!(variables);
    let mut labels = serde_json::Map::new();
    labels.insert(LABEL.into(), label.cloned().unwrap_or(Value::Null));
    Ok(
        json!({"metadata": {"resourceVersion": deployment["metadata"]["resourceVersion"]}, "spec": {"template": {"metadata": {"labels": labels}, "spec": {"containers": containers}}}}),
    )
}

async fn save_backup(api: &Api, config: &Config, secret: &Value, backup: &Backup) -> Result<()> {
    // stringData keeps encoding in the Kubernetes API and avoids secret output.
    let body = json!({"metadata": {"resourceVersion": secret["metadata"]["resourceVersion"]}, "stringData": {"state.json": serde_json::to_string(backup)?}});
    api.request(Method::PATCH, &config.backup_path(), Some(&body))
        .await?;
    Ok(())
}

async fn load_backup(api: &Api, config: &Config) -> Result<(Value, Option<Backup>)> {
    let secret = api
        .request(Method::GET, &config.backup_path(), None)
        .await?;
    // Secret stringData is write-only. The API's protobuf-free JSON data uses base64.
    let value = secret["data"][STATE].as_str().unwrap_or_default();
    let backup = if value.is_empty() {
        None
    } else {
        let bytes = decode_base64(value)?;
        Some(serde_json::from_slice(&bytes).map_err(|_| error("invalid NICo integration backup"))?)
    };
    Ok((secret, backup))
}

fn decode_base64(input: &str) -> Result<Vec<u8>> {
    // The workspace already uses this implementation for Redfish transport.
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|_| error("invalid base64 in NICo backup Secret"))
}

async fn wait_for_rollout(api: &Api, config: &Config) -> Result<()> {
    let started = Instant::now();
    loop {
        let d = api
            .request(Method::GET, &config.deployment_path(), None)
            .await?;
        let desired = d["spec"]["replicas"].as_u64().unwrap_or(1);
        if d["status"]["observedGeneration"].as_u64().unwrap_or(0)
            >= d["metadata"]["generation"].as_u64().unwrap_or(1)
            && d["status"]["updatedReplicas"].as_u64().unwrap_or(0) == desired
            && d["status"]["availableReplicas"].as_u64().unwrap_or(0) == desired
            && d["status"]["replicas"].as_u64().unwrap_or(0) == desired
        {
            return Ok(());
        }
        if started.elapsed().as_secs() >= config.timeout_seconds {
            return Err(error("NICo rollout timed out"));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn restore(
    api: &Api,
    config: &Config,
    deployment: &Value,
    secret: &Value,
    backup: &mut Backup,
) -> Result<()> {
    let current = managed_env(selected_container(deployment, &config.container)?)?;
    let label = current_label(deployment);
    if current == backup.original_env && label == backup.original_label {
        backup.active = false;
        save_backup(api, config, secret, backup).await?;
        return Ok(());
    }
    if (current != backup.applied_env && backup.previous_applied_env.as_ref() != Some(&current))
        || label != Some(json!(config.release))
    {
        return Err(error(
            "NICo OTLP settings changed outside FI; refusing to overwrite them during restore",
        ));
    }
    let patch = template_patch(
        deployment,
        config,
        &backup.original_env,
        backup.original_label.as_ref(),
    )?;
    api.request(Method::PATCH, &config.deployment_path(), Some(&patch))
        .await?;
    wait_for_rollout(api, config).await?;
    backup.active = false;
    save_backup(api, config, secret, backup).await?;
    Ok(())
}

pub async fn run(args: Arguments) -> Result<()> {
    let config: Config = serde_json::from_slice(&std::fs::read(args.config)?)?;
    config.validate()?;
    let api = Api::in_cluster()?;
    let deployment = api
        .request(Method::GET, &config.deployment_path(), None)
        .await?;
    let container = selected_container(&deployment, &config.container)?;
    let (secret, previous) = load_backup(&api, &config).await?;
    if let Some(backup) = &previous {
        validate_backup(backup, &deployment, &config)?;
    }
    if args.restore || !config.enabled {
        if let Some(mut backup) = previous.filter(|b| b.active) {
            restore(&api, &config, &deployment, &secret, &mut backup).await?;
        }
        println!("Restored FI-owned NICo OTLP settings");
        return Ok(());
    }
    if container["image"] != config.expected_image {
        return Err(error(
            "NICo image differs from external.expectedImage; existing image was not changed",
        ));
    }
    source_is_environment(container)?;
    let current = managed_env(container)?;
    let label = current_label(&deployment);
    if label.as_ref().is_some_and(|v| v != &json!(config.release)) {
        return Err(error(
            "NICo OTLP source label is owned by another integration",
        ));
    }
    let mut backup = if let Some(backup) = previous.filter(|b| b.active) {
        if !(((current == backup.applied_env
            || backup.previous_applied_env.as_ref() == Some(&current))
            && label == Some(json!(config.release)))
            || (current == backup.original_env && label == backup.original_label))
        {
            return Err(error(
                "NICo OTLP settings changed outside FI; refusing to overwrite them",
            ));
        }
        backup
    } else {
        Backup {
            deployment_uid: deployment["metadata"]["uid"]
                .as_str()
                .ok_or_else(|| error("NICo Deployment UID is missing"))?
                .into(),
            container: config.container.clone(),
            release: config.release.clone(),
            original_env: current.clone(),
            original_label: label.clone(),
            applied_env: Vec::new(),
            previous_applied_env: None,
            active: true,
        }
    };
    backup.previous_applied_env = Some(current.clone());
    backup.applied_env = desired_env(&backup.original_env, &config.endpoint)?;
    // Persist before changing the external workload, including recovery after an interrupted hook.
    save_backup(&api, &config, &secret, &backup).await?;
    if current != backup.applied_env || label != Some(json!(config.release)) {
        let patch = template_patch(
            &deployment,
            &config,
            &backup.applied_env,
            Some(&json!(config.release)),
        )?;
        api.request(Method::PATCH, &config.deployment_path(), Some(&patch))
            .await?;
    }
    if wait_for_rollout(&api, &config).await.is_err() {
        let current = api
            .request(Method::GET, &config.deployment_path(), None)
            .await?;
        let (secret, _) = load_backup(&api, &config).await?;
        restore(&api, &config, &current, &secret, &mut backup).await?;
        return Err(error(
            "NICo rollout failed; original OTLP settings restored",
        ));
    }
    backup.previous_applied_env = None;
    let (secret, _) = load_backup(&api, &config).await?;
    save_backup(&api, &config, &secret, &backup).await?;
    println!(
        "Configured existing NICo OTLP destination; original image and customer settings retained"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            namespace: "example".into(),
            deployment: "nico".into(),
            container: "health".into(),
            expected_image: "nico:v1".into(),
            endpoint: "http://fi-gateway:4317".into(),
            release: "fi".into(),
            backup_secret: "fi-backup".into(),
            enabled: true,
            timeout_seconds: 30,
        }
    }

    #[test]
    fn preserves_customer_targets_and_updates_existing_fi_target() {
        let original = vec![
            json!({"name": TARGETS, "value": "[{endpoint = \"https://customer.example:4317\", batch_size = 123}, {endpoint = \"http://fi-gateway:4317\", queue_capacity = 42}]"}),
        ];
        let desired = desired_env(&original, &config().endpoint).unwrap();
        let parsed: toml::Table = format!("targets = {}", desired[1]["value"].as_str().unwrap())
            .parse()
            .unwrap();
        let targets = parsed["targets"].as_array().unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0]["batch_size"].as_integer(), Some(123));
        assert_eq!(targets[1]["queue_capacity"].as_integer(), Some(42));
        assert_eq!(targets[1]["include_diagnostics"].as_bool(), Some(true));
        assert_eq!(desired_env(&desired, &config().endpoint).unwrap(), desired);
    }

    #[test]
    fn rejects_ambiguous_config_and_duplicate_targets_without_echoing_contents() {
        for container in [
            json!({"envFrom": [{"secretRef": {"name": "private"}}]}),
            json!({"args": ["/etc/nico.toml"]}),
            json!({"env": [{"name": "NICO_HEALTH__SINKS__OTLP__ENABLED", "value": "true"}]}),
        ] {
            assert!(source_is_environment(&container).is_err());
        }
        assert!(managed_env(&json!({"env":[{"name":TARGETS,"valueFrom":{"secretKeyRef":{"name":"private","key":"targets"}}}]})).is_err());
        let duplicates = vec![
            json!({"name": TARGETS, "value": "[{endpoint=\"http://fi-gateway:4317\"},{endpoint=\"http://fi-gateway:4317\"}]"}),
        ];
        assert!(desired_env(&duplicates, &config().endpoint).is_err());
        let invalid = vec![json!({"name":TARGETS,"value":"customer-secret-is-not-valid-toml"})];
        assert!(
            !desired_env(&invalid, &config().endpoint)
                .unwrap_err()
                .to_string()
                .contains("customer-secret")
        );
    }

    #[test]
    fn patch_changes_only_selected_environment_and_source_label() {
        let deployment = json!({"metadata":{"resourceVersion":"7"},"spec":{"template":{"metadata":{"labels":{"customer":"kept"}},"spec":{"containers":[{"name":"health","image":"nico:v1","env":[{"name":"CUSTOMER","value":"kept"}]},{"name":"sidecar","image":"customer:v1"}],"volumes":[{"name":"customer"}]}}}});
        let desired = desired_env(&[], &config().endpoint).unwrap();
        let patch = template_patch(&deployment, &config(), &desired, Some(&json!("fi"))).unwrap();
        assert_eq!(patch["metadata"]["resourceVersion"], "7");
        let containers = &patch["spec"]["template"]["spec"]["containers"];
        assert_eq!(containers[0]["image"], "nico:v1");
        assert_eq!(containers[0]["env"][0]["name"], "CUSTOMER");
        assert_eq!(
            containers[1],
            deployment["spec"]["template"]["spec"]["containers"][1]
        );
        assert!(patch["spec"]["template"]["spec"].get("volumes").is_none());
        let restored = template_patch(&deployment, &config(), &[], None).unwrap();
        assert!(restored["spec"]["template"]["metadata"]["labels"][LABEL].is_null());
    }

    #[test]
    fn validates_api_paths_and_rejects_credentials_in_endpoint() {
        let mut c = config();
        c.validate().unwrap();
        c.deployment = "../other".into();
        assert!(c.validate().is_err());
        c = config();
        c.endpoint = "https://user:private@example.com:4317".into();
        assert_eq!(
            c.validate().unwrap_err().to_string(),
            "invalid FI OTLP endpoint"
        );
    }
}
