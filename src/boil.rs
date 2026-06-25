use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context as _;
use reqwest::cookie::Jar;
use serde::Deserialize;

pub struct BoilClient {
    client: reqwest::Client,
    jar: Arc<Jar>,
}

#[derive(Deserialize, Debug)]
pub struct QueryAllResponse {
    pub daily_limit: i64,
    pub daily_used: i64,
    pub results: HashMap<String, HashMap<String, String>>,
    pub zone_items: Vec<ZoneItem>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ZoneItem {
    pub router_id: String,
    pub interface: String,
    pub label: String,
    pub nat_no_change: bool,
    pub status: String,
}

impl QueryAllResponse {
    pub fn get_ip(&self, router_id: &str, interface: &str) -> Option<&str> {
        self.results
            .get(router_id)?
            .get(interface)
            .map(String::as_str)
    }

    pub fn changeable(&self) -> Vec<&ZoneItem> {
        self.zone_items
            .iter()
            .filter(|r| !r.nat_no_change && r.status == "ok")
            .collect()
    }
}

fn cookie_path() -> PathBuf {
    // 与 config.env 放在同一目录
    for dir in ["/etc/boil", "."] {
        let p = PathBuf::from(dir);
        if p.exists() {
            return p.join("session.cookie");
        }
    }
    PathBuf::from("session.cookie")
}

const BOIL_URL: &str = "https://ippanel.boil.network";

/// 判断错误是否为服务器限流（查询过于频密）。
/// 服务器以 HTTP 200 + `{"error": "查詢過於頻密..."}` 形式返回，文案为繁体。
pub fn is_rate_limited(err: &anyhow::Error) -> bool {
    let m = err.to_string();
    m.contains("頻密") || m.contains("频密") || m.contains("too frequent")
}

impl BoilClient {
    pub fn new() -> anyhow::Result<Self> {
        let jar = Arc::new(Jar::default());

        // 尝试加载缓存的 session cookie
        if let Ok(cookie) = std::fs::read_to_string(cookie_path()) {
            let cookie = cookie.trim();
            if !cookie.is_empty() {
                if let Ok(url) = BOIL_URL.parse::<reqwest::Url>() {
                    jar.add_cookie_str(cookie, &url);
                }
            }
        }

        let client = reqwest::Client::builder()
            .cookie_provider(jar.clone())
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self { client, jar })
    }

    /// 确保持有有效 session：用缓存 cookie 发一次 query_all 验证，失败则重新登录
    pub async fn login(&self, account: &str, password: &str) -> anyhow::Result<()> {
        if cookie_path().exists() && self.query_all().await.is_ok() {
            return Ok(());
        }
        let _ = std::fs::remove_file(cookie_path());
        self.do_login(account, password).await
    }

    async fn do_login(&self, account: &str, password: &str) -> anyhow::Result<()> {
        // 不跟随重定向，直接拿 302 响应里的 Set-Cookie
        let one_shot = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;

        let resp = one_shot
            .post(format!("{BOIL_URL}/login"))
            .form(&[("account", account), ("password", password)])
            .send()
            .await
            .context("登录请求失败")?;

        // 提取 session=... 部分（去掉 Path/HttpOnly 等属性）
        let session_cookie = resp
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("session="))
            .and_then(|v| v.split(';').next())
            .map(|v| v.to_string())
            .ok_or_else(|| anyhow::anyhow!("登录失败：未获得 session cookie，请检查账号密码"))?;

        // 注入到当前 client 的 jar 中
        if let Ok(url) = BOIL_URL.parse::<reqwest::Url>() {
            self.jar.add_cookie_str(&session_cookie, &url);
        }

        // 持久化到文件（600 权限）
        let path = cookie_path();
        std::fs::write(&path, &session_cookie).context("无法写入 session.cookie")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        log::debug!("session 已刷新并保存到 {:?}", path);
        Ok(())
    }

    pub async fn query_all(&self) -> anyhow::Result<QueryAllResponse> {
        let body = self.client
            .post(format!("{BOIL_URL}/api/query_all"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .context("query_all 请求失败")?
            .text()
            .await
            .context("query_all 读取响应失败")?;

        // 先检查业务层错误（如限流），避免被误判为解析失败
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(err_msg) = v.get("error").and_then(|e| e.as_str()) {
                anyhow::bail!("{}", err_msg);
            }
        }

        serde_json::from_str::<QueryAllResponse>(&body)
            .with_context(|| format!("query_all 响应解析失败: {}", &body[..body.len().min(200)]))
    }

    /// 自动重登录版 query_all：session 失效时删除旧 cookie 重新登录后重试一次；
    /// 遇到限流错误则等待 6 秒后重试，不删 cookie。
    pub async fn query_all_authed(&self, account: &str, password: &str) -> anyhow::Result<QueryAllResponse> {
        match self.query_all().await {
            Ok(d) => Ok(d),
            Err(e) => {
                if is_rate_limited(&e) {
                    log::warn!("query_all 限流，6 秒后重试: {e}");
                    tokio::time::sleep(Duration::from_secs(6)).await;
                    return self.query_all().await;
                }
                // session 过期或无效，强制重新登录
                let _ = std::fs::remove_file(cookie_path());
                self.do_login(account, password).await?;
                self.query_all().await
            }
        }
    }

    pub async fn reconnect(&self, router_id: &str, interface: &str) -> anyhow::Result<()> {
        let body = self.client
            .post(format!("{BOIL_URL}/api/reconnect"))
            .json(&serde_json::json!({
                "router_id": router_id,
                "interface": interface
            }))
            .send()
            .await
            .context("reconnect 请求失败")?
            .error_for_status()
            .context("reconnect 返回错误状态")?
            .text()
            .await
            .context("reconnect 读取响应失败")?;

        log::debug!("reconnect 响应: {}", &body[..body.len().min(300)]);

        // 检查业务层面的失败（服务器可能返回 HTTP 200 但 body 携带错误信息）
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            if v.get("error").is_some()
                || v.get("success").and_then(|s| s.as_bool()) == Some(false)
            {
                anyhow::bail!("reconnect 被服务器拒绝: {}", &body[..body.len().min(300)]);
            }
        }

        Ok(())
    }
}
