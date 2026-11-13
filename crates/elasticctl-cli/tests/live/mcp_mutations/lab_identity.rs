use super::*;

const USER_PREFIX: &str = "elasticctl-live-m13-";
pub(super) struct Lease {
    admin: Transport,
    user: String,
    key_attempted: bool,
    key: Option<String>,
    basic: Transport,
}
fn transport(profile: &Profile) -> TestResult<Transport> {
    cleanup_transport(profile)
}
fn metadata(token: &str) -> Value {
    json!({"marker":LIVE_TAG,"token":token})
}
fn random_hex(bytes: usize) -> TestResult<String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut data = vec![0u8; bytes];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut data))
            .map_err(|_| "contract")?;
        Ok(data.iter().map(|b| format!("{b:02x}")).collect())
    }
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        unsafe extern "system" {
            #[link_name = "BCryptGenRandom"]
            fn bcrypt_gen_random(
                provider: *mut std::ffi::c_void,
                buffer: *mut u8,
                length: u32,
                flags: u32,
            ) -> i32;
        }
        let mut data = vec![0u8; bytes];
        let length = bytes.try_into().map_err(|_| "contract")?;
        // Flag 2 selects the system RNG and needs a null provider: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
        require(
            unsafe { bcrypt_gen_random(std::ptr::null_mut(), data.as_mut_ptr(), length, 2) } == 0,
        )?;
        Ok(data.iter().map(|b| format!("{b:02x}")).collect())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = bytes;
        Err("contract".into())
    }
}
async fn verify_user(admin: &Transport, user: &str) -> TestResult {
    let v = safe(
        admin
            .get_absolute_es(&format!("/_security/user/{user}"))
            .await,
    )?;
    require(
        v.as_object().is_some_and(|m| m.len() == 1)
            && v[user]["username"] == user
            && v[user]["metadata"] == metadata(user)
            && v[user]["roles"] == json!(["superuser"])
            && v[user]["enabled"] == true,
    )
}
async fn key_info(lease: &Lease, id: &str) -> TestResult<Value> {
    let v = safe(
        lease
            .admin
            .get_absolute_es(&format!("/_security/api_key?id={id}"))
            .await,
    )?;
    let keys = v["api_keys"].as_array().ok_or("contract")?;
    require(keys.len() == 1)?;
    let key = &keys[0];
    require(
        key["id"] == id
            && key["name"] == lease.user
            && key["username"] == lease.user
            && key["metadata"] == metadata(&lease.user)
            && key["invalidated"].is_boolean(),
    )?;
    Ok(key.clone())
}
pub(super) async fn provision(
    profile: &Profile,
    opt_in: bool,
    registry: &mut Registry,
) -> TestResult<(Transport, String)> {
    require(measure::lab::lab_target(opt_in, profile) && registry.lab.is_none())?;
    measure::lab::fingerprint(profile, opt_in).await?;
    let admin = transport(profile)?;
    let owner = safe(elasticctl_api::health::credential_identity(&admin).await)?;
    require(owner.username == "elastic" && owner.api_key_id.is_none())?;
    let user = format!("{USER_PREFIX}{}", random_hex(16)?);
    match admin
        .get_absolute_es(&format!("/_security/user/{user}"))
        .await
    {
        Err(e) if e.http_status == Some(404) => {}
        _ => return Err("contract".into()),
    }
    check_cancelled()?;
    let mut basic_profile = profile.clone();
    basic_profile.username = Some(user.clone());
    basic_profile.password = Some(random_hex(32)?);
    let basic = transport(&basic_profile)?;
    registry.lab = Some(Lease {
        admin,
        user: user.clone(),
        key_attempted: false,
        key: None,
        basic: transport(&basic_profile)?,
    });
    let lease = registry.lab.as_mut().ok_or("contract")?;
    let created = safe(lease.admin.put_absolute_es_once(&format!("/_security/user/{user}"),
        &json!({"password":basic_profile.password,"roles":["superuser"],"enabled":true,"metadata":metadata(&user)})).await)?;
    require(created["created"] == true)?;
    verify_user(&lease.admin, &user).await?;
    let identity = safe(elasticctl_api::health::credential_identity(&basic).await)?;
    require(identity.username == user && identity.api_key_id.is_none())?;
    check_cancelled()?;
    let lease = registry.lab.as_mut().ok_or("contract")?;
    lease.key_attempted = true;
    let key = safe(
        basic
            .post_absolute_es_once(
                "/_security/api_key",
                Some(&json!({"name":user,"expiration":"15m","metadata":metadata(&user)})),
            )
            .await,
    )?;
    drop(basic);
    basic_profile.password.take();
    let id = key["id"]
        .as_str()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .ok_or("contract")?;
    lease.key = Some(id.into());
    require(key_info(lease, id).await?["invalidated"] == false)?;
    basic_profile.api_key = Some(key["encoded"].as_str().ok_or("contract")?.into());
    basic_profile.username = None;
    let other = transport(&basic_profile)?;
    let identity = safe(elasticctl_api::health::credential_identity(&other).await)?;
    require(identity.username == user && identity.api_key_id.as_deref() == Some(id))?;
    Ok((other, user))
}
async fn recover_user(lease: &Lease) -> TestResult {
    for _ in 0..3 {
        if verify_user(&lease.admin, &lease.user).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("cleanup_failed".into())
}
async fn recover_keys(lease: &Lease) -> TestResult<Vec<Value>> {
    for _ in 0..3 {
        if let Ok(v) = lease
            .basic
            .get_absolute_es(&format!(
                "/_security/api_key?name={}&owner=true",
                lease.user
            ))
            .await
            && let Some(keys) = v["api_keys"].as_array()
        {
            require(keys.iter().all(|k| {
                k["name"] == lease.user
                    && k["username"] == lease.user
                    && k["metadata"] == metadata(&lease.user)
                    && k["invalidated"].is_boolean()
            }))?;
            return Ok(keys.clone());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("cleanup_failed".into())
}
pub(super) async fn clean(lease: &Lease) -> TestResult {
    if lease.key_attempted {
        let before = recover_keys(lease).await?;
        if before.iter().any(|k| k["invalidated"] == false) {
            let v = safe(
                lease
                    .basic
                    .delete_absolute_es_json(
                        "/_security/api_key",
                        &json!({"name":lease.user,"owner":true}),
                    )
                    .await,
            )?;
            require(v["error_count"] == 0)?;
            require(
                recover_keys(lease)
                    .await?
                    .iter()
                    .all(|k| k["invalidated"] == true),
            )?;
        }
    }
    recover_user(lease).await?;
    let v = safe(
        lease
            .admin
            .delete_absolute_es_once(&format!("/_security/user/{}", lease.user))
            .await,
    )?;
    require(v["found"] == true)
}
pub(super) async fn baseline(t: &Transport, profile: &Profile, opt_in: bool) -> TestResult {
    if !measure::lab::lab_target(opt_in, profile) {
        return Ok(());
    }
    let users = safe(t.get_absolute_es("/_security/user").await)?;
    require(
        !users
            .as_object()
            .ok_or("baseline_failed")?
            .keys()
            .any(|u| u.starts_with(USER_PREFIX)),
    )?;
    let keys = safe(
        t.get_absolute_es(&format!("/_security/api_key?name={USER_PREFIX}*"))
            .await,
    )?;
    require(
        keys["api_keys"]
            .as_array()
            .ok_or("baseline_failed")?
            .iter()
            .all(|k| k["invalidated"] == true),
    )
}
