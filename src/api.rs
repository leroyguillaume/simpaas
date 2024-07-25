use std::{borrow::Cow, collections::BTreeSet, net::SocketAddr, sync::Arc};

use aide::{
    axum::ApiRouter,
    openapi::{Info, OpenApi},
    OperationOutput,
};
use axum::{
    extract::{MatchedPath, Path, Query, State},
    http::{header, Request, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json, Router,
};
use axum_extra::{
    extract::{cookie::Cookie, CookieJar},
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use kube::api::ObjectMeta;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_trim::{btreeset_string_trim, option_string_trim, string_trim};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, info_span, instrument, Instrument};
use uuid::Uuid;
use validator::{Validate, ValidationError, ValidationErrors};

use crate::{
    domain::{Action, App, AppSpec, Chart, Invitation, InvitationSpec, Service, User, UserSpec},
    jwt::JwtEncoder,
    kube::{AppFilter, KubeClient, FINALIZER},
    pwd::PasswordEncoder,
    CookieArgs, SignalListener, CARGO_PKG_NAME,
};

pub const PATH_JOIN: &str = "/join";

const COOKIE_NAME_JWT: &str = "simpaas-jwt";

pub struct ApiContext<J: JwtEncoder, K: KubeClient, P: PasswordEncoder> {
    pub cookie: CookieArgs,
    pub jwt_encoder: J,
    pub kube: K,
    pub pwd_encoder: P,
}

pub async fn start_api<
    J: JwtEncoder + 'static,
    K: KubeClient + 'static,
    P: PasswordEncoder + 'static,
>(
    addr: SocketAddr,
    root_path: &str,
    ctx: ApiContext<J, K, P>,
) -> anyhow::Result<()> {
    let mut sig = SignalListener::new()?;
    debug!("binding tcp listener");
    let tcp = TcpListener::bind(addr).await?;
    info!("server started");
    axum::serve(tcp, create_router(root_path, ctx))
        .with_graceful_shutdown(async move { sig.recv().await })
        .await?;
    info!("server stopped");
    Ok(())
}

type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("permission denied")]
    Forbidden,
    #[error("{0}")]
    JwtDecoding(#[source] crate::jwt::Error),
    #[error("{0}")]
    JwtEncoding(#[source] crate::jwt::Error),
    #[error("{0}")]
    Kube(
        #[from]
        #[source]
        crate::kube::Error,
    ),
    #[error("{0}")]
    PasswordEncoder(
        #[from]
        #[source]
        crate::pwd::Error,
    ),
    #[error("precondition failed")]
    PreconditionFailed(PreconditionFailedResponse),
    #[error("resource already exists")]
    ResourceAlreadyExists(Vec<ResourceAlreadyExistsItem>),
    #[error("resource not found")]
    ResourceNotFound,
    #[error("unauthroized")]
    Unauthorized,
    #[error("validation of request failed")]
    Validation(
        #[from]
        #[source]
        ValidationErrors,
    ),
    #[error("wrong credentials")]
    WrongCredentials,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Self::Forbidden => StatusCode::FORBIDDEN.into_response(),
            Self::JwtDecoding(_) | Self::Unauthorized | Self::WrongCredentials => {
                StatusCode::UNAUTHORIZED.into_response()
            }
            Self::PreconditionFailed(resp) => {
                (StatusCode::PRECONDITION_FAILED, Json(resp)).into_response()
            }
            Self::ResourceAlreadyExists(resp) => (StatusCode::CONFLICT, Json(resp)).into_response(),
            Self::ResourceNotFound => StatusCode::NOT_FOUND.into_response(),
            Self::Validation(err) => (StatusCode::BAD_REQUEST, Json(err)).into_response(),
            err => {
                error!("{err}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

impl OperationOutput for Error {
    type Inner = ();

    fn inferred_responses(
        _ctx: &mut aide::gen::GenContext,
        _operation: &mut aide::openapi::Operation,
    ) -> Vec<(Option<u16>, aide::openapi::Response)> {
        vec![(
            Some(500),
            aide::openapi::Response {
                description: "An unexpected error occurred".into(),
                ..Default::default()
            },
        )]
    }

    fn operation_response(
        _ctx: &mut aide::gen::GenContext,
        _operation: &mut aide::openapi::Operation,
    ) -> Option<aide::openapi::Response> {
        Some(aide::openapi::Response::default())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
struct AppFilterQuery {
    /// Regex to match app name.
    #[serde(default = "default_filter")]
    name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
struct CreateAppRequest {
    /// Chart to use to install app.
    #[serde(default)]
    chart: Chart,
    /// Name.
    #[serde(deserialize_with = "string_trim")]
    #[validate(length(min = 1))]
    name: String,
    /// Namespace. If not specified, name is used.
    #[serde(default, deserialize_with = "option_string_trim")]
    #[validate(length(min = 1))]
    namespace: Option<String>,
    /// List of app services.
    #[validate(nested)]
    services: Vec<Service>,
    /// Helm chart values.
    #[serde(default)]
    values: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
struct SendInvitationRequest {
    /// User roles.
    #[serde(default, deserialize_with = "btreeset_string_trim")]
    roles: BTreeSet<String>,
    /// Email of user to invite.
    #[serde(deserialize_with = "string_trim")]
    #[validate(email)]
    to: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, JsonSchema, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
struct UpdateAppRequest {
    /// Owner of the app.
    owner: String,
    /// List of app services.
    #[validate(nested)]
    services: Vec<Service>,
    /// Helm chart values.
    #[serde(default)]
    values: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
struct UserPasswordCredentialsRequest {
    /// Password.
    password: String,
    /// Username.
    #[serde(deserialize_with = "string_trim")]
    #[validate(length(min = 1))]
    user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
struct JwtResponse {
    /// JWT.
    jwt: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreconditionFailedResponse {
    /// Field that causes the failure.
    field: String,
    /// The reason of the failure.
    reason: PreconditionFailedReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
enum PreconditionFailedReason {
    NotFound,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceAlreadyExistsItem {
    /// Field in conflict.
    field: String,
    /// Source of conflict.
    source: Option<String>,
    /// Value in conflict.
    value: String,
}

fn create_router<J: JwtEncoder + 'static, K: KubeClient + 'static, P: PasswordEncoder + 'static>(
    root_path: &str,
    ctx: ApiContext<J, K, P>,
) -> Router {
    let trace_layer = TraceLayer::new_for_http().make_span_with(|req: &Request<_>| {
        let path = req
            .extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str)
            .unwrap_or_default();
        let span = info_span!(
            "http_request",
            http.method = %req.method(),
            http.path = path,
        );
        debug!(parent: &span, "http request received");
        span
    });
    let mut api = OpenApi {
        info: Info {
            title: CARGO_PKG_NAME.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let router = ApiRouter::new()
        .api_route("/_health", aide::axum::routing::get(health))
        .api_route("/app", aide::axum::routing::get(list_apps))
        .api_route("/app", aide::axum::routing::post(create_app))
        .api_route("/app/:name", aide::axum::routing::get(get_app))
        .api_route("/app/:name", aide::axum::routing::put(update_app))
        .api_route("/app/:name", aide::axum::routing::delete(delete_app))
        .api_route(
            "/auth",
            aide::axum::routing::post(authenticate_with_password),
        )
        .api_route(
            &format!("{PATH_JOIN}/:token"),
            aide::axum::routing::put(join),
        )
        .api_route("/user/invite", aide::axum::routing::post(create_invitation))
        .route("/_doc", axum::routing::get(doc));
    ApiRouter::new()
        .nest(root_path, router)
        .finish_api(&mut api)
        .with_state(Arc::new(ctx))
        .layer(trace_layer)
        .layer(Extension(api))
}

#[instrument(skip(jar, ctx, req), fields(auth.name = req.user))]
async fn authenticate_with_password<J: JwtEncoder, K: KubeClient, P: PasswordEncoder>(
    jar: CookieJar,
    State(ctx): State<Arc<ApiContext<J, K, P>>>,
    Json(req): Json<UserPasswordCredentialsRequest>,
) -> Result<(StatusCode, CookieJar, Json<JwtResponse>)> {
    debug!("authenticating user with password");
    let user = ctx.kube.get_user(&req.user).await?.ok_or_else(|| {
        debug!("user doesn't exist");
        Error::WrongCredentials
    })?;
    let password = user.spec.password.as_ref().ok_or_else(|| {
        debug!("user doesn't have password");
        Error::WrongCredentials
    })?;
    if ctx.pwd_encoder.verify(&req.password, password)? {
        auth_response(&req.user, jar, &ctx)
    } else {
        Err(Error::WrongCredentials)
    }
}

async fn create_app<J: JwtEncoder, K: KubeClient, P: PasswordEncoder>(
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    State(ctx): State<Arc<ApiContext<J, K, P>>>,
    Json(req): Json<CreateAppRequest>,
) -> Result<(StatusCode, Json<AppSpec>)> {
    let (username, user) =
        authenticated_user(auth_header, &jar, &ctx.jwt_encoder, &ctx.kube).await?;
    let span = info_span!("create_app", app.name = req.name, auth.name = username);
    async {
        check_permission(&user, Action::CreateApp, &ctx.kube).await?;
        req.validate()?;
        ensure_domains_are_free(&req.name, &req.services, &ctx.kube).await?;
        if ctx.kube.get_app(&req.name).await?.is_some() {
            return Err(Error::ResourceAlreadyExists(vec![
                ResourceAlreadyExistsItem {
                    field: "name".into(),
                    source: Some(req.name.clone()),
                    value: req.name,
                },
            ]));
        }
        let namespace = req.namespace.unwrap_or_else(|| req.name.clone());
        let spec = AppSpec {
            chart: req.chart,
            namespace,
            owner: username,
            services: req.services,
            values: req.values,
        };
        let app = App {
            metadata: ObjectMeta {
                finalizers: Some(vec![FINALIZER.into()]),
                name: Some(req.name.clone()),
                ..Default::default()
            },
            spec,
        };
        ctx.kube.patch_app(&req.name, &app).await?;
        info!("app created");
        Ok((StatusCode::CREATED, Json(app.spec)))
    }
    .instrument(span)
    .await
}

async fn create_invitation<J: JwtEncoder, K: KubeClient, P: PasswordEncoder>(
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    State(ctx): State<Arc<ApiContext<J, K, P>>>,
    Json(req): Json<SendInvitationRequest>,
) -> Result<(StatusCode, Json<InvitationSpec>)> {
    let (username, user) =
        authenticated_user(auth_header, &jar, &ctx.jwt_encoder, &ctx.kube).await?;
    let token = Uuid::new_v4().to_string();
    let span = info_span!(
        "create_invitation",
        auth.name = username,
        invit.to = req.to,
        invit.token = token,
    );
    async {
        check_permission(&user, Action::InviteUsers, &ctx.kube).await?;
        req.validate()?;
        let spec = InvitationSpec {
            from: username,
            roles: req.roles,
            to: req.to,
        };
        let invit = Invitation {
            metadata: ObjectMeta {
                name: Some(token.clone()),
                ..Default::default()
            },
            spec,
        };
        ctx.kube.patch_invitation(&token, &invit).await?;
        info!("invitation created");
        Ok((StatusCode::CREATED, Json(invit.spec)))
    }
    .instrument(span)
    .await
}

async fn delete_app<J: JwtEncoder, K: KubeClient, P: PasswordEncoder>(
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    State(ctx): State<Arc<ApiContext<J, K, P>>>,
    Path(name): Path<String>,
) -> Result<StatusCode> {
    let (username, user) =
        authenticated_user(auth_header, &jar, &ctx.jwt_encoder, &ctx.kube).await?;
    let span = info_span!("delete_app", app.name = name, auth.name = username);
    async {
        let app = ctx
            .kube
            .get_app(&name)
            .await?
            .ok_or(Error::ResourceNotFound)?;
        if app.spec.owner != username {
            check_permission(&user, Action::DeleteApp(&name), &ctx.kube).await?;
        }
        ctx.kube.delete_app(&name).await?;
        info!("app deleted");
        Ok(StatusCode::NO_CONTENT)
    }
    .instrument(span)
    .await
}

#[instrument(skip(api))]
async fn doc(Extension(api): Extension<OpenApi>) -> Json<OpenApi> {
    Json(api)
}

async fn get_app<J: JwtEncoder, K: KubeClient, P: PasswordEncoder>(
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    State(ctx): State<Arc<ApiContext<J, K, P>>>,
    Path(name): Path<String>,
) -> Result<(StatusCode, Json<AppSpec>)> {
    let (username, user) =
        authenticated_user(auth_header, &jar, &ctx.jwt_encoder, &ctx.kube).await?;
    let span = info_span!("get_app", app.name = name, auth.name = username);
    async {
        let app = ctx
            .kube
            .get_app(&name)
            .await?
            .ok_or(Error::ResourceNotFound)?;
        if app.spec.owner != username {
            check_permission(&user, Action::ReadApp(&name), &ctx.kube).await?;
        }
        Ok((StatusCode::OK, Json(app.spec)))
    }
    .instrument(span)
    .await
}

#[instrument]
async fn health<J: JwtEncoder, K: KubeClient, P: PasswordEncoder>(
    _: State<Arc<ApiContext<J, K, P>>>,
) -> StatusCode {
    StatusCode::NO_CONTENT
}

#[instrument(skip(jar, ctx, token, req), fields(invit.token = token))]
async fn join<J: JwtEncoder, K: KubeClient, P: PasswordEncoder>(
    jar: CookieJar,
    State(ctx): State<Arc<ApiContext<J, K, P>>>,
    Path(token): Path<String>,
    Json(req): Json<UserPasswordCredentialsRequest>,
) -> Result<(StatusCode, CookieJar, Json<JwtResponse>)> {
    req.validate()?;
    if ctx.kube.get_user(&req.user).await?.is_some() {
        let resp = ResourceAlreadyExistsItem {
            field: "name".into(),
            source: Some(req.user.clone()),
            value: req.user,
        };
        return Err(Error::ResourceAlreadyExists(vec![resp]));
    }
    let invit = ctx
        .kube
        .get_invitation(&token)
        .await?
        .ok_or(Error::ResourceNotFound)?;
    let pwd = ctx.pwd_encoder.encode(&req.password)?;
    let user = User {
        metadata: ObjectMeta {
            name: Some(req.user.clone()),
            ..Default::default()
        },
        spec: UserSpec {
            email: Some(invit.spec.to),
            password: Some(pwd),
            roles: invit.spec.roles,
        },
    };
    ctx.kube.patch_user(&req.user, &user).await?;
    info!(user.name = req.user, "user created");
    ctx.kube.delete_invitation(&token).await?;
    auth_response(&req.user, jar, &ctx)
}

async fn list_apps<J: JwtEncoder, K: KubeClient, P: PasswordEncoder>(
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    State(ctx): State<Arc<ApiContext<J, K, P>>>,
    Query(filter): Query<AppFilterQuery>,
) -> Result<(StatusCode, Json<Vec<AppSpec>>)> {
    let (username, user) =
        authenticated_user(auth_header, &jar, &ctx.jwt_encoder, &ctx.kube).await?;
    let span = info_span!("list_apps", auth.name = username);
    async {
        let filter = filter.try_into()?;
        let apps = ctx
            .kube
            .list_apps(&filter, &username, &user)
            .await?
            .into_iter()
            .map(|app| app.spec)
            .collect();
        Ok((StatusCode::OK, Json(apps)))
    }
    .instrument(span)
    .await
}

async fn update_app<J: JwtEncoder, K: KubeClient, P: PasswordEncoder>(
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: CookieJar,
    Path(name): Path<String>,
    State(ctx): State<Arc<ApiContext<J, K, P>>>,
    Json(req): Json<UpdateAppRequest>,
) -> Result<(StatusCode, Json<AppSpec>)> {
    let (username, user) =
        authenticated_user(auth_header, &jar, &ctx.jwt_encoder, &ctx.kube).await?;
    let span = info_span!("update_app", app.name = name, auth.name = username);
    async {
        let app = ctx
            .kube
            .get_app(&name)
            .await?
            .ok_or(Error::ResourceNotFound)?;
        if app.spec.owner != username {
            check_permission(&user, Action::UpdateApp(&name), &ctx.kube).await?;
        }
        req.validate()?;
        ensure_domains_are_free(&name, &req.services, &ctx.kube).await?;
        if ctx.kube.get_user(&req.owner).await?.is_none() {
            return Err(Error::PreconditionFailed(PreconditionFailedResponse {
                field: "owner".into(),
                reason: PreconditionFailedReason::NotFound,
            }));
        }
        let app = App {
            metadata: ObjectMeta {
                managed_fields: None,
                ..app.metadata
            },
            spec: AppSpec {
                owner: req.owner,
                services: req.services,
                values: req.values,
                ..app.spec
            },
        };
        ctx.kube.patch_app(&name, &app).await?;
        info!("app updated");
        Ok((StatusCode::OK, Json(app.spec)))
    }
    .instrument(span)
    .await
}

#[instrument(skip(auth_header, jar, encoder, kube))]
async fn authenticated_user<J: JwtEncoder, K: KubeClient>(
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    jar: &CookieJar,
    encoder: &J,
    kube: &K,
) -> Result<(String, User)> {
    let jwt = auth_header
        .as_ref()
        .map(|header| header.0.token())
        .or_else(|| {
            debug!(
                "request doesn't contain header `{}`, trying cookie",
                header::AUTHORIZATION
            );
            jar.get(COOKIE_NAME_JWT).map(|cookie| cookie.value())
        })
        .ok_or_else(|| {
            debug!("no cookie {COOKIE_NAME_JWT}");
            Error::Unauthorized
        })?;
    let name = encoder.decode(jwt).map_err(Error::JwtDecoding)?;
    let user = kube.get_user(&name).await?.ok_or_else(|| {
        debug!("user doesn't exist");
        Error::Unauthorized
    })?;
    Ok((name, user))
}

async fn check_permission<K: KubeClient>(user: &User, action: Action<'_>, kube: &K) -> Result {
    if kube.user_has_permission(user, action).await? {
        Ok(())
    } else {
        debug!("user doesn't have required permission");
        Err(Error::Forbidden)
    }
}

async fn ensure_domains_are_free<K: KubeClient>(name: &str, svcs: &[Service], kube: &K) -> Result {
    let usages = kube.domain_usages(name, svcs).await?;
    if usages.is_empty() {
        Ok(())
    } else {
        let items = usages
            .into_iter()
            .map(|usage| ResourceAlreadyExistsItem {
                field: "domain".into(),
                source: usage.app,
                value: usage.domain,
            })
            .collect();
        Err(Error::ResourceAlreadyExists(items))
    }
}

fn auth_response<J: JwtEncoder, K: KubeClient, P: PasswordEncoder>(
    username: &str,
    jar: CookieJar,
    ctx: &ApiContext<J, K, P>,
) -> Result<(StatusCode, CookieJar, Json<JwtResponse>)> {
    let jwt = ctx
        .jwt_encoder
        .encode(username)
        .map_err(Error::JwtEncoding)?;
    let cookie = Cookie::build((COOKIE_NAME_JWT, jwt.token.clone()))
        .domain(ctx.cookie.domain.clone())
        .path("/")
        .http_only(!ctx.cookie.http_only_disabled)
        .secure(!ctx.cookie.secure_disabled)
        .expires(jwt.expiration)
        .max_age(jwt.validity);
    Ok((
        StatusCode::OK,
        jar.add(cookie),
        Json(JwtResponse { jwt: jwt.token }),
    ))
}

fn default_filter() -> String {
    r".*".into()
}

impl TryFrom<AppFilterQuery> for AppFilter {
    type Error = Error;

    fn try_from(query: AppFilterQuery) -> Result<Self> {
        let mut errs = ValidationErrors::new();
        let name = match Regex::new(&query.name) {
            Ok(name) => name,
            Err(err) => {
                errs.add(
                    "name",
                    ValidationError::new("regex").with_message(Cow::Owned(err.to_string())),
                );
                Regex::new(r".*").unwrap()
            }
        };
        if errs.is_empty() {
            Ok(Self { name })
        } else {
            Err(Error::Validation(errs))
        }
    }
}
