use std::{collections::BTreeSet, net::SocketAddr, sync::Arc};

use aide::{
    axum::ApiRouter,
    openapi::{Info, OpenApi},
    OperationOutput,
};
use axum::{
    extract::{MatchedPath, Path, State},
    http::{header, HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json, Router,
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
use validator::Validate;

use crate::{
    jwt::JwtEncoder,
    kube::{
        App, AppSpec, Chart, Invitation, InvitationSpec, KubeClient, Permission, Service, User,
        UserSpec, FINALIZER,
    },
    mail::MailSender,
    pwd::PasswordEncoder,
    SignalListener, CARGO_PKG_NAME,
};

pub const PATH_JOIN: &str = "/join";

pub struct ApiContext<J: JwtEncoder, K: KubeClient, M: MailSender, P: PasswordEncoder> {
    pub jwt_encoder: J,
    pub kube: K,
    pub mail_sender: M,
    pub pwd_encoder: P,
}

pub async fn start_api<
    J: JwtEncoder + 'static,
    K: KubeClient + 'static,
    M: MailSender + 'static,
    P: PasswordEncoder + 'static,
>(
    addr: SocketAddr,
    ctx: ApiContext<J, K, M, P>,
) -> anyhow::Result<()> {
    let mut sig = SignalListener::new()?;
    debug!("binding tcp listener");
    let tcp = TcpListener::bind(addr).await?;
    info!("server started");
    axum::serve(tcp, create_router(ctx))
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
    Mail(
        #[from]
        #[source]
        crate::mail::Error,
    ),
    #[error("malformed resource")]
    MalformedResource,
    #[error("{0}")]
    PasswordEncoder(
        #[from]
        #[source]
        crate::pwd::Error,
    ),
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
        validator::ValidationErrors,
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

#[derive(Clone, Debug, Deserialize, PartialEq, JsonSchema, Serialize, Validate)]
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

#[derive(Clone, Debug, Deserialize, PartialEq, JsonSchema, Serialize, Validate)]
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
struct UserPasswordCredentialsRequest {
    /// Password.
    password: String,
    /// Username.
    #[serde(deserialize_with = "string_trim")]
    #[validate(length(min = 1))]
    user: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
struct JwtResponse {
    /// JWT.
    jwt: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceAlreadyExistsItem {
    /// Field in conflict.
    field: String,
    /// Source of conflict.
    source: Option<String>,
    /// Value in conflict.
    value: String,
}

fn create_router<
    J: JwtEncoder + 'static,
    K: KubeClient + 'static,
    M: MailSender + 'static,
    P: PasswordEncoder + 'static,
>(
    ctx: ApiContext<J, K, M, P>,
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
    ApiRouter::new()
        .api_route("/_health", aide::axum::routing::get(health))
        .api_route("/app", aide::axum::routing::post(create_app))
        .api_route(
            "/auth",
            aide::axum::routing::post(authenticate_with_password),
        )
        .api_route(
            &format!("{PATH_JOIN}/:token"),
            aide::axum::routing::put(join),
        )
        .api_route("/user/invite", aide::axum::routing::post(send_invitation))
        .route("/_doc", axum::routing::get(doc))
        .finish_api(&mut api)
        .with_state(Arc::new(ctx))
        .layer(trace_layer)
        .layer(Extension(api))
}

#[instrument(skip(ctx, req), fields(user.name = req.user))]
async fn authenticate_with_password<
    J: JwtEncoder,
    K: KubeClient,
    M: MailSender,
    P: PasswordEncoder,
>(
    State(ctx): State<Arc<ApiContext<J, K, M, P>>>,
    Json(req): Json<UserPasswordCredentialsRequest>,
) -> Result<(StatusCode, Json<JwtResponse>)> {
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
        let jwt = ctx
            .jwt_encoder
            .encode(&req.user)
            .map_err(Error::JwtEncoding)?;
        Ok((StatusCode::OK, Json(JwtResponse { jwt })))
    } else {
        Err(Error::WrongCredentials)
    }
}

async fn create_app<J: JwtEncoder, K: KubeClient, M: MailSender, P: PasswordEncoder>(
    headers: HeaderMap,
    State(ctx): State<Arc<ApiContext<J, K, M, P>>>,
    Json(req): Json<CreateAppRequest>,
) -> Result<(StatusCode, Json<AppSpec>)> {
    let user = authenticated_user(&headers, &ctx.jwt_encoder, &ctx.kube).await?;
    check_permission(&user, &Permission::CreateApp {}, &ctx.kube).await?;
    req.validate()?;
    ensure_domains_are_free(&req.name, &req.services, &ctx.kube).await?;
    let namespace = req.namespace.unwrap_or_else(|| req.name.clone());
    let spec = AppSpec {
        chart: req.chart,
        namespace,
        services: req.services,
        values: req.values,
    };
    let span = info_span!("create_app", app.name = req.name,);
    async {
        debug!("creating app");
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

#[instrument(skip(api))]
async fn doc(Extension(api): Extension<OpenApi>) -> Json<OpenApi> {
    Json(api)
}

#[instrument]
async fn health<J: JwtEncoder, K: KubeClient, M: MailSender, P: PasswordEncoder>(
    _: State<Arc<ApiContext<J, K, M, P>>>,
) -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn join<J: JwtEncoder, K: KubeClient, M: MailSender, P: PasswordEncoder>(
    State(ctx): State<Arc<ApiContext<J, K, M, P>>>,
    Path(token): Path<String>,
    Json(req): Json<UserPasswordCredentialsRequest>,
) -> Result<(StatusCode, Json<JwtResponse>)> {
    req.validate()?;
    let span = info_span!("join", invit.token = token);
    async {
        debug!("creating user from invitation");
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
        let jwt = ctx
            .jwt_encoder
            .encode(&req.user)
            .map_err(Error::JwtEncoding)?;
        Ok((StatusCode::CREATED, Json(JwtResponse { jwt })))
    }
    .instrument(span)
    .await
}

async fn send_invitation<J: JwtEncoder, K: KubeClient, M: MailSender, P: PasswordEncoder>(
    headers: HeaderMap,
    State(ctx): State<Arc<ApiContext<J, K, M, P>>>,
    Json(req): Json<SendInvitationRequest>,
) -> Result<(StatusCode, Json<InvitationSpec>)> {
    req.validate()?;
    let user = authenticated_user(&headers, &ctx.jwt_encoder, &ctx.kube).await?;
    let from = user.metadata.name.as_ref().ok_or_else(|| {
        debug!("user doesn't have name");
        Error::MalformedResource
    })?;
    check_permission(&user, &Permission::InviteUsers {}, &ctx.kube).await?;
    let token = Uuid::new_v4().to_string();
    let spec = InvitationSpec {
        from: from.clone(),
        roles: req.roles,
        to: req.to,
    };
    let span = info_span!(
        "send_invitation",
        auth = from,
        invit.to = spec.to,
        invit.token = token,
    );
    async {
        debug!("sending invitation email");
        let invit = Invitation {
            metadata: ObjectMeta {
                name: Some(token.clone()),
                ..Default::default()
            },
            spec,
        };
        ctx.kube.patch_invitation(&token, &invit).await?;
        ctx.mail_sender.send_invitation(&token, &invit).await?;
        info!("invitation sent");
        Ok((StatusCode::CREATED, Json(invit.spec)))
    }
    .instrument(span)
    .await
}

#[instrument(skip(headers, encoder, kube))]
async fn authenticated_user<J: JwtEncoder, K: KubeClient>(
    headers: &HeaderMap,
    encoder: &J,
    kube: &K,
) -> Result<User> {
    let authz = headers.get(header::AUTHORIZATION).ok_or_else(|| {
        debug!("request doesn't contain header `{}`", header::AUTHORIZATION);
        Error::Unauthorized
    })?;
    let authz = authz.to_str().map_err(|err| {
        debug!("invalid header `{}`: {err}", header::AUTHORIZATION);
        Error::Unauthorized
    })?;
    let regex = Regex::new(r"(?i)bearer (.*)$").unwrap();
    let caps = regex.captures(authz).ok_or_else(|| {
        debug!("header `{}` doesn't match pattern", header::AUTHORIZATION);
        Error::Unauthorized
    })?;
    let jwt = caps.get(1).unwrap().as_str();
    let name = encoder.decode(jwt).map_err(Error::JwtDecoding)?;
    kube.get_user(&name).await?.ok_or_else(|| {
        debug!("user doesn't exist");
        Error::Unauthorized
    })
}

async fn check_permission<K: KubeClient>(user: &User, perm: &Permission, kube: &K) -> Result {
    if kube.user_has_permission(user, perm).await? {
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
