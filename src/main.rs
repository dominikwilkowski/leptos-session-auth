pub mod db;

use axum::{
    body::Body as AxumBody,
    extract::{Path, State},
    http::Request,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use axum_session::{SessionConfig, SessionLayer, SessionStore};
use axum_session_auth::{AuthConfig, AuthSessionLayer};
pub use axum_session_sqlx::SessionPgPool;
use leptos::{get_configuration, logging::log, provide_context};
use leptos_axum::{
    generate_route_list, handle_server_fns_with_context, LeptosRoutes,
};
use session_auth_axum::{
    auth::{ssr::AuthSession, User},
    fallback::file_and_error_handler,
    state::AppState,
    todo::*,
};
use sqlx::PgPool;

async fn server_fn_handler(
    State(app_state): State<AppState>,
    auth_session: AuthSession,
    path: Path<String>,
    request: Request<AxumBody>,
) -> impl IntoResponse {
    log!("{:?}", path);

    handle_server_fns_with_context(
        move || {
            provide_context(auth_session.clone());
            provide_context(app_state.pool.clone());
        },
        request,
    )
    .await
}

async fn leptos_routes_handler(
    auth_session: AuthSession,
    State(app_state): State<AppState>,
    req: Request<AxumBody>,
) -> Response {
    let handler = leptos_axum::render_route_with_context(
        app_state.leptos_options.clone(),
        app_state.routes.clone(),
        move || {
            provide_context(auth_session.clone());
            provide_context(app_state.pool.clone());
        },
        TodoApp,
    );
    handler(req).await.into_response()
}

#[tokio::main]
async fn main() {
    use crate::db::ssr::{get_db, init_db};

    simple_logger::init_with_level(log::Level::Info)
        .expect("couldn't initialize logging");

    init_db().await.expect("Initialization of database failed");

    // Auth section
    let session_config =
        SessionConfig::default().with_table_name("axum_sessions");
    let auth_config = AuthConfig::<i32>::default();
    let session_store = SessionStore::<SessionPgPool>::new(
        Some(SessionPgPool::from(get_db().clone())),
        session_config,
    )
    .await
    .unwrap();

    if let Err(e) = sqlx::migrate!().run(&get_db().clone()).await {
        eprintln!("{e:?}");
    }

    // Setting this to None means we'll be using cargo-leptos and its env vars
    let conf = get_configuration(None).await.unwrap();
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(TodoApp);

    let app_state = AppState {
        leptos_options,
        routes: routes.clone(),
        pool: get_db().clone(),
    };

    // build our application with a route
    let app = Router::new()
        .route(
            "/api/*fn_name",
            get(server_fn_handler).post(server_fn_handler),
        )
        .leptos_routes_with_handler(routes, get(leptos_routes_handler))
        .fallback(file_and_error_handler)
        .layer(
            AuthSessionLayer::<User, i32, SessionPgPool, PgPool>::new(Some(
                get_db().clone(),
            ))
            .with_config(auth_config),
        )
        .layer(SessionLayer::new(session_store))
        .with_state(app_state);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    log!("listening on http://{}", &addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
