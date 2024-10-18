use axum::extract::FromRef;
use leptos::LeptosOptions;
use leptos_router::RouteListing;
use sqlx::PgPool;

#[derive(FromRef, Debug, Clone)]
pub struct AppState {
	pub leptos_options: LeptosOptions,
	pub routes: Vec<RouteListing>,
	pub pool: PgPool,
}
