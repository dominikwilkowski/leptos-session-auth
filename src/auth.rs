use leptos::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
	pub id: i32,
	pub username: String,
	pub permissions: HashSet<String>,
}

// Explicitly is not Serialize/Deserialize!
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPasshash(String);

impl Default for User {
	fn default() -> Self {
		let permissions = HashSet::new();

		Self {
			id: -1,
			username: "Guest".into(),
			permissions,
		}
	}
}

#[cfg(feature = "ssr")]
pub mod ssr {
	pub use super::{User, UserPasshash};
	pub use axum_session_auth::{Authentication, HasPermission};
	pub use axum_session_sqlx::SessionPgPool;
	pub use sqlx::PgPool;
	pub use std::collections::HashSet;
	pub type AuthSession = axum_session_auth::AuthSession<User, i32, SessionPgPool, PgPool>;
	pub use crate::todo::ssr::auth;
	pub use async_trait::async_trait;
	pub use bcrypt::{hash, verify, DEFAULT_COST};

	impl User {
		pub async fn get_with_passhash(id: i32, pool: &PgPool) -> Option<(Self, UserPasshash)> {
			let sqluser =
				sqlx::query_as::<_, SqlUser>("SELECT * FROM users WHERE id = $1").bind(id).fetch_one(pool).await.ok()?;

			//lets just get all the tokens the user can use, we will only use the full permissions if modifying them.
			let sql_user_perms =
				sqlx::query_as::<_, SqlPermissionTokens>("SELECT token FROM user_permissions WHERE user_id = $1;")
					.bind(id)
					.fetch_all(pool)
					.await
					.ok()?;

			Some(sqluser.into_user(Some(sql_user_perms)))
		}

		pub async fn get(id: i32, pool: &PgPool) -> Option<Self> {
			User::get_with_passhash(id, pool).await.map(|(user, _)| user)
		}

		pub async fn get_from_username_with_passhash(name: String, pool: &PgPool) -> Option<(Self, UserPasshash)> {
			let sqluser = sqlx::query_as::<_, SqlUser>("SELECT * FROM users WHERE username = $1")
				.bind(name)
				.fetch_one(pool)
				.await
				.ok()?;

			//lets just get all the tokens the user can use, we will only use the full permissions if modifying them.
			let sql_user_perms =
				sqlx::query_as::<_, SqlPermissionTokens>("SELECT token FROM user_permissions WHERE user_id = $1;")
					.bind(sqluser.id)
					.fetch_all(pool)
					.await
					.ok()?;

			Some(sqluser.into_user(Some(sql_user_perms)))
		}

		pub async fn get_from_username(name: String, pool: &PgPool) -> Option<Self> {
			User::get_from_username_with_passhash(name, pool).await.map(|(user, _)| user)
		}
	}

	#[derive(sqlx::FromRow, Clone)]
	pub struct SqlPermissionTokens {
		pub token: String,
	}

	#[async_trait]
	impl Authentication<User, i32, PgPool> for User {
		async fn load_user(userid: i32, pool: Option<&PgPool>) -> Result<User, anyhow::Error> {
			let pool = pool.unwrap();
			User::get(userid, pool).await.ok_or_else(|| anyhow::anyhow!("Cannot get user"))
		}

		fn is_authenticated(&self) -> bool {
			true
		}

		fn is_active(&self) -> bool {
			true
		}

		fn is_anonymous(&self) -> bool {
			false
		}
	}

	#[async_trait]
	impl HasPermission<PgPool> for User {
		async fn has(&self, perm: &str, _pool: &Option<&PgPool>) -> bool {
			self.permissions.contains(perm)
		}
	}

	#[derive(sqlx::FromRow, Clone)]
	pub struct SqlUser {
		pub id: i32,
		pub username: String,
		pub password: String,
	}

	impl SqlUser {
		pub fn into_user(self, sql_user_perms: Option<Vec<SqlPermissionTokens>>) -> (User, UserPasshash) {
			(
				User {
					id: self.id,
					username: self.username,
					permissions: if let Some(user_perms) = sql_user_perms {
						user_perms.into_iter().map(|x| x.token).collect::<HashSet<String>>()
					} else {
						HashSet::<String>::new()
					},
				},
				UserPasshash(self.password),
			)
		}
	}
}

#[server]
pub async fn get_user() -> Result<Option<User>, ServerFnError> {
	use crate::todo::ssr::auth;

	let auth = auth()?;

	Ok(auth.current_user)
}

#[server(Login, "/api")]
pub async fn login(username: String, password: String, remember: Option<String>) -> Result<(), ServerFnError> {
	use self::ssr::*;

	let pool = use_context::<PgPool>().expect("Database not initialized");
	let auth = auth()?;

	let (user, UserPasshash(expected_passhash)) = User::get_from_username_with_passhash(username, &pool)
		.await
		.ok_or_else(|| ServerFnError::new("User does not exist."))?;

	match verify(password, &expected_passhash)? {
		true => {
			auth.login_user(user.id);
			auth.remember_user(remember.is_some());
			leptos_axum::redirect("/");
			Ok(())
		},
		false => Err(ServerFnError::ServerError("Password does not match.".to_string())),
	}
}

#[server(Signup, "/api")]
pub async fn signup(
	username: String,
	password: String,
	password_confirmation: String,
	remember: Option<String>,
) -> Result<(), ServerFnError> {
	use self::ssr::*;

	let pool = use_context::<PgPool>().expect("Database not initialized");
	let auth = auth()?;

	if password != password_confirmation {
		return Err(ServerFnError::ServerError("Passwords did not match.".to_string()));
	}

	let password_hashed = hash(password, DEFAULT_COST).unwrap();

	sqlx::query("INSERT INTO users (username, password) VALUES ($1, $2)")
		.bind(username.clone())
		.bind(password_hashed)
		.execute(&pool)
		.await?;

	let user = User::get_from_username(username, &pool)
		.await
		.ok_or_else(|| ServerFnError::new("Signup failed: User does not exist."))?;

	auth.login_user(user.id);
	auth.remember_user(remember.is_some());

	leptos_axum::redirect("/");

	Ok(())
}

#[server(Logout, "/api")]
pub async fn logout() -> Result<(), ServerFnError> {
	use self::ssr::*;

	let auth = auth()?;

	auth.logout_user();
	leptos_axum::redirect("/");

	Ok(())
}
