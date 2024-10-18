use leptos::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
	ReadAny,
	Read(Vec<i32>),
	WriteAny,
	Write(Vec<i32>),
}

impl Permission {
	pub fn parse(perm: String) -> Result<Permission, String> {
		match perm.replace(" ", "").replace(")", "").to_uppercase().as_str() {
			"READ(*" => Ok(Permission::ReadAny),
			"WRITE(*" => Ok(Permission::WriteAny),
			cleaned_perm => {
				let parts = cleaned_perm.split("(").collect::<Vec<&str>>();
				if parts.len() != 2 {
					return Err(String::from("Invalid permission string"));
				}

				let scope = parts[1].split(",").collect::<Vec<&str>>();
				let mut numbers = Vec::new();

				for item in &scope {
					match item.parse::<i32>() {
						Ok(num) => numbers.push(num),
						Err(_) => return Err(String::from("Invalid permission string")),
					}
				}

				match parts[0] {
					"READ" => Ok(Permission::Read(numbers)),
					"WRITE" => Ok(Permission::Write(numbers)),
					_ => Err(String::from("Invalid permission string")),
				}
			},
		}
	}
}

#[test]
fn permission_parse_test() {
	assert_eq!(Permission::parse(String::from("READ(*)")), Ok(Permission::ReadAny));
	assert_eq!(Permission::parse(String::from("READ( * )")), Ok(Permission::ReadAny));
	assert_eq!(Permission::parse(String::from("READ (*)")), Ok(Permission::ReadAny));
	assert_eq!(Permission::parse(String::from("read(*)")), Ok(Permission::ReadAny));
	assert_eq!(Permission::parse(String::from("READ(1,2,4564,789)")), Ok(Permission::Read(vec![1, 2, 4564, 789])));
	assert_eq!(Permission::parse(String::from("READ(5, 99, 0)")), Ok(Permission::Read(vec![5, 99, 0])));

	assert_eq!(Permission::parse(String::from("WRITE(*)")), Ok(Permission::WriteAny));
	assert_eq!(Permission::parse(String::from("WRITE(1,2,3,4)")), Ok(Permission::Write(vec![1, 2, 3, 4])));
	assert_eq!(Permission::parse(String::from("WRITE(5, 99   , 0 )")), Ok(Permission::Write(vec![5, 99, 0])));

	assert_eq!(Permission::parse(String::from("READ")), Err(String::from("Invalid permission string")));
	assert_eq!(Permission::parse(String::from("READ(1,2,x,4)")), Err(String::from("Invalid permission string")));
	assert_eq!(Permission::parse(String::from("FOO(1,2,3)")), Err(String::from("Invalid permission string")));
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
	pub id: i32,
	pub username: String,
	pub permission_equipment: Permission,
	pub permission_user: Permission,
	pub permission_todo: Permission,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ssr", derive(sqlx::FromRow))]
pub struct UserSQL {
	pub id: i32,
	pub username: String,
	pub password: String,
	pub permission_equipment: String,
	pub permission_user: String,
	pub permission_todo: String,
}

impl From<UserSQL> for User {
	fn from(val: UserSQL) -> Self {
		User {
			id: val.id,
			username: val.username,
			permission_equipment: Permission::parse(val.permission_equipment).expect("Invalid permission string"),
			permission_user: Permission::parse(val.permission_user).expect("Invalid permission string"),
			permission_todo: Permission::parse(val.permission_todo).expect("Invalid permission string"),
		}
	}
}

impl UserSQL {
	pub fn into_user(self) -> (User, UserPasshash) {
		let password = self.password.clone();
		(self.into(), UserPasshash(password))
	}
}

// Explicitly is not Serialize/Deserialize!
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPasshash(String);

impl Default for User {
	fn default() -> Self {
		Self {
			id: -1,
			username: "Guest".into(),
			permission_equipment: Permission::ReadAny,
			permission_user: Permission::ReadAny,
			permission_todo: Permission::ReadAny,
		}
	}
}

#[cfg(feature = "ssr")]
pub mod ssr {
	pub use super::{User, UserPasshash, UserSQL};
	pub use argon2::{
		self,
		password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
		Argon2,
	};
	pub use async_trait::async_trait;
	pub use axum_session_auth::{Authentication, HasPermission};
	pub use axum_session_sqlx::SessionPgPool;
	pub use rand::rngs::OsRng;
	pub use sqlx::PgPool;
	pub use std::collections::HashSet;

	pub type AuthSession = axum_session_auth::AuthSession<User, i32, SessionPgPool, PgPool>;

	impl User {
		pub async fn get_from_id_with_passhash(id: i32, pool: &PgPool) -> Option<(Self, UserPasshash)> {
			let sqluser =
				sqlx::query_as::<_, UserSQL>("SELECT * FROM users WHERE id = $1").bind(id).fetch_one(pool).await.ok()?;

			Some(sqluser.into_user())
		}

		pub async fn get_from_id(id: i32, pool: &PgPool) -> Option<Self> {
			User::get_from_id_with_passhash(id, pool).await.map(|(user, _)| user)
		}

		pub async fn get_from_username_with_passhash(name: String, pool: &PgPool) -> Option<(Self, UserPasshash)> {
			let sqluser = sqlx::query_as::<_, UserSQL>("SELECT * FROM users WHERE username = $1")
				.bind(name)
				.fetch_one(pool)
				.await
				.ok()?;

			Some(sqluser.into_user())
		}

		pub async fn get_from_username(name: String, pool: &PgPool) -> Option<Self> {
			User::get_from_username_with_passhash(name, pool).await.map(|(user, _)| user)
		}
	}

	#[async_trait]
	impl Authentication<User, i32, PgPool> for User {
		async fn load_user(userid: i32, pool: Option<&PgPool>) -> Result<User, anyhow::Error> {
			let pool = pool.unwrap();
			User::get_from_id(userid, pool).await.ok_or_else(|| anyhow::anyhow!("Cannot get user"))
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

	// #[async_trait]
	// impl HasPermission<PgPool> for User {
	// 	async fn has(&self, perm: &str, _pool: &Option<&PgPool>) -> bool {
	// 		self.permissions.contains(&perm.to_string())
	// 	}
	// }
}

#[server]
pub async fn get_user() -> Result<Option<User>, ServerFnError> {
	use crate::auth::ssr::AuthSession;

	let auth = use_context::<AuthSession>().expect("No session found");

	Ok(auth.current_user)
}

#[server]
pub async fn login(username: String, password: String, remember: Option<String>) -> Result<(), ServerFnError> {
	use self::ssr::*;
	use server_fn::error::NoCustomError;

	let pool = use_context::<PgPool>().expect("Database not initialized");
	let auth = use_context::<AuthSession>().expect("No session found");

	let (user, UserPasshash(expected_passhash)) = User::get_from_username_with_passhash(username, &pool)
		.await
		.ok_or_else(|| ServerFnError::new("Username or Password does not match."))?;

	let parsed_hash = PasswordHash::new(&expected_passhash)
		.map_err(|error| ServerFnError::<NoCustomError>::ServerError(format!("Hashing parsing error: {}", error)))?;

	match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
		Ok(_) => {
			auth.login_user(user.id);
			auth.remember_user(remember.is_some());
			leptos_axum::redirect("/");
			Ok(())
		},
		Err(_) => Err(ServerFnError::ServerError("Username or Password does not match.".to_string())),
	}
}

#[server]
pub async fn signup(
	username: String,
	password: String,
	password_confirmation: String,
	remember: Option<String>,
) -> Result<(), ServerFnError> {
	use self::ssr::*;
	use server_fn::error::NoCustomError;

	let pool = use_context::<PgPool>().expect("Database not initialized");
	let auth = use_context::<AuthSession>().expect("No session found");

	if password != password_confirmation {
		return Err(ServerFnError::ServerError("Passwords did not match.".to_string()));
	}

	let salt = SaltString::generate(&mut OsRng);

	let password_hashed = Argon2::default()
		.hash_password(password.as_bytes(), &salt)
		.map_err(|error| ServerFnError::<NoCustomError>::ServerError(format!("Hashing error: {}", error)))?
		.to_string();

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

#[server]
pub async fn logout() -> Result<(), ServerFnError> {
	use self::ssr::*;

	let auth = use_context::<AuthSession>().expect("No session found");

	auth.logout_user();
	leptos_axum::redirect("/");

	Ok(())
}
