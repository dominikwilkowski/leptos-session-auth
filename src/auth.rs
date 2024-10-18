use leptos::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
	ReadAny,
	Read(Vec<i32>),
	WriteAny,
	Write(Vec<i32>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permissions {
	ReadWrite { read: Permission, write: Permission },
}

impl Permission {
	pub fn parse(perm: String) -> Result<Permissions, &'static str> {
		let perms: String = perm.chars().filter(|&c| c != ' ' && c != ')').map(|c| c.to_ascii_uppercase()).collect();

		let mut read_ids = Vec::new();
		let mut write_ids = Vec::new();

		for perm in perms.split("|") {
			match perm {
				"READ(*" => read_ids.push(-1),
				"WRITE(*" => write_ids.push(-1),
				cleaned_perm => {
					let (action, scope) = cleaned_perm.split_once('(').ok_or_else(|| "Invalid permission string")?;

					let scope = scope.split(",").collect::<Vec<&str>>();
					let mut ids = Vec::with_capacity(scope.len());

					for item in &scope {
						match item.parse::<i32>() {
							Ok(id) => ids.push(id),
							Err(_) => return Err("Invalid permission string"),
						}
					}

					match action {
						"READ" => {
							read_ids = ids;
						},
						"WRITE" => {
							write_ids = ids;
						},
						_ => return Err("Invalid permission string"),
					}
				},
			}
		}

		if read_ids.is_empty() || write_ids.is_empty() {
			Err("Invalid permission string")
		} else {
			let (read, write) = if write_ids.contains(&-1) {
				// If we can write any, we must be able to read any
				(Permission::ReadAny, Permission::WriteAny)
			} else if read_ids.contains(&-1) {
				// If we can read all then our write can be a subset of ids
				(Permission::ReadAny, Permission::Write(write_ids))
			} else {
				// If we have a list of ids in write let's make sure each id is also readable
				for id in &write_ids {
					if !read_ids.contains(&id) {
						read_ids.push(*id);
					}
				}
				(Permission::Read(read_ids), Permission::Write(write_ids))
			};

			Ok(Permissions::ReadWrite { read, write })
		}
	}
}

#[test]
fn permission_parse_test() {
	assert_eq!(
		Permission::parse(String::from("READ(*)|WRITE(*)")),
		Ok(Permissions::ReadWrite {
			read: Permission::ReadAny,
			write: Permission::WriteAny
		})
	);
	assert_eq!(
		Permission::parse(String::from("WriTE(*)|REad(*)")),
		Ok(Permissions::ReadWrite {
			read: Permission::ReadAny,
			write: Permission::WriteAny
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ( * )|WRITE(* )")),
		Ok(Permissions::ReadWrite {
			read: Permission::ReadAny,
			write: Permission::WriteAny
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ (*) | WRITE( *)")),
		Ok(Permissions::ReadWrite {
			read: Permission::ReadAny,
			write: Permission::WriteAny
		})
	);
	assert_eq!(
		Permission::parse(String::from("read(*)|write(*)")),
		Ok(Permissions::ReadWrite {
			read: Permission::ReadAny,
			write: Permission::WriteAny
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ(1,2,4564,789)|WRITE(1,2,3,4)")),
		Ok(Permissions::ReadWrite {
			read: Permission::Read(vec![1, 2, 4564, 789, 3, 4]),
			write: Permission::Write(vec![1, 2, 3, 4])
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ(5, 99, 0) | WRITE(5, 99   , 0 )")),
		Ok(Permissions::ReadWrite {
			read: Permission::Read(vec![5, 99, 0]),
			write: Permission::Write(vec![5, 99, 0])
		})
	);

	assert_eq!(
		Permission::parse(String::from("READ(1,2)|WRITE(1,2,3)")),
		Ok(Permissions::ReadWrite {
			read: Permission::Read(vec![1, 2, 3]),
			write: Permission::Write(vec![1, 2, 3])
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ(1,2,3)|WRITE(1,2)")),
		Ok(Permissions::ReadWrite {
			read: Permission::Read(vec![1, 2, 3]),
			write: Permission::Write(vec![1, 2])
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ(*)|WRITE(1,2)")),
		Ok(Permissions::ReadWrite {
			read: Permission::ReadAny,
			write: Permission::Write(vec![1, 2])
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ(1,2)|WRITE(*)")),
		Ok(Permissions::ReadWrite {
			read: Permission::ReadAny,
			write: Permission::WriteAny
		})
	);

	assert_eq!(Permission::parse(String::from("READ||WRITE(1)")), Err("Invalid permission string"));
	assert_eq!(Permission::parse(String::from("READ(1)||WRITE")), Err("Invalid permission string"));
	assert_eq!(Permission::parse(String::from("READ(1)")), Err("Invalid permission string"));
	assert_eq!(Permission::parse(String::from("WRITE(1)")), Err("Invalid permission string"));
	assert_eq!(Permission::parse(String::from("READ(||WRITE(1)")), Err("Invalid permission string"));
	assert_eq!(Permission::parse(String::from("READ()|WRITE(1)")), Err("Invalid permission string"));
	assert_eq!(Permission::parse(String::from("READ(1,2,x,4)|WRITE(1)")), Err("Invalid permission string"));
	assert_eq!(Permission::parse(String::from("FOO(1,2,3)|WRITE(1)")), Err("Invalid permission string"));
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
	pub id: i32,
	pub username: String,
	pub permission_equipment: Permissions,
	pub permission_user: Permissions,
	pub permission_todo: Permissions,
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
			permission_equipment: Permissions::ReadWrite {
				read: Permission::ReadAny,
				write: Permission::WriteAny,
			},
			permission_user: Permissions::ReadWrite {
				read: Permission::ReadAny,
				write: Permission::WriteAny,
			},
			permission_todo: Permissions::ReadWrite {
				read: Permission::ReadAny,
				write: Permission::WriteAny,
			},
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
