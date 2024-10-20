use crate::{auth::*, error_template::ErrorTemplate};
use chrono::prelude::*;
use leptos::*;
use leptos_meta::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Todo {
	id: i32,
	user: Option<User>,
	title: String,
	created_at: DateTime<Utc>,
	completed: bool,
}

#[cfg(feature = "ssr")]
pub mod ssr {
	use super::Todo;
	use crate::auth::User;
	use chrono::prelude::*;
	use sqlx::PgPool;

	#[derive(sqlx::FromRow, Clone)]
	pub struct SqlTodo {
		id: i32,
		person: i32,
		title: String,
		created_at: DateTime<Utc>,
		completed: bool,
	}

	impl SqlTodo {
		pub async fn into_todo(self, pool: &PgPool) -> Todo {
			Todo {
				id: self.id,
				user: User::get_from_id(self.person, pool).await,
				title: self.title,
				created_at: self.created_at,
				completed: self.completed,
			}
		}
	}
}

#[server]
pub async fn get_todos() -> Result<Vec<Todo>, ServerFnError> {
	use self::ssr::SqlTodo;
	use crate::permission::Permissions;
	use futures::future::join_all;
	use sqlx::PgPool;

	let pool = use_context::<PgPool>().expect("Database not initialized");
	let user = get_user().await?;

	let mut query = String::from("SELECT * FROM todos");
	match user {
		Some(user) => {
			let Permissions::ReadWrite {
				read: perm,
				write: _,
				create: _,
			} = user.permission_todo;
			query.push_str(&perm.get_query_select("id"));
		},
		None => return Err(ServerFnError::Request(String::from("User not authenticated"))),
	};

	Ok(
		join_all(
			sqlx::query_as::<_, SqlTodo>(&query)
				.fetch_all(&pool)
				.await?
				.iter()
				.map(|todo: &SqlTodo| todo.clone().into_todo(&pool)),
		)
		.await,
	)
}

#[server]
pub async fn add_todo(title: String) -> Result<(), ServerFnError> {
	use sqlx::PgPool;

	let pool = use_context::<PgPool>().expect("Database not initialized");
	let user = get_user().await?;

	let id = match user {
		Some(user) => user.id,
		None => -1,
	};

	// fake API delay
	std::thread::sleep(std::time::Duration::from_millis(1250));

	Ok(
		sqlx::query!("INSERT INTO todos (title, person, completed) VALUES ($1, $2, false)", title, id)
			.execute(&pool)
			.await
			.map(|_| ())?,
	)
}

#[server]
pub async fn delete_todo(id: u16) -> Result<(), ServerFnError> {
	use sqlx::PgPool;

	let pool = use_context::<PgPool>().expect("Database not initialized");

	Ok(sqlx::query("DELETE FROM todos WHERE id = $1").bind(id as i16).execute(&pool).await.map(|_| ())?)
}

#[component]
pub fn TodoApp() -> impl IntoView {
	let login = create_server_action::<Login>();
	let logout = create_server_action::<Logout>();
	let signup = create_server_action::<Signup>();

	let user = create_resource(
		move || (login.version().get(), signup.version().get(), logout.version().get()),
		move |_| get_user(),
	);
	provide_meta_context();

	view! {
		<Link rel="shortcut icon" type_="image/ico" href="/favicon.ico" />
		<Stylesheet id="leptos" href="/pkg/session_auth_axum.css" />
		<Router>
			<header>
				<A href="/">
					<h1>"My Tasks"</h1>
				</A>
				<Transition fallback=move || {
					view! { <span>"Loading..."</span> }
				}>
					{move || {
						user.get()
							.map(|user| match user {
								Err(e) => {
									view! {
										<A href="/signup">"Signup"</A>
										", "
										<A href="/login">"Login"</A>
										", "
										<span>{format!("Login error: {}", e)}</span>
									}
										.into_view()
								}
								Ok(None) => {
									view! {
										<A href="/signup">"Signup"</A>
										", "
										<A href="/login">"Login"</A>
										", "
										<span>"Logged out."</span>
									}
										.into_view()
								}
								Ok(Some(user)) => {
									view! {
										<A href="/settings">"Settings"</A>
										", "
										<span>
											{format!("Logged in as: {} ({})", user.username, user.id)}
										</span>
									}
										.into_view()
								}
							})
					}}

				</Transition>
			</header>
			<hr />
			<main>
				<Routes>
					// Route
					<Route path="" view=Todos />
					<Route path="signup" view=move || view! { <Signup action=signup /> } />
					<Route path="login" view=move || view! { <Login action=login /> } />
					<Route
						path="settings"
						view=move || {
							view! {
								<h1>"Settings"</h1>
								<Logout action=logout />
							}
						}
					/>

				</Routes>
			</main>
		</Router>
	}
}

#[component]
pub fn Todos() -> impl IntoView {
	let add_todo = create_server_multi_action::<AddTodo>();
	let delete_todo = create_server_action::<DeleteTodo>();
	let submissions = add_todo.submissions();

	// list of todos is loaded from the server in reaction to changes
	let todos = create_resource(move || (add_todo.version().get(), delete_todo.version().get()), move |_| get_todos());

	view! {
		<div>
			<MultiActionForm action=add_todo>
				<label>"Add a Todo" <input type="text" name="title" /></label>
				<input type="submit" value="Add" />
			</MultiActionForm>
			<Transition fallback=move || view! { <p>"Loading..."</p> }>
				<ErrorBoundary fallback=|errors| {
					view! { <ErrorTemplate errors=errors /> }
				}>
					{move || {
						let existing_todos = {
							move || {
								todos
									.get()
									.map(move |todos| match todos {
										Err(e) => {
											view! {
												<pre class="error">"Server Error: " {e.to_string()}</pre>
											}
												.into_view()
										}
										Ok(todos) => {
											if todos.is_empty() {
												view! { <p>"No tasks were found."</p> }.into_view()
											} else {
												todos
													.into_iter()
													.map(move |todo| {
														view! {
															<li>
																{todo.title} ": Created at " {todo.created_at.to_string()}
																" by " {todo.user.unwrap_or_default().username}
																<ActionForm action=delete_todo>
																	<input type="hidden" name="id" value=todo.id />
																	<input type="submit" value="X" />
																</ActionForm>
															</li>
														}
													})
													.collect_view()
											}
										}
									})
									.unwrap_or_default()
							}
						};
						let pending_todos = move || {
							submissions
								.get()
								.into_iter()
								.filter(|submission| submission.pending().get())
								.map(|submission| {
									view! {
										<li class="pending">
											{move || submission.input.get().map(|data| data.title)}
										</li>
									}
								})
								.collect_view()
						};
						view! { <ul>{existing_todos} {pending_todos}</ul> }
					}}

				</ErrorBoundary>
			</Transition>
		</div>
	}
}

#[component]
pub fn Login(action: Action<Login, Result<(), ServerFnError>>) -> impl IntoView {
	view! {
		<ActionForm action=action>
			<h1>"Log In"</h1>
			<label>
				"User:"
				<input
					type="text"
					placeholder="User Name"
					maxlength="32"
					name="username"
					class="auth-input"
				/>
			</label>
			<br />
			<label>
				"Password:"
				<input type="password" placeholder="Password" name="password" class="auth-input" />
			</label>
			<br />
			<label>
				<input type="checkbox" name="remember" class="auth-input" />
				"Remember me?"
			</label>
			<br />
			<button type="submit" class="button">
				"Log In"
			</button>
		</ActionForm>
	}
}

#[component]
pub fn Signup(action: Action<Signup, Result<(), ServerFnError>>) -> impl IntoView {
	view! {
		<ActionForm action=action>
			<h1>"Sign Up"</h1>
			<label>
				"User:"
				<input
					type="text"
					placeholder="User Name"
					maxlength="32"
					name="username"
					class="auth-input"
				/>
			</label>
			<br />
			<label>
				"Password:"
				<input type="password" placeholder="Password" name="password" class="auth-input" />
			</label>
			<br />
			<label>
				"Confirm Password:"
				<input
					type="password"
					placeholder="Password again"
					name="password_confirmation"
					class="auth-input"
				/>
			</label>
			<br />
			<label>
				"Remember me?" <input type="checkbox" name="remember" class="auth-input" />
			</label>

			<br />
			<button type="submit" class="button">
				"Sign Up"
			</button>
		</ActionForm>
	}
}

#[component]
pub fn Logout(action: Action<Logout, Result<(), ServerFnError>>) -> impl IntoView {
	view! {
		<div id="loginbox">
			<ActionForm action=action>
				<button type="submit" class="button">
					"Log Out"
				</button>
			</ActionForm>
		</div>
	}
}
