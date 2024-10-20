use serde::{Deserialize, Serialize};
#[cfg(feature = "ssr")]
use std::fmt::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
	Equipment(i32),
	Person(i32),
	Any,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
	ReadAny,
	Read(Vec<Scope>),
	WriteAny,
	Write(Vec<Scope>),
	Create(bool),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permissions {
	ReadWrite {
		read: Permission,
		write: Permission,
		create: Permission,
	},
}

#[cfg(feature = "ssr")]
impl Permission {
	pub fn parse(perm: String) -> Result<Permissions, &'static str> {
		let perms: String = perm.chars().filter(|&c| c != ' ' && c != ')').map(|c| c.to_ascii_uppercase()).collect();

		let mut read_scopes = Vec::new();
		let mut write_scopes = Vec::new();
		let mut create_scope = None;

		for perm in perms.split("|") {
			match perm {
				"READ(*" => read_scopes.push(Scope::Any),
				"WRITE(*" => write_scopes.push(Scope::Any),
				"CREATE(TRUE" => create_scope = Some(true),
				"CREATE(FALSE" => create_scope = Some(false),
				cleaned_perm => {
					let (action, scope) = cleaned_perm.split_once('(').ok_or("Invalid permission string (No scope found)")?;

					let scope = scope.split(",").collect::<Vec<&str>>();

					for scope_str in &scope {
						let open_paren = scope_str.find('[').ok_or("Invalid permission string (Missing id)")?;
						let close_paren = scope_str.find(']').ok_or("Invalid permission string (Missing id)")?;
						let id_str = &scope_str[open_paren + 1..close_paren];

						let id = match id_str.parse::<i32>() {
							Ok(id) => id,
							Err(_) => return Err("Invalid permission string (Could not parse id)"),
						};

						match &scope_str[..open_paren] {
							"EQUIPMENT" => match action {
								"READ" => {
									read_scopes.push(Scope::Equipment(id));
								},
								"WRITE" => {
									write_scopes.push(Scope::Equipment(id));
								},
								_ => return Err("Invalid permission string (Unrecognized action)"),
							},
							"PERSON" => match action {
								"READ" => {
									read_scopes.push(Scope::Person(id));
								},
								"WRITE" => {
									write_scopes.push(Scope::Person(id));
								},
								_ => return Err("Invalid permission string (Unrecognized action)"),
							},
							_ => return Err("Invalid permission string (Unrecognized scope)"),
						}
					}
				},
			}
		}

		if read_scopes.is_empty() || write_scopes.is_empty() || create_scope.is_none() {
			Err("Invalid permission string (No action/scope found)")
		} else {
			let (read, write) = if write_scopes.contains(&Scope::Any) {
				// If we can write any, we must be able to read any
				(Permission::ReadAny, Permission::WriteAny)
			} else if read_scopes.contains(&Scope::Any) {
				// If we can read all then our write can be a subset of ids
				(Permission::ReadAny, Permission::Write(write_scopes))
			} else {
				// If we have a list of ids in write let's make sure each id is also readable
				for id in &write_scopes {
					if !read_scopes.contains(id) {
						read_scopes.push(*id);
					}
				}
				(Permission::Read(read_scopes), Permission::Write(write_scopes))
			};

			Ok(Permissions::ReadWrite {
				read,
				write,
				create: Permission::Create(create_scope.unwrap()),
			})
		}
	}

	pub fn get_query_select(&self, field: &str) -> String {
		let field_sanitized = match field {
			"id" => "id",
			"equipment" => "equipment",
			_ => "id",
		};

		let mut query = String::new();
		match self {
			Permission::ReadAny | Permission::WriteAny | Permission::Write(_) | Permission::Create(_) => {},
			Permission::Read(scope) => {
				let mut equipment_ids = String::new();
				let mut person_ids = String::new();

				for item in scope.iter() {
					match item {
						Scope::Equipment(id) => {
							if !equipment_ids.is_empty() {
								equipment_ids.push(',');
							}
							write!(&mut equipment_ids, "{id}").unwrap();
						},
						Scope::Person(id) => {
							if !person_ids.is_empty() {
								person_ids.push(',');
							}
							write!(&mut person_ids, "{id}").unwrap();
						},
						Scope::Any => {},
					}
				}

				let mut first_clause = true;
				if !equipment_ids.is_empty() || !person_ids.is_empty() {
					write!(&mut query, " WHERE ").unwrap();
				}
				if !equipment_ids.is_empty() {
					write!(&mut query, "{field_sanitized} IN ({equipment_ids})").unwrap();
					first_clause = false;
				}
				if !person_ids.is_empty() {
					if !first_clause {
						write!(&mut query, " AND ").unwrap();
					}
					write!(&mut query, "person IN ({person_ids})").unwrap();
				}
			},
		}

		query
	}

	pub fn get_query_select_without_where(&self, field: &str) -> String {
		self.get_query_select(field).replace("WHERE", "AND")
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn permission_parse_test() {
		assert_eq!(
			Permission::parse(String::from("READ(*)|WRITE(*)|CREATE(false)")),
			Ok(Permissions::ReadWrite {
				read: Permission::ReadAny,
				write: Permission::WriteAny,
				create: Permission::Create(false),
			})
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment[1])|WRITE(equipment[1])|CREATE(true)")),
			Ok(Permissions::ReadWrite {
				read: Permission::Read(vec![Scope::Equipment(1)]),
				write: Permission::Write(vec![Scope::Equipment(1)]),
				create: Permission::Create(true),
			})
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment[1])|WRITE(equipment[1])|CREATE(false)")),
			Ok(Permissions::ReadWrite {
				read: Permission::Read(vec![Scope::Equipment(1)]),
				write: Permission::Write(vec![Scope::Equipment(1)]),
				create: Permission::Create(false),
			})
		);
		assert_eq!(
			Permission::parse(String::from("READ(person[1])|WRITE(person[1])|CREATE(false)")),
			Ok(Permissions::ReadWrite {
				read: Permission::Read(vec![Scope::Person(1)]),
				write: Permission::Write(vec![Scope::Person(1)]),
				create: Permission::Create(false),
			})
		);
		assert_eq!(
			Permission::parse(String::from("READ(*)|WRITE(equipment[1],equipment[5],person[7])|CREATE(false)")),
			Ok(Permissions::ReadWrite {
				read: Permission::ReadAny,
				write: Permission::Write(vec![Scope::Equipment(1), Scope::Equipment(5), Scope::Person(7)]),
				create: Permission::Create(false),
			})
		);

		assert_eq!(
			Permission::parse(String::from("WriTE(*)|REad(*)|CREATE(true)")),
			Ok(Permissions::ReadWrite {
				read: Permission::ReadAny,
				write: Permission::WriteAny,
				create: Permission::Create(true),
			})
		);
		assert_eq!(
			Permission::parse(String::from("READ( * )|WRITE(* )|CREATE( true )")),
			Ok(Permissions::ReadWrite {
				read: Permission::ReadAny,
				write: Permission::WriteAny,
				create: Permission::Create(true),
			})
		);
		assert_eq!(
			Permission::parse(String::from("READ (*) | WRITE( *)| CREATE(false )")),
			Ok(Permissions::ReadWrite {
				read: Permission::ReadAny,
				write: Permission::WriteAny,
				create: Permission::Create(false),
			})
		);
		assert_eq!(
			Permission::parse(String::from("read(*)|write(*)|create(FALSE)")),
			Ok(Permissions::ReadWrite {
				read: Permission::ReadAny,
				write: Permission::WriteAny,
				create: Permission::Create(false),
			})
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment[1],equipment[2],equipment[4564],equipment[789])|WRITE(equipment[1],equipment[2],equipment[3],equipment[4])|CREATE(false)")),
			Ok(Permissions::ReadWrite {
				read: Permission::Read(vec![
					Scope::Equipment(1),
					Scope::Equipment(2),
					Scope::Equipment(4564),
					Scope::Equipment(789),
					Scope::Equipment(3),
					Scope::Equipment(4),
				]),
				write: Permission::Write(vec![Scope::Equipment(1), Scope::Equipment(2), Scope::Equipment(3), Scope::Equipment(4)]),
				create: Permission::Create(false),
			})
		);
		assert_eq!(
			Permission::parse(String::from(
				"READ(equipment[5], equipment[99], equipment[0]) | WRITE(equipment[5], equipment[99]   , equipment[0] )| CREATE( true  )"
			)),
			Ok(Permissions::ReadWrite {
				read: Permission::Read(vec![Scope::Equipment(5), Scope::Equipment(99), Scope::Equipment(0)]),
				write: Permission::Write(vec![Scope::Equipment(5), Scope::Equipment(99), Scope::Equipment(0)]),
				create: Permission::Create(true),
			})
		);

		assert_eq!(
			Permission::parse(String::from(
				"READ(equipment[1],equipment[2])|WRITE(equipment[1],equipment[2],equipment[3])|CREATE(false)"
			)),
			Ok(Permissions::ReadWrite {
				read: Permission::Read(vec![Scope::Equipment(1), Scope::Equipment(2), Scope::Equipment(3)]),
				write: Permission::Write(vec![Scope::Equipment(1), Scope::Equipment(2), Scope::Equipment(3)]),
				create: Permission::Create(false),
			})
		);
		assert_eq!(
			Permission::parse(String::from(
				"READ(equipment[1],equipment[2],equipment[3])|WRITE(equipment[1],equipment[2])|CREATE(false)"
			)),
			Ok(Permissions::ReadWrite {
				read: Permission::Read(vec![Scope::Equipment(1), Scope::Equipment(2), Scope::Equipment(3)]),
				write: Permission::Write(vec![Scope::Equipment(1), Scope::Equipment(2)]),
				create: Permission::Create(false),
			})
		);
		assert_eq!(
			Permission::parse(String::from("READ(*)|WRITE(equipment[1],equipment[2])|CREATE(FALSE)")),
			Ok(Permissions::ReadWrite {
				read: Permission::ReadAny,
				write: Permission::Write(vec![Scope::Equipment(1), Scope::Equipment(2)]),
				create: Permission::Create(false),
			})
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment[1],equipment[2])|WRITE(*)|CREATE(true)")),
			Ok(Permissions::ReadWrite {
				read: Permission::ReadAny,
				write: Permission::WriteAny,
				create: Permission::Create(true),
			})
		);

		assert_eq!(
			Permission::parse(String::from("READ||WRITE(equipment[1])|CREATE(false)")),
			Err("Invalid permission string (No scope found)")
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment[1])||WRITE")),
			Err("Invalid permission string (No scope found)")
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment[1])|WRITE(equipment[1])|CREATE")),
			Err("Invalid permission string (No scope found)")
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment[1])")),
			Err("Invalid permission string (No action/scope found)")
		);
		assert_eq!(
			Permission::parse(String::from("WRITE(equipment[1])")),
			Err("Invalid permission string (No action/scope found)")
		);
		assert_eq!(
			Permission::parse(String::from("CREATE(false)")),
			Err("Invalid permission string (No action/scope found)")
		);
		assert_eq!(
			Permission::parse(String::from("READ(|WRITE(equipment[1])|CREATE(true)")),
			Err("Invalid permission string (Missing id)")
		);
		assert_eq!(
			Permission::parse(String::from("READ()|WRITE(equipment[1])|CREATE(true)")),
			Err("Invalid permission string (Missing id)")
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment)|WRITE(equipment[1])|CREATE(true)")),
			Err("Invalid permission string (Missing id)")
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment[)|WRITE(equipment[1])|CREATE(true)")),
			Err("Invalid permission string (Missing id)")
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment[5])|WRITE(equipment[1],*)|CREATE(true)")),
			Err("Invalid permission string (Missing id)")
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment[1])|WRITE(equipment[1])|CREATE(foo)")),
			Err("Invalid permission string (Missing id)")
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment[])|WRITE(equipment[1])|CREATE(true)")),
			Err("Invalid permission string (Could not parse id)")
		);
		assert_eq!(
			Permission::parse(String::from(
				"READ(equipment[1],equipment[2],equipment[x],equipment[4])|WRITE(equipment[1])|CREATE(true)"
			)),
			Err("Invalid permission string (Could not parse id)")
		);
		assert_eq!(
			Permission::parse(String::from("FOO(equipment[1],equipment[2],equipment[3])|WRITE(equipment[1])|CREATE(true)")),
			Err("Invalid permission string (Unrecognized action)")
		);
		assert_eq!(
			Permission::parse(String::from("READ(equipment[1],x[2],equipment[3])|WRITE(equipment[1])|CREATE(true)")),
			Err("Invalid permission string (Unrecognized scope)")
		);
	}

	#[test]
	fn get_query_select_test() {
		assert_eq!(
			Permission::Read(vec![Scope::Equipment(1), Scope::Equipment(2), Scope::Equipment(3)]).get_query_select("id"),
			String::from(" WHERE id IN (1,2,3)")
		);
		assert_eq!(
			Permission::Read(vec![Scope::Equipment(1), Scope::Equipment(2), Scope::Equipment(3)])
				.get_query_select("equipment"),
			String::from(" WHERE equipment IN (1,2,3)")
		);
		assert_eq!(
			Permission::Read(vec![Scope::Person(1), Scope::Person(2), Scope::Person(3)]).get_query_select("id"),
			String::from(" WHERE person IN (1,2,3)")
		);

		assert_eq!(
			Permission::Read(vec![Scope::Equipment(1), Scope::Equipment(2), Scope::Equipment(3)]).get_query_select("foo"),
			String::from(" WHERE id IN (1,2,3)")
		);

		assert_eq!(
			Permission::Read(vec![
				Scope::Equipment(1),
				Scope::Equipment(2),
				Scope::Person(666),
				Scope::Person(42)
			])
			.get_query_select("id"),
			String::from(" WHERE id IN (1,2) AND person IN (666,42)")
		);
		assert_eq!(
			Permission::Read(vec![
				Scope::Person(666),
				Scope::Person(42),
				Scope::Equipment(1),
				Scope::Equipment(2)
			])
			.get_query_select("equipment"),
			String::from(" WHERE equipment IN (1,2) AND person IN (666,42)")
		);
		assert_eq!(
			Permission::Read(vec![Scope::Person(1), Scope::Equipment(1),]).get_query_select("id"),
			String::from(" WHERE id IN (1) AND person IN (1)")
		);

		assert_eq!(
			Permission::Read(vec![
				Scope::Person(1),
				Scope::Equipment(1),
				Scope::Person(2),
				Scope::Equipment(2)
			])
			.get_query_select("id"),
			String::from(" WHERE id IN (1,2) AND person IN (1,2)")
		);
	}

	#[test]
	fn get_query_select_without_where_test() {
		assert_eq!(
			Permission::Read(vec![Scope::Equipment(1), Scope::Equipment(2), Scope::Equipment(3)])
				.get_query_select_without_where("id"),
			String::from(" AND id IN (1,2,3)"),
		);
	}
}
