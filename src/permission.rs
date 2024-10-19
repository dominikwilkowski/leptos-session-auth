use serde::{Deserialize, Serialize};
#[cfg(feature = "ssr")]
use std::fmt::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
	Id(i32),
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
}

#[cfg(feature = "ssr")]
impl Permission {
	pub fn parse(perm: String) -> Result<Permissions, &'static str> {
		let perms: String = perm.chars().filter(|&c| c != ' ' && c != ')').map(|c| c.to_ascii_uppercase()).collect();

		let mut read_scopes = Vec::new();
		let mut write_scopes = Vec::new();

		for perm in perms.split("|") {
			match perm {
				"READ(*" => read_scopes.push(Scope::Any),
				"WRITE(*" => write_scopes.push(Scope::Any),
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
							"ID" => match action {
								"READ" => {
									read_scopes.push(Scope::Id(id));
								},
								"WRITE" => {
									write_scopes.push(Scope::Id(id));
								},
								_ => return Err("Invalid permission string (Unrecognized action)"),
							},
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

		if read_scopes.is_empty() || write_scopes.is_empty() {
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

			Ok(Permissions::ReadWrite { read, write })
		}
	}

	pub fn get_query(&self) -> String {
		let mut query = String::new();
		match self {
			Permission::ReadAny | Permission::WriteAny => {},
			Permission::Read(scope) => {
				let mut id_ids = String::new();
				let mut equipment_ids = String::new();
				let mut person_ids = String::new();

				for item in scope.iter() {
					match item {
						Scope::Id(id) => {
							if !id_ids.is_empty() {
								id_ids.push(',');
							}
							write!(&mut id_ids, "{id}").unwrap();
						},
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
				if !id_ids.is_empty() || !equipment_ids.is_empty() || !person_ids.is_empty() {
					write!(&mut query, " WHERE ").unwrap();
				}
				if !id_ids.is_empty() {
					write!(&mut query, "id IN ({id_ids})").unwrap();
					first_clause = false;
				}
				if !equipment_ids.is_empty() {
					if !first_clause {
						write!(&mut query, " AND ").unwrap();
					}
					write!(&mut query, "equipment IN ({equipment_ids})").unwrap();
					first_clause = false;
				}
				if !person_ids.is_empty() {
					if !first_clause {
						write!(&mut query, " AND ").unwrap();
					}
					write!(&mut query, "person IN ({person_ids})").unwrap();
				}
			},
			Permission::Write(_) => {
				// TODO
			},
		}

		query
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
		Permission::parse(String::from("READ(id[1])|WRITE(id[1])")),
		Ok(Permissions::ReadWrite {
			read: Permission::Read(vec![Scope::Id(1)]),
			write: Permission::Write(vec![Scope::Id(1)])
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ(equipment[1])|WRITE(equipment[1])")),
		Ok(Permissions::ReadWrite {
			read: Permission::Read(vec![Scope::Equipment(1)]),
			write: Permission::Write(vec![Scope::Equipment(1)])
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ(person[1])|WRITE(person[1])")),
		Ok(Permissions::ReadWrite {
			read: Permission::Read(vec![Scope::Person(1)]),
			write: Permission::Write(vec![Scope::Person(1)])
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ(*)|WRITE(id[1],equipment[5],person[7])")),
		Ok(Permissions::ReadWrite {
			read: Permission::ReadAny,
			write: Permission::Write(vec![Scope::Id(1), Scope::Equipment(5), Scope::Person(7)]),
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
		Permission::parse(String::from("READ(id[1],id[2],id[4564],id[789])|WRITE(id[1],id[2],id[3],id[4])")),
		Ok(Permissions::ReadWrite {
			read: Permission::Read(vec![
				Scope::Id(1),
				Scope::Id(2),
				Scope::Id(4564),
				Scope::Id(789),
				Scope::Id(3),
				Scope::Id(4)
			]),
			write: Permission::Write(vec![Scope::Id(1), Scope::Id(2), Scope::Id(3), Scope::Id(4)])
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ(id[5], id[99], id[0]) | WRITE(id[5], id[99]   , id[0] )")),
		Ok(Permissions::ReadWrite {
			read: Permission::Read(vec![Scope::Id(5), Scope::Id(99), Scope::Id(0)]),
			write: Permission::Write(vec![Scope::Id(5), Scope::Id(99), Scope::Id(0)])
		})
	);

	assert_eq!(
		Permission::parse(String::from("READ(id[1],id[2])|WRITE(id[1],id[2],id[3])")),
		Ok(Permissions::ReadWrite {
			read: Permission::Read(vec![Scope::Id(1), Scope::Id(2), Scope::Id(3)]),
			write: Permission::Write(vec![Scope::Id(1), Scope::Id(2), Scope::Id(3)])
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ(id[1],id[2],id[3])|WRITE(id[1],id[2])")),
		Ok(Permissions::ReadWrite {
			read: Permission::Read(vec![Scope::Id(1), Scope::Id(2), Scope::Id(3)]),
			write: Permission::Write(vec![Scope::Id(1), Scope::Id(2)])
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ(*)|WRITE(id[1],id[2])")),
		Ok(Permissions::ReadWrite {
			read: Permission::ReadAny,
			write: Permission::Write(vec![Scope::Id(1), Scope::Id(2)])
		})
	);
	assert_eq!(
		Permission::parse(String::from("READ(id[1],id[2])|WRITE(*)")),
		Ok(Permissions::ReadWrite {
			read: Permission::ReadAny,
			write: Permission::WriteAny
		})
	);

	assert_eq!(Permission::parse(String::from("READ||WRITE(id[1])")), Err("Invalid permission string (No scope found)"));
	assert_eq!(Permission::parse(String::from("READ(id[1])||WRITE")), Err("Invalid permission string (No scope found)"));
	assert_eq!(Permission::parse(String::from("READ(id[1])")), Err("Invalid permission string (No action/scope found)"));
	assert_eq!(Permission::parse(String::from("WRITE(id[1])")), Err("Invalid permission string (No action/scope found)"));
	assert_eq!(Permission::parse(String::from("READ(||WRITE(id[1])")), Err("Invalid permission string (Missing id)"));
	assert_eq!(Permission::parse(String::from("READ()|WRITE(id[1])")), Err("Invalid permission string (Missing id)"));
	assert_eq!(Permission::parse(String::from("READ(id)|WRITE(id[1])")), Err("Invalid permission string (Missing id)"));
	assert_eq!(Permission::parse(String::from("READ(id[)|WRITE(id[1])")), Err("Invalid permission string (Missing id)"));
	assert_eq!(
		Permission::parse(String::from("READ(id[5])|WRITE(id[1],*)")),
		Err("Invalid permission string (Missing id)")
	);
	assert_eq!(
		Permission::parse(String::from("READ(id[])|WRITE(id[1])")),
		Err("Invalid permission string (Could not parse id)")
	);
	assert_eq!(
		Permission::parse(String::from("READ(id[1],id[2],id[x],id[4])|WRITE(id[1])")),
		Err("Invalid permission string (Could not parse id)")
	);
	assert_eq!(
		Permission::parse(String::from("FOO(id[1],id[2],id[3])|WRITE(id[1])")),
		Err("Invalid permission string (Unrecognized action)")
	);
	assert_eq!(
		Permission::parse(String::from("READ(id[1],x[2],id[3])|WRITE(id[1])")),
		Err("Invalid permission string (Unrecognized scope)")
	);
}

#[test]
fn get_query_text() {
	assert_eq!(
		Permission::Read(vec![Scope::Id(1), Scope::Id(2), Scope::Id(3)]).get_query(),
		String::from(" WHERE id IN (1,2,3)")
	);
	assert_eq!(
		Permission::Read(vec![Scope::Equipment(1), Scope::Equipment(2), Scope::Equipment(3)]).get_query(),
		String::from(" WHERE equipment IN (1,2,3)")
	);
	assert_eq!(
		Permission::Read(vec![Scope::Person(1), Scope::Person(2), Scope::Person(3)]).get_query(),
		String::from(" WHERE person IN (1,2,3)")
	);

	assert_eq!(
		Permission::Read(vec![Scope::Id(1), Scope::Id(2), Scope::Equipment(666), Scope::Equipment(42)]).get_query(),
		String::from(" WHERE id IN (1,2) AND equipment IN (666,42)")
	);

	assert_eq!(
		Permission::Read(vec![Scope::Id(1), Scope::Id(2), Scope::Person(666), Scope::Person(42)]).get_query(),
		String::from(" WHERE id IN (1,2) AND person IN (666,42)")
	);

	assert_eq!(
		Permission::Read(vec![Scope::Person(1), Scope::Id(1), Scope::Equipment(1),]).get_query(),
		String::from(" WHERE id IN (1) AND equipment IN (1) AND person IN (1)")
	);
	assert_eq!(
		Permission::Read(vec![
			Scope::Person(1),
			Scope::Id(1),
			Scope::Equipment(1),
			Scope::Id(2),
			Scope::Person(2),
			Scope::Equipment(2)
		])
		.get_query(),
		String::from(" WHERE id IN (1,2) AND equipment IN (1,2) AND person IN (1,2)")
	);
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permissions {
	ReadWrite { read: Permission, write: Permission },
}
