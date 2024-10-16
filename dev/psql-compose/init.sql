-- init.sql
CREATE TABLE user_permissions (
    user_id  INTEGER NOT NULL,
    token    TEXT NOT NULL
);

CREATE TABLE users (
  id         INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  username   TEXT NOT NULL UNIQUE,
  password   TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO users (username, password) VALUES ('dom', 'x'), ('josh', 'xx');

CREATE TABLE todos (
  id         INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT NOT NULL,
  completed  BOOLEAN,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO todos (user_id, title, completed) VALUES (1, 'Something to do!', false), (2, 'Last thing!', false);
