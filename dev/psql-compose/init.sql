-- init.sql
CREATE TABLE users (
  id         INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  username   TEXT NOT NULL UNIQUE,
  password   TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO users (username, password) VALUES ('dom', '$2b$12$rgB7bxoyNAjtbGhQHecpHOG83kEipspOvBwmd7KxX0ls9rIHBIkgG'), ('josh', '$2b$12$rgB7bxoyNAjtbGhQHecpHOG83kEipspOvBwmd7KxX0ls9rIHBIkgG');
-- password: test

CREATE TABLE user_permissions (
    user_id  INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token    TEXT NOT NULL
);
INSERT INTO user_permissions (user_id, token) VALUES (1, 'READ'), (1, 'WRITE'), (2, 'READ');

CREATE TABLE todos (
  id         INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT NOT NULL,
  completed  BOOLEAN,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO todos (user_id, title, completed) VALUES (1, 'Something to do!', false), (2, 'Last thing!', false);
