-- init.sql
CREATE TABLE users (
  id                   INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  username             TEXT NOT NULL UNIQUE,
  password             TEXT NOT NULL,
  created_at           TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  permission_equipment TEXT NOT NULL,
  permission_user      TEXT NOT NULL,
  permission_todo      TEXT NOT NULL
);
INSERT INTO users
  (username, password, permission_equipment, permission_user, permission_todo)
  VALUES
  ('dom', '$argon2id$v=19$m=19456,t=2,p=1$T9GO2wvNWMGcMQ/uPdH8lQ$EjVtyckTRnjly15GvDW3RAo2GvZPT/Dv7prpRDv6YcI', 'READ(*)|WRITE(*)|CREATE(true)', 'READ(*)|WRITE(*)|CREATE(true)', 'READ(equipment[2])|WRITE(equipment[2])|CREATE(true)'),
  ('thewizzy', '$argon2id$v=19$m=19456,t=2,p=1$jGpHvsSseOmqYpSjYmHsDw$C/tnsXIf8dEdGojiKDcYis3e7gniaT40jvqIyFzri4c', 'READ(*)|WRITE(*)|CREATE(true)', 'READ(*)|WRITE(*)|CREATE(true)', 'READ(*)|WRITE(*)|CREATE(true)');
-- password for both: test

CREATE TABLE todos (
  id         INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  person     INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT NOT NULL,
  completed  BOOLEAN,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO todos (person, title, completed) VALUES (1, 'Something to do!', false), (2, 'So much todo', false), (1, 'Last thing!', false);
