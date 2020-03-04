ALTER TABLE ONLY users ADD COLUMN first_name varchar(64);
ALTER TABLE ONLY users ADD COLUMN last_name varchar(64);

UPDATE users SET first_name=userquery.first_name, last_name=userquery.last_name FROM (SELECT split_part(name, ' ', 1) AS first_name, split_part(name, ' ', 2) as last_name from users) AS userquery;
UPDATE users SET last_name=first_name WHERE users.last_name = '';

ALTER TABLE ONLY users ALTER COLUMN first_name SET NOT NULL;
ALTER TABLE ONLY users ALTER COLUMN last_name SET NOT NULL;
