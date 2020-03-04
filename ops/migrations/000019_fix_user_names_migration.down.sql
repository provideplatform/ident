ALTER TABLE ONLY users ADD COLUMN name varchar(128);
UPDATE users SET name=userquery.name FROM (SELECT id, concat_ws(' ', first_name, last_name) as name FROM users) AS userquery WHERE id=userquery.id;
ALTER TABLE ONLY users ALTER COLUMN name SET NOT NULL;
