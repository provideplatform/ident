UPDATE users SET first_name=userquery.first_name, last_name=userquery.last_name FROM (SELECT id, split_part(name, ' ', 1) AS first_name, split_part(name, ' ', 2) as last_name from users) AS userquery WHERE users.id=userquery.id;
ALTER TABLE ONLY users DROP COLUMN name;
