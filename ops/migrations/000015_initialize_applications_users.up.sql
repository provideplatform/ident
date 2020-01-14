INSERT INTO applications_users (application_id, user_id) SELECT applications.id, applications.user_id FROM applications;
UPDATE applications_users SET permissions = 510;
