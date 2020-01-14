-- applications_ join table

CREATE TABLE applications_users (
    application_id uuid DEFAULT uuid_generate_v4() NOT NULL,
    user_id uuid DEFAULT uuid_generate_v4() NOT NULL,
    permissions integer DEFAULT 0 NOT NULL
);

ALTER TABLE ONLY applications_users ADD CONSTRAINT applications_users_pkey PRIMARY KEY (application_id, user_id);
ALTER TABLE ONLY applications_users ADD CONSTRAINT applications_application_id_applications_id_foreign FOREIGN KEY (application_id) REFERENCES applications(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE ONLY applications_users ADD CONSTRAINT applications_user_id_users_id_foreign FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE;
