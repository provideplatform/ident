-- organizations

CREATE TABLE organizations (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    user_id uuid,
    name text NOT NULL,
    description text,
    permissions integer NOT NULL DEFAULT 0
);

ALTER TABLE ONLY organizations ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);

CREATE INDEX idx_organizations_user_id ON organizations USING btree (user_id);
ALTER TABLE ONLY organizations ADD CONSTRAINT organizations_user_id_users_id_foreign FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE SET NULL;

-- applications_organizations join table

CREATE TABLE applications_organizations (
    application_id uuid DEFAULT uuid_generate_v4() NOT NULL,
    organization_id uuid DEFAULT uuid_generate_v4() NOT NULL,
    permissions integer DEFAULT 0 NOT NULL
);

ALTER TABLE ONLY applications_organizations ADD CONSTRAINT applications_organizations_pkey PRIMARY KEY (application_id, organization_id);
ALTER TABLE ONLY applications_organizations ADD CONSTRAINT applications_application_id_applications_id_foreign FOREIGN KEY (application_id) REFERENCES applications(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE ONLY applications_organizations ADD CONSTRAINT applications_organization_id_organizations_id_foreign FOREIGN KEY (organization_id) REFERENCES organizations(id) ON UPDATE CASCADE ON DELETE CASCADE;


-- organizations_users join table

CREATE TABLE organizations_users (
    organization_id uuid DEFAULT uuid_generate_v4() NOT NULL,
    user_id uuid DEFAULT uuid_generate_v4() NOT NULL,
    permissions integer DEFAULT 0 NOT NULL
);

ALTER TABLE ONLY organizations_users ADD CONSTRAINT organizations_users_pkey PRIMARY KEY (organization_id, user_id);
ALTER TABLE ONLY organizations_users ADD CONSTRAINT organizations_organization_id_organizations_id_foreign FOREIGN KEY (organization_id) REFERENCES organizations(id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE ONLY organizations_users ADD CONSTRAINT organizations_user_id_users_id_foreign FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE;
