-- Organizations
ALTER TABLE organizations
  DROP CONSTRAINT organizations_user_id_users_id_foreign;
ALTER TABLE organizations_users
  DROP CONSTRAINT organizations_user_id_users_id_foreign;
ALTER TABLE organizations_users
  DROP CONSTRAINT organizations_organization_id_organizations_id_foreign;

-- Applications
ALTER TABLE applications
  DROP CONSTRAINT applications_user_id_users_id_foreign;
ALTER TABLE applications
  DROP CONSTRAINT applications_organization_id_organizations_id_foreign;
ALTER TABLE kyc_applications
  DROP CONSTRAINT kyc_applications_user_id_users_id_foreign;
ALTER TABLE applications_users
  DROP CONSTRAINT applications_user_id_users_id_foreign;
ALTER TABLE applications_organizations
  DROP CONSTRAINT applications_organization_id_organizations_id_foreign;

-- Tokens
ALTER TABLE tokens
  DROP CONSTRAINT tokens_user_id_users_id_foreign;

-- Root
ALTER TABLE users
  ALTER COLUMN id TYPE uuid,
  ALTER COLUMN id SET DEFAULT public.uuid_generate_v4();

ALTER TABLE organizations
  ALTER COLUMN id TYPE uuid,
  ALTER COLUMN id SET DEFAULT public.uuid_generate_v4();

-- Organizations
ALTER TABLE organizations
  ALTER COLUMN user_id TYPE uuid;
ALTER TABLE organizations_users
  ALTER COLUMN user_id TYPE uuid,
  ALTER COLUMN user_id SET DEFAULT public.uuid_generate_v4();
ALTER TABLE organizations_users
  ALTER COLUMN organization_id TYPE uuid,
  ALTER COLUMN organization_id SET DEFAULT public.uuid_generate_v4();

-- Applications
ALTER TABLE applications
  ALTER COLUMN user_id TYPE uuid;
ALTER TABLE applications
  ALTER COLUMN organization_id TYPE uuid;
ALTER TABLE kyc_applications
  ALTER COLUMN user_id TYPE uuid;
ALTER TABLE applications_users
  ALTER COLUMN user_id TYPE uuid,
  ALTER COLUMN user_id SET DEFAULT public.uuid_generate_v4();
ALTER TABLE applications_organizations
  ALTER COLUMN organization_id TYPE uuid,
  ALTER COLUMN organization_id SET DEFAULT public.uuid_generate_v4();

-- Tokens
ALTER TABLE tokens
  ALTER COLUMN user_id TYPE uuid;

-- Organizations
ALTER TABLE organizations
  ADD CONSTRAINT organizations_user_id_users_id_foreign
  FOREIGN KEY (user_id) REFERENCES users(id)
  ON UPDATE CASCADE ON DELETE SET NULL;
ALTER TABLE organizations_users
  ADD CONSTRAINT organizations_user_id_users_id_foreign
  FOREIGN KEY (user_id) REFERENCES users(id)
  ON UPDATE CASCADE ON DELETE SET NULL;
ALTER TABLE organizations_users
  ADD CONSTRAINT organizations_organization_id_organizations_id_foreign
  FOREIGN KEY (organization_id) REFERENCES organizations(id)
  ON UPDATE CASCADE ON DELETE SET NULL;

-- Applications
ALTER TABLE applications
  ADD CONSTRAINT applications_user_id_users_id_foreign
  FOREIGN KEY (user_id) REFERENCES users(id)
  ON UPDATE CASCADE ON DELETE SET NULL;
ALTER TABLE applications
  ADD CONSTRAINT applications_organization_id_organizations_id_foreign
  FOREIGN KEY (organization_id) REFERENCES organizations(id)
  ON UPDATE CASCADE ON DELETE SET NULL;
ALTER TABLE kyc_applications
  ADD CONSTRAINT kyc_applications_user_id_users_id_foreign
  FOREIGN KEY (user_id) REFERENCES users(id)
  ON UPDATE CASCADE ON DELETE SET NULL;
ALTER TABLE applications_users
  ADD CONSTRAINT applications_user_id_users_id_foreign
  FOREIGN KEY (user_id) REFERENCES users(id)
  ON UPDATE CASCADE ON DELETE SET NULL;
ALTER TABLE applications_organizations
  ADD CONSTRAINT applications_organization_id_organizations_id_foreign
  FOREIGN KEY (organization_id) REFERENCES organizations(id)
  ON UPDATE CASCADE ON DELETE SET NULL;

-- Tokens
ALTER TABLE tokens
  ADD CONSTRAINT tokens_user_id_users_id_foreign
  FOREIGN KEY (user_id) REFERENCES users(id)
  ON UPDATE CASCADE ON DELETE SET NULL;
