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
ALTER TABLE tokens
  DROP CONSTRAINT tokens_organization_id_organizations_id_foreign;

-- Root
ALTER TABLE users
  ALTER COLUMN id TYPE text,
  ALTER COLUMN id DROP DEFAULT;
ALTER TABLE organizations
  ALTER COLUMN id TYPE text,
  ALTER COLUMN id DROP DEFAULT;

-- Organizations
ALTER TABLE organizations
  ALTER COLUMN user_id TYPE text;
ALTER TABLE organizations_users
  ALTER COLUMN user_id TYPE text,
  ALTER COLUMN user_id DROP DEFAULT;
ALTER TABLE organizations_users
  ALTER COLUMN organization_id TYPE text,
  ALTER COLUMN organization_id DROP DEFAULT;

-- Applications
ALTER TABLE applications
  ALTER COLUMN user_id TYPE text;
ALTER TABLE applications
  ALTER COLUMN organization_id TYPE text;
ALTER TABLE kyc_applications
  ALTER COLUMN user_id TYPE text;
ALTER TABLE applications_users
  ALTER COLUMN user_id TYPE text,
  ALTER COLUMN user_id DROP DEFAULT;
ALTER TABLE applications_organizations
  ALTER COLUMN organization_id TYPE text,
  ALTER COLUMN organization_id DROP DEFAULT;

-- Tokens
ALTER TABLE tokens
  ALTER COLUMN user_id TYPE text;
ALTER TABLE tokens
  ALTER COLUMN organization_id TYPE text;

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
ALTER TABLE tokens
  ADD CONSTRAINT tokens_organization_id_organizations_id_foreign
  FOREIGN KEY (organization_id) REFERENCES organizations(id)
  ON UPDATE CASCADE ON DELETE SET NULL;
