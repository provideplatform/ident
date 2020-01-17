CREATE TABLE token_revocations (
    hash character(64) NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone NOT NULL DEFAULT now()
);

ALTER TABLE ONLY token_revocations ADD CONSTRAINT token_revocations_pkey PRIMARY KEY (hash);
