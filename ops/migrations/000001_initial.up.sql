--
-- PostgreSQL database dump
--

-- Dumped from database version 10.6
-- Dumped by pg_dump version 10.11 (Ubuntu 10.11-1.pgdg16.04+1)

-- The following portion of the pg_dump output should not run during migrations:
-- SET statement_timeout = 0;
-- SET lock_timeout = 0;
-- SET idle_in_transaction_session_timeout = 0;
-- SET client_encoding = 'UTF8';
-- SET standard_conforming_strings = on;
-- SELECT pg_catalog.set_config('search_path', '', false);
-- SET check_function_bodies = false;
-- SET xmloption = content;
-- SET client_min_messages = warning;
-- SET row_security = off;

DO
$do$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE  rolname = 'ident') THEN
      CREATE ROLE ident WITH SUPERUSER LOGIN PASSWORD 'prvdident';
   END IF;
END
$do$;

SET ROLE ident;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


ALTER USER current_user WITH NOSUPERUSER;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: applications; Type: TABLE; Schema: public; Owner: ident
--

CREATE TABLE public.applications (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    config json,
    hidden boolean DEFAULT false NOT NULL,
    network_id uuid NOT NULL,
    encrypted_config bytea
);


ALTER TABLE public.applications OWNER TO ident;

--
-- Name: kyc_applications; Type: TABLE; Schema: public; Owner: ident
--

CREATE TABLE public.kyc_applications (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    user_id uuid NOT NULL,
    provider text NOT NULL,
    identifier text,
    type text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    encrypted_params bytea,
    application_id uuid,
    description text,
    name text,
    pii_hash text,
    id_number text
);


ALTER TABLE public.kyc_applications OWNER TO ident;

--
-- Name: tokens; Type: TABLE; Schema: public; Owner: ident
--

CREATE TABLE public.tokens (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    token text,
    application_id uuid,
    user_id uuid
);


ALTER TABLE public.tokens OWNER TO ident;

--
-- Name: users; Type: TABLE; Schema: public; Owner: ident
--

CREATE TABLE public.users (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    application_id uuid,
    name text NOT NULL,
    email text NOT NULL,
    password text,
    privacy_policy_agreed_at timestamp with time zone,
    terms_of_service_agreed_at timestamp with time zone,
    reset_password_token text
);


ALTER TABLE public.users OWNER TO ident;

--
-- Name: applications applications_pkey; Type: CONSTRAINT; Schema: public; Owner: ident
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_pkey PRIMARY KEY (id);


--
-- Name: kyc_applications kyc_applications_pkey; Type: CONSTRAINT; Schema: public; Owner: ident
--

ALTER TABLE ONLY public.kyc_applications
    ADD CONSTRAINT kyc_applications_pkey PRIMARY KEY (id);


--
-- Name: tokens tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: ident
--

ALTER TABLE ONLY public.tokens
    ADD CONSTRAINT tokens_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: ident
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: idx_applications_hidden; Type: INDEX; Schema: public; Owner: ident
--

CREATE INDEX idx_applications_hidden ON public.applications USING btree (hidden);


--
-- Name: idx_applications_network_id; Type: INDEX; Schema: public; Owner: ident
--

CREATE INDEX idx_applications_network_id ON public.applications USING btree (network_id);


--
-- Name: idx_kyc_applications_application_id; Type: INDEX; Schema: public; Owner: ident
--

CREATE INDEX idx_kyc_applications_application_id ON public.kyc_applications USING btree (application_id);


--
-- Name: idx_kyc_applications_id_number; Type: INDEX; Schema: public; Owner: ident
--

CREATE INDEX idx_kyc_applications_id_number ON public.kyc_applications USING btree (id_number);


--
-- Name: idx_kyc_applications_identifier; Type: INDEX; Schema: public; Owner: ident
--

CREATE INDEX idx_kyc_applications_identifier ON public.kyc_applications USING btree (identifier);


--
-- Name: idx_kyc_applications_pii_hash; Type: INDEX; Schema: public; Owner: ident
--

CREATE INDEX idx_kyc_applications_pii_hash ON public.kyc_applications USING btree (pii_hash);


--
-- Name: idx_kyc_applications_status; Type: INDEX; Schema: public; Owner: ident
--

CREATE INDEX idx_kyc_applications_status ON public.kyc_applications USING btree (status);


--
-- Name: idx_kyc_applications_user_id; Type: INDEX; Schema: public; Owner: ident
--

CREATE INDEX idx_kyc_applications_user_id ON public.kyc_applications USING btree (user_id);


--
-- Name: idx_tokens_token; Type: INDEX; Schema: public; Owner: ident
--

CREATE INDEX idx_tokens_token ON public.tokens USING btree (token);


--
-- Name: idx_users_application_id; Type: INDEX; Schema: public; Owner: ident
--

CREATE INDEX idx_users_application_id ON public.users USING btree (application_id);


--
-- Name: idx_users_application_id_email; Type: INDEX; Schema: public; Owner: ident
--

CREATE UNIQUE INDEX idx_users_application_id_email ON public.users USING btree (application_id, email);


--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: ident
--

CREATE INDEX idx_users_email ON public.users USING btree (email);


--
-- Name: idx_users_email_null_application_id; Type: INDEX; Schema: public; Owner: ident
--

CREATE UNIQUE INDEX idx_users_email_null_application_id ON public.users USING btree (application_id, email) WHERE (application_id IS NULL);


--
-- Name: applications applications_user_id_users_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: ident
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_user_id_users_id_foreign FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: kyc_applications kyc_applications_user_id_users_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: ident
--

ALTER TABLE ONLY public.kyc_applications
    ADD CONSTRAINT kyc_applications_user_id_users_id_foreign FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: tokens tokens_application_id_applications_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: ident
--

ALTER TABLE ONLY public.tokens
    ADD CONSTRAINT tokens_application_id_applications_id_foreign FOREIGN KEY (application_id) REFERENCES public.applications(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: tokens tokens_user_id_users_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: ident
--

ALTER TABLE ONLY public.tokens
    ADD CONSTRAINT tokens_user_id_users_id_foreign FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: users users_application_id_applications_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: ident
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_application_id_applications_id_foreign FOREIGN KEY (application_id) REFERENCES public.applications(id) ON UPDATE CASCADE ON DELETE SET NULL;

--
-- PostgreSQL database dump complete
--
