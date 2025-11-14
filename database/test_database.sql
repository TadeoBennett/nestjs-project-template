-- public.users definition

-- Drop table
-- DROP TABLE public.users;

CREATE TYPE public.role_enum AS ENUM ('admin', 'user');

CREATE TABLE public.users (
	id serial4 NOT NULL,
	username varchar(50) NOT NULL,
	"password" varchar(255) NOT NULL,
	"role" public."role_enum" DEFAULT 'user'::role_enum NOT NULL,
	phone varchar(20) NULL,
	CONSTRAINT users_pkey PRIMARY KEY (id),
	CONSTRAINT users_username_key UNIQUE (username)
);


-- public.user_sessions definition

-- Drop table
-- DROP TABLE public.user_sessions;

CREATE TABLE public.user_sessions (
	id serial4 NOT NULL,
	user_id int4 NULL,
	refresh_token varchar(512) NOT NULL,
	expires_at timestamp NOT NULL,
	created_at timestamp DEFAULT now() NULL,
	ip_address varchar(45) NULL,
	user_agent text NULL,
	revoked bool DEFAULT false NULL,
	CONSTRAINT user_sessions_pkey PRIMARY KEY (id)
);

-- public.user_sessions foreign keys
ALTER TABLE public.user_sessions ADD CONSTRAINT user_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

TRUNCATE TABLE users RESTART identity CASCADE;
TRUNCATE TABLE user_sessions RESTART IDENTITY;
