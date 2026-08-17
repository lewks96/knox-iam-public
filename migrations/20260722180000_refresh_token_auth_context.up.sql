-- Carry the authentication event through refresh-token rotation.
--
-- `amr`/`acr`/`auth_time` describe how the user proved who they are, which
-- happens once per session — but an access token is reissued every hour from
-- the refresh token, which knew nothing about it. Without these columns those
-- claims would vanish at the first refresh, leaving a resource server unable to
-- distinguish a refreshed multi-factor session from a single-factor one.
--
-- Both nullable/defaulted: rows predating this migration describe logins whose
-- methods were never recorded, and an empty `amr` says exactly that.
ALTER TABLE refresh_tokens
    ADD COLUMN amr TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN auth_time TIMESTAMPTZ;
