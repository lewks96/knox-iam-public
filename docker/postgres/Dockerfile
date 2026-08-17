FROM postgres:16

# Install pg_cron — the extension that drives refresh-token pruning
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-16-cron \
    && rm -rf /var/lib/apt/lists/*

# Bake the pg_cron preload config directly into the image so no runtime
# `command:` override is needed.  PostgreSQL reads *.conf files from
# /etc/postgresql/conf.d/ automatically when include_dir is set, but the
# simplest portable approach is a snippet in /etc/postgresql/postgresql.conf.d/
# which postgres:16 already includes via `$POSTGRES_EXTRA_CONFIG`.
#
# We use the officially-supported conf override directory instead:
COPY pg_cron.conf /etc/postgresql/conf.d/pg_cron.conf

# Make sure Postgres loads conf.d (safe — this file is otherwise empty)
RUN echo "include_dir = '/etc/postgresql/conf.d'" >> /usr/share/postgresql/postgresql.conf.sample
