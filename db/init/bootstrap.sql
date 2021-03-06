--
-- Copyright 2018 Telefónica Digital España S.L.
--
-- This file is part of UrboCore API.
--
-- UrboCore API is free software: you can redistribute it and/or
-- modify it under the terms of the GNU Affero General Public License as
-- published by the Free Software Foundation, either version 3 of the
-- License, or (at your option) any later version.
--
-- UrboCore API is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero
-- General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with UrboCore API. If not, see http://www.gnu.org/licenses/.
--
-- For those usages not covered by this license please contact with
-- iot_support at tid dot es
--

-- Set the following parameters according to your needs
---------------------------------------

-- Database config
\set dbname `echo "${URBO_DB_NAME:-urbo}"`
\set password `echo "${URBO_DB_PASSWD:-urbo}"`
\set owner `echo "${URBO_DB_OWNER:-urbo_admin}"`

-- API login for the superuser
\set admin_email `echo "${URBO_ADMIN_EMAIL:-example@geographica.gs}"`
\set admin_pwd `echo "${URBO_ADMIN_PASSWD:-admin}"`
\set guest_email `echo "${URBO_GUEST_EMAIL:-guest@guest.com}"`
\set guest_pwd `echo "${URBO_GUEST_PASSWD:-guest}"`
---------------------------------------

-- Database initialization
CREATE USER :owner WITH PASSWORD :'password';
CREATE DATABASE :dbname WITH OWNER :owner;

-- Connection to new database as admin
\c :dbname

-- Adding necessary pgsql extensions
CREATE EXTENSION postgis;
CREATE EXTENSION intarray;

-- Set up base schemas and tables
\ir ddl/urbo_init_public.sql
\ir ddl/urbo_init_metadata.sql
\ir ddl/urbo_init_logs.sql

-- Create superuser users in DB and API
\ir dml/urbo_init_admin.sql
