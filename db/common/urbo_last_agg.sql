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

-- Create a function that always returns the last non-NULL item
CREATE OR REPLACE FUNCTION public.last_agg ( anyelement, anyelement )
RETURNS anyelement LANGUAGE SQL IMMUTABLE STRICT AS $$
      SELECT $2;
$$;

-- And then wrap an aggregate around it
CREATE AGGREGATE public.LAST (
      sfunc    = public.last_agg,
      basetype = anyelement,
      stype    = anyelement);
