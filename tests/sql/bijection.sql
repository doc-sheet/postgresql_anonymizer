BEGIN;

CREATE EXTENSION IF NOT EXISTS anon CASCADE;

-- Strict mode checks

SELECT anon.bijection(NULL,NULL) IS NULL;
SELECT anon.bijection(0,NULL) IS NULL;
SELECT anon.bijection(NULL,0) IS NULL;
SELECT anon.bijection_id(NULL) IS NULL;
SELECT anon.luhn_append(NULL) IS NULL;
SELECT anon.bijection_siret(NULL) IS NULL;

-- Using the secret param

SELECT anon.bijection(123456789,111111111) = 234567890;

SELECT anon.bijection(48324786,78435973) = 16759659;

SELECT anon.bijection_id('483-247-86',78435973) = '167-596-59';

SELECT anon.luhn_append(16759659) = 167596592;

SELECT anon.bijection_siret('483 247 862',78435973) = '167596592';

-- Using the bijection_secret GUC

SET anon.bijection_secret TO '78435973';

SELECT anon.bijection(48324786) = 16759659;

SELECT anon.bijection_id('483-247-86',78435973) = '167-596-59';

SELECT anon.bijection_siret('483 247 862') = '167596592';

-- Masking a Foreign Key

CREATE TABLE people (
  ssn TEXT PRIMARY KEY,
  name TEXT
);

CREATE TABLE driver_license (
  id SERIAL,
  driver_ssn TEXT,
  plate_number TEXT,
  CONSTRAINT fk_ssn FOREIGN KEY(driver_ssn) REFERENCES people(ssn) DEFERRABLE
);

INSERT INTO people
  VALUES ('179-05-726', 'Adam Driver');

INSERT INTO driver_license(driver_ssn, plate_number)
  VALUES ('179-05-726', 'K1L0 R3N');

SELECT * FROM people;

SELECT * FROM driver_license;

SET anon.bijective_secret TO '357835675';

SECURITY LABEL FOR anon ON COLUMN people.name
  IS 'MASKED WITH VALUE $$CONFIDENTIAL$$';

SECURITY LABEL FOR anon ON COLUMN people.ssn
  IS 'MASKED WITH FUNCTION anon.bijection_id(ssn)';

SECURITY LABEL FOR anon ON COLUMN driver_license.driver_ssn
  IS 'MASKED WITH FUNCTION anon.bijection_id(driver_ssn)';

SELECT anon.anonymize_database();

SELECT * FROM people;

SELECT * FROM driver_license;

ROLLBACK;
