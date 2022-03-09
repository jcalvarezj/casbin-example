# Casbin Example

This is a short example of authorization validation through middleware using Casbin policies. A local MySQL database is expected to be running, where the policies table is located and it is called *casbin_rule_test*

To test, set the following environment variables:

- **CE_DB_NAME** (the name of the test database)
- **CE_DB_PORT** (the port of connection)
- **CE_DB_USER** (the user to access the database)
- **CE_DB_PASS** (the password to access the database)

This server responds to requests on the following resources:

- **/ [GET]** for roles "admin" and "treasury"

- **/free-resource [GET]** for anyone (not enforcing auth.)

- **/foo/bar [GET]** for roles "admin", "treasury", and "lawyer"

- **/foo/bar [POST]** for roles "admin" and "lawyer"

- **/foo/bar [PUT]** for roles "admin" and "treasury"

- **/foo/bar [PATCH]** for roles "admin" and "treasury"

Finally, to send a role in the request use the "Role" header with the name of the role to test (implemented like that just for testing quickly)

Example:

```curl -X POST -H "Role: admin" localhost:8080/foo/bar```