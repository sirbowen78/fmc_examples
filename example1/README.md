Reference: https://cyruslab.net/2020/02/27/pythoncisco-fmc-rest-api-example-get-server-version-and-add-device-to-cisco-fmc/
You can read the full documentation of the codes in above link.

The examples here do four things:
1. Generate access token,
2. Get server version,
3. Get AccessPolicy ID,
4. Add device to Cisco FMC using POST method.

For POST method, always test the json body in the /api/api-explorer before deploying to the code api-explorer helps to verify if the json body is accepted by the Cisco FMC server or not.
