# Hapi IAM Check Permissions

**Note: The `develop` branch and Version 1.x is only compatible with hapi v17 and above.**

## Installation

```
npm i hapi-iam-check-permissions --save
```

### Example usage
```
server = Hapi.Server();
server.connection({ port: 8080 });
await server.register([require('hapi-iam-check-permissions', {
  plugin: hapiIamCheckPermissions,
  options: {
    applicationId: 'appId',
    evaluatePermissionsUrl: 'http://server/evaluatePermissions',
    permissionsToSkip: ['unsecured.get']
  }
}]);
```

### A word about `node` versions.

This was written using async/await and required node version 7.6 or higher.
