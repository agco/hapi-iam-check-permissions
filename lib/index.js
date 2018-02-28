/* eslint-disable no-console */
const Boom = require('boom');
const _ = require('lodash');
const url = require('url');
const request = require('request-promise');
const { name, version } = require('../package.json');

const register = (server, options = {}) => {
  let disabled;
  const { evaluatePermissionsUrl, permissionsToSkip } = options;
  const parsedEvaluatePermissionsUrl = url.parse(evaluatePermissionsUrl);

  const openRoutes = {};
  if (Array.isArray(permissionsToSkip)) {
    permissionsToSkip.forEach((permission) => {
      openRoutes[permission] = true;
    });
  }

  const localIamCall = async (payload, authorization) => {
    await server.start();
    const res = await server.inject({
      url: evaluatePermissionsUrl, method: 'POST', payload, headers: { authorization }
    });
    if (res.statusCode !== 200) {
      console.error('Error evaluate local permissions', res.statusCode, res.payload);
      throw Boom.internal();
    }
    return res.result.permitted;
  };

  const remoteIamCall = async (body, authorization) => {
    try {
      const result = await request({
        method: 'POST',
        uri: evaluatePermissionsUrl,
        body,
        json: true,
        headers: { authorization }
      });
      return result.permitted;
    } catch (err) {
      console.error('Error evaluate remote permissions', err.message || err);
      throw Boom.internal();
    }
  };

  const evaluatePermissions = async (req, applicationId, agcoUuid, permission) => {
    const isLocal = !parsedEvaluatePermissionsUrl.protocol;
    const body = { appId: applicationId, agcoUuid, name: permission };
    const { authorization } = req.headers;
    let permitted;
    if (isLocal) {
      permitted = await localIamCall(body, authorization);
    } else {
      permitted = await remoteIamCall(body, authorization);
    }

    if (permitted) {
      return true;
    }
    throw Boom.forbidden();
  };

  server.ext('onPostAuth', async (req, h) => {
    const isAuthenticated = _.get(req, 'auth.isAuthenticated');
    if (disabled || !isAuthenticated || parsedEvaluatePermissionsUrl.path === req.route.path) {
      return h.continue;
    }
    const path = req.route.path.replace(/^\//, '').replace(/\//g, '.').replace(/({[^}]*})/g, '*');
    const permission = `${path}.${req.method}`;

    if (openRoutes[permission]) {
      return h.continue;
    }

    await evaluatePermissions(req, options.applicationId, _.get(req, 'auth.credentials.sub'), permission);
    return h.continue;
  });

  server.expose('disable', () => {
    disabled = true;
  });
};

module.exports = { register, name, version };
