const Hapi = require('hapi');
const hapiAuthBasic = require('hapi-auth-basic');
const Boom = require('boom');
const nock = require('nock');
const hapiIamCheckPermissions = require('../lib/index');
const { expect } = require('chai');

nock.disableNetConnect();
const evaluatePermissionsUrls = {
  endpoint: '/evaluatePermissions',
  host: 'http://iamserver'
};

const setupServer = async (local = false) => {
  const { host, endpoint } = evaluatePermissionsUrls;
  const evaluatePermissionsUrl = local ? endpoint : `${host}${endpoint}`;
  const server = Hapi.server();
  await server.register([hapiAuthBasic, {
    plugin: hapiIamCheckPermissions,
    options: {
      applicationId: 'app',
      evaluatePermissionsUrl,
      permissionsToSkip: ['unsecured.get']
    }
  }]);
  server.auth.strategy('simple', 'basic', {
    validate: (req, username) => {
      if (username === 'user' || username === 'guest' || username === 'error') {
        return { isValid: true, credentials: { sub: username, token: 'token' } };
      }
      return { isValid: false, credentials: {} };
    }
  });
  server.route({
    method: 'get',
    path: '/valid',
    config: { auth: 'simple' },
    handler: () => 'ok'
  });
  server.route({
    method: 'get',
    config: { auth: 'simple' },
    path: '/unsecured',
    handler: () => 'ok'
  });
  server.route({
    method: 'get',
    path: '/public',
    handler: () => 'ok'
  });
  server.route({
    method: 'post',
    path: '/evaluatePermissions',
    config: { auth: 'simple' },
    handler: (req) => {
      if (req.payload.agcoUuid === 'error') {
        throw Boom.badRequest('Something went wrong');
      }
      return { permitted: req.payload.agcoUuid === 'user' };
    }
  });
  return server;
};

const setupNock = (permitted = true, error = false) => {
  const { host, endpoint } = evaluatePermissionsUrls;
  const iamNock = nock(host).post(endpoint, /.*/);
  if (error) {
    iamNock.reply(400, 'Something went wrong');
  } else {
    iamNock.reply(200, { permitted });
  }
};

const runTests = (local = true) => {
  let server;
  let res;

  before(async () => {
    server = await setupServer(local);
  });

  describe('user is not authenticated', () => {
    before(async () => {
      res = await server.inject({ url: '/valid' });
    });

    it('should respond with 401', () => {
      expect(res.statusCode).to.equal(401);
    });
  });

  describe('user is authenticated', () => {
    describe('has permission', () => {
      const authString = Buffer.from('user:user').toString('base64');
      before(async () => {
        if (!local) {
          setupNock(true);
        }
        res = await server.inject({ url: '/valid', headers: { authorization: `Basic ${authString}` } });
      });

      it('allows accessing the route', () => {
        expect(res.statusCode).to.equal(200);
        expect(res.payload).to.equal('ok');
      });
    });

    describe('does not have permission', () => {
      const authString = Buffer.from('guest:guest').toString('base64');
      before(async () => {
        if (!local) {
          setupNock(false);
        }
        res = await server.inject({ url: '/valid', headers: { authorization: `Basic ${authString}` } });
      });
      it('responds with 403', () => {
        expect(res.statusCode).to.equal(403);
      });
    });

    describe('accesses unsecured route', () => {
      const authString = Buffer.from('guest:guest').toString('base64');
      before(async () => {
        res = await server.inject({ url: '/unsecured', headers: { authorization: `Basic ${authString}` } });
      });

      it('should respond with 200', () => {
        expect(res.statusCode).to.equal(200);
        expect(res.payload).to.equal('ok');
      });
    });

    describe('accesses publicly open route', () => {
      before(async () => {
        res = await server.inject({ url: '/public' });
      });

      it('should respond with 200', () => {
        expect(res.statusCode).to.equal(200);
        expect(res.payload).to.equal('ok');
      });
    });

    describe('permissions check has internal error', () => {
      const authString = Buffer.from('error:error').toString('base64');
      before(async () => {
        if (!local) {
          setupNock(false, true);
        }
        res = await server.inject({ url: '/valid', headers: { authorization: `Basic ${authString}` } });
      });
      it('responds with 500', () => {
        expect(res.statusCode).to.equal(500);
      });
    });
  });
};

describe('hapi-iam-check-permissions', () => {
  describe('with local check permissions url', () => {
    runTests(true);
  });

  describe('with remote check permissions url', () => {
    runTests(false);
  });
});
