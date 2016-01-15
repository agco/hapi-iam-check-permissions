'use strict'

const Hapi = require('hapi')
const expect = require('chai').expect

describe('hapi-iam-check-permissions', function () {

    let app1
    const app1Port = 8001

    function setupApp(appId, port, evaluatePermissionsUrl) {
        return new Promise((resolve) => {
            const plugins = [
                {register: require('hapi-auth-basic')},
                {register: require('../lib/index'), options: {applicationId: appId, evaluatePermissionsUrl: evaluatePermissionsUrl}},
                {register: require('inject-then')}
            ]
            var server = new Hapi.Server()
            server.connection({port: port})
            server.register(plugins, () => {
                server.auth.strategy('basic', 'basic', {
                    validateFunc: function (req, user, password, next) {
                        if (('user' === user || 'admin' === user) && 'password' === password) {
                            next(null, true, {sub: user, password: password})
                        } else {
                            next(null, false)
                        }
                    }
                })
                server.auth.default({
                    strategies: ['basic']
                })
                server.start(() => {
                    server.route({
                        method: 'get',
                        path: '/hello',
                        handler: (req, reply)=>reply('world')
                    })
                    server.route({
                        method: 'post',
                        path: '/evaluatePermissions',
                        handler: function (req, reply) {
                            reply({permitted: 'app1' === req.payload.appId && 'admin' === req.payload.agcoUuid && 'hello.get' === req.payload.name})
                        }
                    })
                    resolve(server)
                })
            })
        })
    }


    function setupTests(remote) {

        before(function () {
            const evaluatePermissionsUrl = remote ? `http://localhost:${app1Port}/evaluatePermissions` : '/evaluatePermissions'
            return setupApp('app1', app1Port, evaluatePermissionsUrl).then(function (result) {
                app1 = result
            })
        })

        after(function (done) {
            app1.stop(done)
        })

        describe('when user is not authenticated', function () {
            it('should respond with 401', function () {
                return app1.injectThen({url: '/hello'}).then(function (res) {
                    expect(res.statusCode).to.equal(401)
                })
            })
        })

        describe('when user is authenticated', function () {
            describe('and has permission', function () {
                it('should allow accessing the route', function () {
                    return app1.injectThen({url: '/hello', headers: {authorization: 'Basic YWRtaW46cGFzc3dvcmQ='}}).then(function (res) {
                        expect(res.statusCode).to.equal(200)
                        expect(res.payload).to.equal('world')
                    })
                })
            })
            describe('but does not have permission', function () {
                it('should respond with 403', function () {
                    return app1.injectThen({url: '/hello', headers: {authorization: 'Basic dXNlcjpwYXNzd29yZA=='}}).then(function (res) {
                        expect(res.statusCode).to.equal(403)
                    })
                })
            })
        })
    }

    describe('when check mode is set to local', function () {
        setupTests()
    })

    describe('when check mode is set to remote', function () {

        setupTests(true)

        describe('when request to evaluatePermissionUrl fails', function () {

            let app2

            before(function () {
                return setupApp('app2', app1Port + 1, `http://localhost:${app1Port}/unsupported-path`).then(function (result) {
                    app2 = result
                })
            })

            after(function (done) {
                app2.stop(done)
            })

            it('should respond with 500', function () {
                return app2.injectThen({url: '/hello', headers: {authorization: 'Basic YWRtaW46cGFzc3dvcmQ='}}).then(function (res) {
                    expect(res.statusCode).to.equal(500)
                })
            })
        })
    })
})
