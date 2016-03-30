'use strict';

require('co-mocha');
var chai = require('chai');
var expect = chai.expect;
var request = require("co-request");

describe('jwt server auth', () => {
    var token;
    var email = `${Date.now()}@email.com`;
    var password = 'Passw0rd';

    it('can register and return a token', function *() {
        var loginResult = yield request({
            method: 'POST',
            url: 'http://localhost:3333/auth/register',
            body: {
                'email': email,
                'password': password
            },
            json: true,
            resolveWithFullResponse: true
        });

        token  = loginResult.body.token;

        expect(loginResult.statusCode).to.equal(200);
        expect(token).to.not.be.empty;
    });

    it('should login and return a token', function *() {
        var loginResult = yield request({
            method: 'POST',
            url: 'http://localhost:3333/auth/login',
            body: {
                'email': email,
                'password': password
            },
            json: true,
            resolveWithFullResponse: true
        });

        token  = loginResult.body.token;

        expect(loginResult.statusCode).to.equal(200);
        expect(token).to.not.be.empty;
    });

    it('should be able to access secure endpoint with token', function* () {
        var secureResult = yield request({
            method: 'GET',
            url: 'http://localhost:3333/api/hello',
            headers: {
                'Authorization': `${token}`
            },
            json: true,
            resolveWithFullResponse: true
        });

        expect(secureResult.statusCode).to.equal(200);
        expect(secureResult.body).to.equal(`hello ${ email }`);
    });

    it('should not be able to access secure endpoint with invalid token', function* () {
        var secureResult = yield request({
            method: 'GET',
            url: 'http://localhost:3333/api/hello',
            headers: {
                'Authorization': `not a token`
            },
            json: true,
            resolveWithFullResponse: true
        });

        expect(secureResult.statusCode).to.equal(401);
    })
});