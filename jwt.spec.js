'use strict';

require('co-mocha');

var fs = require('fs');
var chai = require('chai');
var expect = chai.expect;
var jwt = require('jsonwebtoken');
var ms = require('ms');
var moment = require('moment');

describe('jwt auth', () => {
    var now = Math.floor(Date.now() / 1000);
    var oneDayExpiry = 60 * 60 * 24;
    var privateKey = fs.readFileSync('demo.rsa');
    var expectedClaims = {
        iss: 'auth.yoursite.com',
        aud: 'yoursite.com',
        email: 'foo@foo.com',
        exp: now + oneDayExpiry
    };

    it('should return claims with iat added when decrypting a signed token with private key', function *() {
        var token = jwt.sign(expectedClaims, privateKey);
        var options = {
            audience: 'yoursite.com',
            issuer: 'auth.yoursite.com'
        };

        var actualClaims = jwt.verify(token, privateKey, options);
        expectedClaims.iat = actualClaims.iat;

        expect(expectedClaims).to.deep.equal(actualClaims);
    });
});