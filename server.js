'use strict';

var fs = require('fs');
var koa = require('koa');
var jwt = require('jsonwebtoken');
var bodyParser = require('koa-bodyparser');
var Router = require('koa-router');
var userStore = require('./userStore');

var privateKey = fs.readFileSync('demo.rsa');

var app = koa();
app.use(bodyParser());

var issuer = 'auth.yoursite.com';
var audience = 'yoursite.com';

// unauthenticated
var authRouter = Router({ prefix: '/authenticate' });
authRouter.post('/', function *() {
    var params = this.request.body;
    var user = userStore.find(params.email);

    if(user === null) {
        this.status = 404;
        this.body = 'Account not found';
    } else if(!userStore.comparePassword(params.password, user.password)) {
        this.status = 409;
        this.body = 'Password incorrect';
    } else {
        var now = Math.floor(Date.now() / 1000);
        var oneDayExpiry = 60 * 60 * 24;
        var claims = {
            iss: issuer,
            aud: audience,
            email: params.email,
            exp: now + oneDayExpiry
        };

        var token = jwt.sign(claims, privateKey);

        this.status = 200;
        this.body = { token: token };
    }
});
authRouter.post('/register', function *() {
    var params = this.request.body;
    var user = userStore.find(params.email);

    if(user !== null) {
        this.status = 409;
        this.body = 'Email already registered';
    } else {
        userStore.insert(params.email, params.password);

        var now = Math.floor(Date.now() / 1000);
        var oneDayExpiry = 60 * 60 * 24;
        var claims = {
            iss: issuer,
            aud: audience,
            email: params.email,
            exp: now + oneDayExpiry
        };

        var token = jwt.sign(claims, privateKey);

        this.status = 200;
        this.body = { token: token };
    }
});
app.use(authRouter.routes());

// authenticated
var secureRouter = Router({ prefix: '/api' });
secureRouter.use(function*(next){
    try {
        var token = this.request.header.authorization;

        var options = {
            audience: audience,
            issuer: issuer
        };
        
        var claims = jwt.verify(token, privateKey, options);

        this.user = userStore.find(claims.email);

        yield next;

    } catch(ex) {
        this.status = 401;
        this.body = 'Unauthorized';
    }
});
secureRouter.post('/user', function *() {
    var params = this.request.body;
    var user = userStore.find(params.email);

    if(user !== null) {
        this.status = 409;
        this.body = 'User already exists';
        return;
    }

    userStore.insert(params.email, params.password);

    this.status = 201;
    this.body = 'User created';
});
secureRouter.get('/hello', function *() {
    this.status = 200;
    this.body = `hello ${ this.user.email }`;
});
app.use(secureRouter.routes());

app.listen(3333);